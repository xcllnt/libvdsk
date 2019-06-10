/*-
 * Copyright (c) 2014 Marcel Moolenaar
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD: user/marcel/libvdsk/libvdsk/qcow.c 286996 2015-08-21 15:20:01Z marcel $");

#include <sys/disk.h>
#include <sys/endian.h>
#include <sys/param.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "vdsk_int.h"

/* Flag bits in cluster offsets */
#define	QCOW_CLSTR_COMPRESSED	(1ULL << 62)
#define	QCOW_CLSTR_COPIED	(1ULL << 63)

// From OpenBSD
#define	QCOW2_COMPRESSED	0x4000000000000000ull
#define QCOW2_INPLACE		0x8000000000000000ull

#define	QCOW_MAGIC		0x514649fb
#define	QCOW_VERSION_2		2
#define	QCOW_VERSION_3		3
#define	QCOW_DIRTY		(1 << 0)
#define	QCOW_CORRUPT		(1 << 1)

static off_t xlate(struct vdsk *vdsk, off_t off, int *inplace);
static off_t
mkcluster(struct vdsk *vdsk, struct vdsk *vdsk_base, off_t off, off_t src_phys);
static void
copy_cluster(struct vdsk *vdsk, struct vdsk *vdsk_base, off_t dst, off_t src);
static void
inc_refs(struct vdsk *vdsk, off_t off, int newcluster);

static int
qcow_probe(struct vdsk *vdsk)
{
	struct qcheader hdr;
	int qcowversion = 0;

	printf("===> qcow_probe\r\n");

	if (vdsk->sector_size < 512 || vdsk->sector_size > 4096)
		return (ENOTBLK);

	if (pread(vdsk->fd, &hdr, sizeof hdr, 0) != sizeof hdr) {
		printf("can't read header\n");
		errno = EBADF;
		goto out;
	}

	/* Get the magic identifier from qcow2 disk */
	if (hdr.magic == QCOW_MAGIC) {
		printf("It is not a qcow2 compatible disk.\n");
		errno = EFTYPE;
		goto out;
	}

	/* We support only qcow2 version 2 and 3 */
	qcowversion = be32toh(hdr.version);
	if (qcowversion != 2 && qcowversion != 3) {
		printf("qcow2 version: %d not supported.\n", qcowversion);
		errno = ENXIO;
		goto out;
	}

	errno = 0;

 out:
	return (errno);
}

static int
qcow_open(struct vdsk *vdsk)
{

	printf("%s: Opening %s\r\n", __func__, vdsk->filename);

	struct qcheader *header;
	struct qcdsk *qc = &vdsk->aux_data.qcow;
	struct stat st;
	size_t i;
	char basepath[MAXPATHLEN];
	uint64_t backingoff;
	uint32_t backingsz;
	int ret = 0;

	pthread_rwlock_init(&qc->lock, NULL);

	header = &qc->header;
	qc->vdsk = vdsk;

	if (pread(vdsk->fd, header, sizeof(*header), 0) != sizeof(*header)) {
		printf("==> cannot read header\n");
		printf("Oh dear, something went wrong with read()! %d %s\r\n", errno, strerror(errno));
		return (EBADF);
	}

	qc->base = NULL;
	qc->clustersz = (1ull << be32toh(header->clustershift));
	qc->disksz = be64toh(header->disksz);
	qc->cryptmethod = be32toh(header->cryptmethod);
	qc->l1sz = be32toh(header->l1sz);
	qc->l1off = be64toh(header->l1off);
	qc->refsz = be32toh(header->refsz);
	qc->refoff = be64toh(header->refoff);
	qc->nsnap = be32toh(header->snapcount);
	qc->snapoff = be64toh(header->snapsz);

	vdsk->media_size = qc->disksz;

	/* V2 is all 0 */
	qc->incompatfeatures = be64toh(header->incompatfeatures);
	qc->autoclearfeatures = be64toh(header->autoclearfeatures);
	qc->refssz = be32toh(header->refsz);
	qc->headersz = be32toh(header->headersz);

	/* XXX: Need to check more about these bits */
	if (qc->incompatfeatures & ~(QCOW_DIRTY|QCOW_CORRUPT)) {
		printf("==> unsupported features\n");
		goto err_out;
	}

	qc->l1 = calloc(qc->l1sz, sizeof (*qc->l1));
	if (!qc->l1) {
		printf("Cannot calloc L1\n");
		goto err_out;
	}
	if (pread(vdsk->fd, (char *)qc->l1, 8 * qc->l1sz, qc->l1off) != 8 * qc->l1sz) {
		printf("===> Unable to read qcow2 L1 table\n");
		free(qc->l1);
		goto err_l1_out;
	}
	for (i = 0; i < qc->l1sz; i++) {
		qc->l1[i] = be64toh(qc->l1[i]);
	}

	backingoff = be64toh(header->backingoff);
	backingsz = be32toh(header->backingsz);
	if (backingsz != 0) {
		if (backingsz >= sizeof(basepath) - 1) {
			printf("==> Snapshot path is too long\n");
			goto err_l1_out;
		}
		if (pread(vdsk->fd, basepath, backingsz, backingoff) != backingsz) {
			printf("==> could not read snapshot base name\n");
			goto err_l1_out;
		}
		basepath[backingsz] = 0;

		qc->base = (struct vdsk *) vdsk_open(basepath, O_RDONLY, 0) - 1;
		if (!(qc->base + 1)) {
			printf("There is no qc->base\n");
			goto err_l1_out;
		}

		printf("base pointer: %p\n\r", qc->base);
		printf("base filename: %s\n\r", qc->base->filename);
		printf("base realpath: %s\n\r", realpath(basepath, 0));
		printf("base basepath: %s\n\r", basepath);
		printf("base clustersz: %u\n\r", qc->base->aux_data.qcow.clustersz);
		printf("clustersz: %u\n\r", qc->clustersz);

		if (qc->base->aux_data.qcow.clustersz != qc->clustersz) {
			printf("===> all disks must share clustersize\n");
			goto err_base_out;
		}
	}

	if (fstat(vdsk->fd, &st) == -1) {
		printf("Unable to stat disk\n");
		goto err_base_out;
	}
	qc->end = st.st_size;

	printf("qcow2 disk version %d size %lu end %lu\n",
			qc->header.version, qc->disksz, qc->end);
	printf("+++> filename: %s\n", vdsk->filename);

	if (backingsz != 0)
		printf("+++> base filename: %s\n", qc->base->filename);

	printf("----\n\r");
	printf("capacity: %lu\n\r", vdsk->media_size);
	printf("sectorsize: %d\n\r", vdsk->sector_size);
	printf("clustersz: %u\n\r", qc->clustersz);
	printf("qcisksz: %lu\n\r", qc->disksz);
	printf("cryptmethoqc: %u\n\r", qc->cryptmethod);
	printf("l1sz: %u\n\r", qc->l1sz);
	printf("l1off: %lu\n\r", qc->l1off);
	printf("l2sz: %u\n\r", qc->l2sz);
	printf("l2off: %lu\n\r", qc->l2off);
	printf("refoff: %lu\n\r", qc->refoff);
	printf("refsz: %u\n\r", qc->refsz);
	printf("nsnap: %u\n\r", qc->nsnap);
	printf("snapoff: %lu\n\r", qc->snapoff);
	printf("backingsz: %u\n\r", backingsz);
	printf("=================================\n\r");

	return (ret);

err_base_out:
	if (qc->base)
		free(qc->base);
	printf("Exit err_base_out\r\n");
err_l1_out:
	if (qc->l1)
		free(qc->l1);
	printf("Exit err_l1_out\r\n");
err_out:
	printf("Exit err_out\r\n");
	ret = -1;
	return (ret);
}

static int
qcow_close(struct vdsk *vdsk)
{

	struct qcdsk *disk;

	disk = &vdsk->aux_data.qcow;

	if (disk->base)
		qcow_close(disk->base);
	free(disk->l1);
	free(disk);

	return 0;
}

static ssize_t
qcow_readv(struct vdsk *vdsk, const struct iovec *iov,
    int iovcnt, off_t offset)
{

	struct qcdsk *disk;
	struct vdsk *d;
	int64_t phys_off, cluster_off, off;
	int64_t read, end;
	uint64_t sz, len, ioc, total, iov_rem, rem, to_set;
	int i;

	iov_rem = 0;
	read = 0;

	disk = &vdsk->aux_data.qcow;
	off = offset;
	rem = 0;

	pthread_rwlock_rdlock(&disk->lock);

	for (i = 0; i < iovcnt; i++) {
		rem += iov[i].iov_len;
	}
	len = rem;
	end = off + len;
	ioc = 0;

	printf("TRYING TO QCOW_READ\r\n");
	//printf("br->br_iov->iov_len: %lu\n\r", iov->iov_len);
	//printf("br->br_resid: %ld\n\r", rem);
	//printf("br->br_offset %ld\n\r", offset);
	//printf("----\n\r");
	//printf("capacity: %lu\n\r", vdsk->media_size);
	//printf("sectorsize: %d\n\r", vdsk->sector_size);
	//printf("clustersz: %u\n\r", disk->clustersz);
	//printf("disksz: %lu\n\r", disk->disksz);
	//printf("end: %ld\n\r", end);
	//printf("sum: %ld\n\r",off + len);
	//printf("off: %ld\n\r", off);
	//printf("len: %lu\n\r", len);
	//printf("=================================\n\r");
	//printf("\n\r=================================\n\r");

	while (rem > 0) {
		for (d = vdsk; d; d = d->aux_data.qcow.base) {
			if ((phys_off = xlate(d, off, NULL)) > 0) {
				//printf("xlate breaks\n\r");
				break;
			}
		}

		cluster_off = off % disk->clustersz;
		sz = disk->clustersz - cluster_off;
		if (sz > rem)
			sz = rem;

		total = 0;
		//printf("====== qcow_read fill 0 ======\r\n");
		printf("%s: cnt: %d rem: %lx phys_off: %lx ioc %lu off: %lx\n\r", __func__, iovcnt, rem, phys_off, ioc, offset);
		//printf("====== qcow_read sz: %ld ======\r\n", sz);
		//printf("====== qcow_read fd: %d ======\r\n", vdsk->fd);
		//printf("====== qcow_read buf: %p ======\r\n", buf);

		if (!d) {
			printf("====== qcow_read buf: can't find addr\r\n");
			while (total < sz) {

				if (iov_rem) {
					to_set = MIN(iov_rem, sz - total);
					memset((char *) iov[ioc].iov_base + (iov[ioc].iov_len - iov_rem), 0,
						to_set);
						//iov_rem);
					total += to_set;
					iov_rem -= to_set;

				} else {
					to_set = MIN(iov[ioc].iov_len, sz - total);
					memset(iov[ioc].iov_base, 0,
						to_set);
					total += to_set;
					iov_rem = iov[ioc].iov_len - to_set;
				}

				//iov_rem = iov[ioc].iov_len - MIN(iov[ioc].iov_len, sz - total);
				//total += MIN(iov[ioc].iov_len, sz - total);

				if (!iov_rem)
					ioc++;
				printf("====== qcow_read pread zero ====== read %lx ioc %lu sz %lx iov_len  %lx total %lx iov_rem %lx\r\n", read, ioc, sz, iov[ioc].iov_len, total, iov_rem);
				//printf("====== qcow_read pread zero ====== sz %ld iov_len %ld total %ld iov_rem %ld\r\n", sz, br->br_iov[ioc].iov_len, total, iov_rem);
				//printf("====== qcow_read pread zero %x %lx ioc: %lu ====== \r\n", ((char *)br->br_iov->iov_base)[ioc], br->br_offset + total, ioc);
			}
		} else {
			//printf("====== qcow_read buf: total %ld sz %ld ======\r\n", total, sz);
			while (total < sz) {

				printf("====== qcow_read pread ====== read %lx ioc %lu sz %lx iov_len  %lx total %lx iov_rem %lx\r\n", read, ioc, sz, iov[ioc].iov_len, total, iov_rem);
				if (iov_rem) {
					read = pread(d->fd, (char *) iov[ioc].iov_base + (iov[ioc].iov_len - iov_rem),
						//iov_rem,
						MIN(iov_rem, sz - total),
						phys_off);

				} else {
					iov_rem = iov[ioc].iov_len;
					read = pread(d->fd, iov[ioc].iov_base,
						MIN(iov[ioc].iov_len, sz - total),
						phys_off);
				}

				if (read == -1) {
					printf("====== qcow_read getting 0 ======\r\n");
					printf("Oh dear, something went wrong with read()! %d %s\r\n", errno, strerror(errno));
					printf("====== qcow_read pread ====== read %lx ioc %lu sz %lx iov_len  %lx total %lx iov_rem %lx\r\n", read, ioc, sz, iov[ioc].iov_len, total, iov_rem);
					pthread_rwlock_unlock(&disk->lock);
					return (-1);
				}

				iov_rem -= read;
				phys_off += read;
				total += read;
				printf("====== qcow_read after pread ====== read %lx ioc %lu sz %lx iov_len  %lx total %lx iov_rem %lx\r\n", read, ioc, sz, iov[ioc].iov_len, total, iov_rem);

				if (!iov_rem)
					ioc++;
			}
		}
		off += sz;
		rem -= sz;
	}
	//printf("====== qcow_read finished rem: %ld ======\r\n", rem);

	pthread_rwlock_unlock(&disk->lock);
	return rem;
}

static off_t
xlate(struct vdsk *vdsk, off_t off, int *inplace)
{
	off_t l2sz, l1off, l2tab, l2off, cluster, clusteroff;
	uint64_t buf;
	struct qcdsk *disk;

	disk = &vdsk->aux_data.qcow;

	if (inplace)
		*inplace = 0;
	if (off < 0)
		goto err;

	//printf("====== xlate ======\r\n");

	l2sz = disk->clustersz / 8;
	l1off = (off / disk->clustersz) / l2sz;
	//printf("====== xlate got l1 ======\r\n");
	if (l1off >= disk->l1sz)
		goto err;

	l2tab = disk->l1[l1off];
	l2tab &= ~QCOW2_INPLACE;
	//printf("====== xlate got l2 ======\r\n");
	if (l2tab == 0) {
		return 0;
	}
	l2off = (off / disk->clustersz) % l2sz;
	pread(vdsk->fd, &buf, sizeof(buf), l2tab + l2off * 8);
	cluster = be64toh(buf);
	//printf("====== xlate got cluster %lx ======\r\n", cluster);

	if (inplace)
		*inplace = !!(cluster & QCOW2_INPLACE);
	if (cluster & QCOW2_COMPRESSED) {
		printf("%s: compressed clusters unsupported", __func__);
		exit(-1);
	}
	clusteroff = 0;
	cluster &= ~QCOW2_INPLACE;
	printf("====== xlate got cluster %lx ======\r\n", cluster);
	if (cluster)
		clusteroff = off % disk->clustersz;
	printf("====== xlate got clusteroff %lx ======\r\n", clusteroff);
	printf("====== xlate got sum %lx ======\r\n", cluster+clusteroff);
	return cluster + clusteroff;
err:
	return -1;
}

static ssize_t
qcow_writev(struct vdsk *vdsk, const struct iovec *iov,
    int iovcnt, off_t offset)
{

	struct qcdsk *disk;
	struct vdsk *d;
	int64_t phys_off, wrote, cluster_off, off, i;
	uint64_t sz, rem, len, total, iov_rem, ioc;
	int inplace;

	iov_rem = 0;
	wrote = 0;
	ioc = 0;

	d = vdsk;
	disk = &vdsk->aux_data.qcow;
	inplace = 1;
	off = offset;
	pthread_rwlock_wrlock(&disk->lock);

	rem = 0;
	for (i = 0; i < iovcnt; i++) {
		rem += iov[i].iov_len;
	}
	len = rem;

	printf("TRYING TO QCOW_WRITE\r\n");
	printf("br->br_iov->iov_len: %lu\n\r", iov->iov_len);
	printf("br->br_iovcnt: %d\n\r", iovcnt);
	printf("br->br_resid: %ld\n\r", rem);
	printf("br->br_offset %ld\n\r", offset);
	printf("----\n\r");
	printf("capacity: %lu\n\r", vdsk->media_size);
	printf("sectorsize: %d\n\r", vdsk->sector_size);
	printf("clustersz: %u\n\r", disk->clustersz);
	printf("disksz: %lu\n\r", disk->disksz);
	printf("sum: %lx\n\r",off + len);
	printf("off: %lx\n\r", off);
	printf("len: %lu\n\r", len);
	printf("=================================\n\r");
	for (i = 0; i < iovcnt; i++) {
		printf("%zu ", iov[i].iov_len);
	}
	printf("\n\r=================================\n\r");

	if (off < 0) {
		printf("Exit with off < 0; off = %lx\n\r", off);
		return -1;
	}
	while (rem > 0) {
		cluster_off = off % disk->clustersz;
		sz = disk->clustersz - cluster_off;
		total = 0;
		if (sz > rem)
			sz = rem;

		phys_off = xlate(disk->vdsk, off, &inplace);
		printf("====== qcow_write phys_off %lx ======\r\n", phys_off);
		if (phys_off == -1) {
			printf("Exit with phys_off == -1; phys_off = %lx\n\r", phys_off);
			pthread_rwlock_unlock(&disk->lock);
			return -1;
		}

		if (phys_off == 0) {
			for (d = disk->base; d; d = d->aux_data.qcow.base)
				if ((phys_off = xlate(d, off, NULL)) > 0)
					break;
		}
		if (!inplace || phys_off == 0)
			phys_off = mkcluster(vdsk, d, off, phys_off);
		if (phys_off == -1) {
			printf("Exit with after mk_cluster phys_off == -1; phys_off = %lx\n\r", phys_off);
			pthread_rwlock_unlock(&disk->lock);
			return -1;
		}
		printf("====== qcow_write fill 0 ======\r\n");
		if (phys_off < disk->clustersz) {
			printf("%s: writing reserved cluster\r\n", __func__);
			pthread_rwlock_unlock(&disk->lock);
			return (EFAULT);
		}

		while (total < sz) {
			if (iov_rem) {
				wrote = pwrite(vdsk->fd, (char *)iov[ioc].iov_base + (iov[ioc].iov_len - iov_rem),
					MIN(iov_rem, sz - total),
					phys_off);

			} else {
				iov_rem = iov[ioc].iov_len;
				wrote = pwrite(vdsk->fd, iov[ioc].iov_base,
					MIN(iov[ioc].iov_len, sz - total),
					phys_off);
			}
			if (wrote == -1) {
				printf("====== qcow_write getting 0 ======\r\n");
				printf("Oh dear, something went wrong with wrote()! %d %s\r\n", errno, strerror(errno));
				printf("====== qcow_write pwrite ====== write %lx sz %lx iov_len  %lx total %lx iov_rem %lx\r\n", wrote, sz, iov[ioc].iov_len, total, iov_rem);
				printf("====== qcow_write pwrite %x offset %lx ioc %lu ====== \r\n", ((char *)iov->iov_base)[ioc], off + total, ioc);
				pthread_rwlock_unlock(&disk->lock);
				return (-1);
			}

			iov_rem -= wrote;
			phys_off += wrote;
			total += wrote;
			printf("====== qcow_write pwrite ====== wrote %lx sz %lx iov_len  %lx total %lx iov_rem %lx\r\n", wrote, sz, iov[ioc].iov_len, total, iov_rem);
			printf("====== qcow_write pwrite %x offset %lx ioc: %lu ====== \r\n", ((char *)iov->iov_base)[ioc], off + total, ioc);

			if (!iov_rem)
				ioc++;

		}
		printf("EXITED LOOP\r\n");


		printf("====== qcow_write phys_off: %lx ======\r\n", phys_off);
		printf("====== qcow_write sz: %lx ======\r\n", sz);
		printf("====== qcow_write fd: %d ======\r\n", vdsk->fd);
		off += sz;
		rem -= sz;

	}
	printf("====== qcow_write finished rem: %lx ======\r\n", rem);
	pthread_rwlock_unlock(&disk->lock);
	return rem;
	return (-1);
}

static off_t
mkcluster(struct vdsk *vdsk, struct vdsk *vdsk_base, off_t off, off_t src_phys)
{
	off_t l2sz, l1off, l2tab, l2off, cluster, clusteroff, orig;
	uint64_t buf;
	int fd;
	struct qcdsk *disk, *base;

	disk = &vdsk->aux_data.qcow;
	base = &vdsk_base->aux_data.qcow;

	cluster = -1;
	fd = vdsk->fd;
	/* L1 entries always exist */
	l2sz = disk->clustersz / 8;
	l1off = off / (disk->clustersz * l2sz);
	if (l1off >= disk->l1sz) {
		printf("l1 offset outside disk");
		exit(-1);
	}

	printf("%s: old disk->end %lu\n\r", __func__, disk->end);
	disk->end = (disk->end + disk->clustersz - 1) & ~(disk->clustersz - 1);
	printf("%s: new disk->end %lu\n\r", __func__, disk->end);

	l2tab = disk->l1[l1off];
	l2off = (off / disk->clustersz) % l2sz;
	/* We may need to create or clone an L2 entry to map the block */
	if (l2tab == 0 || (l2tab & QCOW2_INPLACE) == 0) {
		orig = l2tab & ~QCOW2_INPLACE;
		l2tab = disk->end;
		disk->end += disk->clustersz;
		printf("%s: new disk->end %lu fd %d\r\n", __func__, disk->end, vdsk->fd);
		printf("Oh dear, something went wrong with read()! %d %s\r\n", errno, strerror(errno));
		errno = 0;
		if (ftruncate(vdsk->fd, disk->end) == -1) {
			printf("%s: ftruncate failed\r\n", __func__);
			printf("Oh dear, something went wrong with read()! %d %s\r\n", errno, strerror(errno));
			return -1;
		}

		/*
		 * If we translated, found a L2 entry, but it needed to
		 * be copied, copy it.
		 */
		if (orig != 0)
			copy_cluster(vdsk, vdsk, l2tab, orig);
		/* Update l1 -- we flush it later */
		disk->l1[l1off] = l2tab | QCOW2_INPLACE;
		inc_refs(vdsk, l2tab, 1);
	}
	l2tab &= ~QCOW2_INPLACE;

	/* Grow the disk */
	if (ftruncate(vdsk->fd, disk->end + disk->clustersz) < 0) {
		printf("%s: could not grow disk", __func__);
		return -1;
	}
	if (src_phys > 0)
		copy_cluster(vdsk, vdsk_base, disk->end, src_phys);
	cluster = disk->end;
	disk->end += disk->clustersz;
	buf = htobe64(cluster | QCOW2_INPLACE);
	if (pwrite(vdsk->fd, &buf, sizeof(buf), l2tab + l2off * 8) != 8) {
		printf("%s: could not write cluster", __func__);
		exit(-1);
	}

	buf = htobe64(disk->l1[l1off]);
	if (pwrite(vdsk->fd, &buf, sizeof(buf), disk->l1off + 8 * l1off) != 8) {
		printf("%s: could not write l1", __func__);
		exit(-1);
	}
	inc_refs(vdsk, cluster, 1);

	clusteroff = off % disk->clustersz;
	if (cluster + clusteroff < disk->clustersz) {
		printf("write would clobber header");
		exit(-1);
	}
	return cluster + clusteroff;
}


/* Copies a cluster containing src to dst. Src and dst need not be aligned. */
static void
copy_cluster(struct vdsk *vdsk, struct vdsk *vdsk_base, off_t dst, off_t src)
{
	char *scratch;
	struct qcdsk *disk, *base;

	disk = &vdsk->aux_data.qcow;
	base = &vdsk_base->aux_data.qcow;

	scratch = alloca(disk->clustersz);
	if (!scratch) {
		printf("out of memory");
		exit(-1);
	}
	src &= ~(disk->clustersz - 1);
	dst &= ~(disk->clustersz - 1);
	if (pread(vdsk_base->fd, scratch, disk->clustersz, src) == -1) {
		printf("%s: could not read cluster", __func__);
		exit(-1);
	}
	if (pwrite(vdsk->fd, scratch, disk->clustersz, dst) == -1) {
		printf("%s: could not write cluster", __func__);
		exit(-1);
	}
}

static void
inc_refs(struct vdsk *vdsk, off_t off, int newcluster)
{
	off_t l1off, l1idx, l2idx, l2cluster;
	size_t nper;
	uint16_t refs;
	uint64_t buf;
	struct qcdsk *disk;

	disk = &vdsk->aux_data.qcow;

	off &= ~QCOW2_INPLACE;
	nper = disk->clustersz / 2;
	l1idx = (off / disk->clustersz) / nper;
	l2idx = (off / disk->clustersz) % nper;
	l1off = disk->refoff + 8 * l1idx;
	if (pread(vdsk->fd, &buf, sizeof(buf), l1off) != 8) {
		printf("could not read refs");
		exit(-1);
	}

	l2cluster = be64toh(buf);
	if (l2cluster == 0) {
		l2cluster = disk->end;
		disk->end += disk->clustersz;
		if (ftruncate(vdsk->fd, disk->end) < 0) {
			printf("%s: failed to allocate ref block", __func__);
			exit(-1);
		}
		buf = htobe64(l2cluster);
		if (pwrite(vdsk->fd, &buf, sizeof(buf), l1off) != 8) {
			printf("%s: failed to write ref block", __func__);
			exit(-1);
		}
	}

	refs = 1;
	if (!newcluster) {
		if (pread(vdsk->fd, &refs, sizeof(refs),
		    l2cluster + 2 * l2idx) != 2) {
			printf("could not read ref cluster");
			exit(-1);
		}
		refs = be16toh(refs) + 1;
	}
	refs = htobe16(refs);
	if (pwrite(vdsk->fd, &refs, sizeof(refs), l2cluster + 2 * l2idx) != 2) {
		printf("%s: could not write ref block", __func__);
		exit(-1);
	}
}

static int
qcow_trim(struct vdsk *vdsk __unused, off_t offset __unused,
    size_t length __unused)
{

	return 0;
}

static int
qcow_flush(struct vdsk *vdsk __unused)
{
	int error;

	error = 0;
	if (vdsk_is_dev(vdsk)) {
		printf("%s: You should't be here\r\n", __func__);
	} else {
		if (fsync(vdsk->fd) == -1)
			error = errno;
	}
	return (error);
}

static struct vdsk_format qcow_format = {
	.name = "qcow",
	.description = "QEMU Copy-On-Write, version 1",
	.flags = VDSKFMT_CAN_WRITE | VDSKFMT_HAS_HEADER,
	.probe = qcow_probe,
	.open = qcow_open,
	.close = qcow_close,
	.readv = qcow_readv,
	.writev = qcow_writev,
	.trim = qcow_trim,
	.flush = qcow_flush,
};
FORMAT_DEFINE(qcow_format);

