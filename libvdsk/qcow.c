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
#include "qcow.h"

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

static struct qcdsk*
qcow_deref(struct vdsk *vdsk)
{
	return (struct qcdsk*) vdsk - 1;
}

static int
qcow_probe(struct vdsk *vdsk)
{
	struct qcheader hdr;
	int qcowversion = 0;

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

	struct qcheader *header;
	struct qcdsk *qc = qcow_deref(vdsk);
	struct stat st;
	size_t i;
	char basepath[MAXPATHLEN];
	uint64_t backingoff;
	uint32_t backingsz;
	int ret = 0;

#ifdef SMP
	pthread_rwlock_init(&qc->lock, NULL);
#endif

	header = &qc->header;
	qc->vdsk = vdsk;

	if (pread(vdsk->fd, header, sizeof(*header), 0) != sizeof(*header)) {
		printf("cannot read header\n");
		printf("%s: (%d) %s\r\n", __func__, errno, strerror(errno));
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

	if (qc->incompatfeatures & ~(QCOW_DIRTY|QCOW_CORRUPT)) {
		printf("unsupported features\n");
		goto err_out;
	}

	qc->l1 = calloc(qc->l1sz, sizeof (*qc->l1));
	if (!qc->l1) {
		printf("Cannot calloc L1\n");
		goto err_out;
	}
	if (pread(vdsk->fd, (char *)qc->l1, 8 * qc->l1sz, qc->l1off) != 8 * qc->l1sz) {
		printf("Unable to read qcow2 L1 table\n");
		printf("%s: (%d) %s\r\n", __func__, errno, strerror(errno));
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
			printf("Snapshot path is too long\n");
			goto err_l1_out;
		}
		if (pread(vdsk->fd, basepath, backingsz, backingoff) != backingsz) {
			printf("could not read snapshot base name\n");
			printf("%s: (%d) %s\r\n", __func__, errno, strerror(errno));
			goto err_l1_out;
		}
		basepath[backingsz] = 0;

		qc->base = (struct vdsk *) vdsk_open(basepath, O_RDONLY, 0) - 1;
		if (!(qc->base + 1)) {
			printf("There is no qc->base\n");
			goto err_l1_out;
		}

		if (qcow_deref(qc->base)->clustersz != qc->clustersz) {
			printf("all disks must share clustersize\n");
			goto err_base_out;
		}
	}

	if (fstat(vdsk->fd, &st) == -1) {
		printf("Unable to stat disk\n");
		printf("%s: (%d) %s\r\n", __func__, errno, strerror(errno));
		goto err_base_out;
	}
	qc->end = st.st_size;

	DPRINTF("----\n\r");
	DPRINTF("qcow2 disk version %d size %lu end %lu\n",
		qc->header.version, qc->disksz, qc->end);
	DPRINTF("+++> filename: %s\n", vdsk->filename);
	DPRINTF("capacity: %lu\n\r", vdsk->media_size);
	DPRINTF("sectorsize: %d\n\r", vdsk->sector_size);
	DPRINTF("clustersz: %ld\n\r", qc->clustersz);
	DPRINTF("qcisksz: %lu\n\r", qc->disksz);
	DPRINTF("cryptmethoqc: %u\n\r", qc->cryptmethod);
	DPRINTF("l1sz: %u\n\r", qc->l1sz);
	DPRINTF("l1off: %lu\n\r", qc->l1off);
	DPRINTF("l2sz: %u\n\r", qc->l2sz);
	DPRINTF("l2off: %lu\n\r", qc->l2off);
	DPRINTF("refoff: %lu\n\r", qc->refoff);
	DPRINTF("refsz: %ld\n\r", qc->refsz);
	DPRINTF("nsnap: %u\n\r", qc->nsnap);
	DPRINTF("snapoff: %lu\n\r", qc->snapoff);
	DPRINTF("backingsz: %u\n\r", backingsz);
	DPRINTF("=================================\n\r");

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

	disk = qcow_deref(vdsk);

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
	off_t phys_off, read, cluster_off;
	ssize_t sz, rem, iov_rem, total;
	uint64_t ioc, to_set;
	int i;

	iov_rem = 0;
	read = 0;
	ioc = 0;
	disk = qcow_deref(vdsk);
	rem = 0;

#ifdef SMP
	pthread_rwlock_rdlock(&disk->lock);
#endif

	DPRINTF("TRYING TO %s\r\n", __func__);
	DPRINTF("iov->iov_len: %lu\n\r", iov->iov_len);
	DPRINTF("rem: %ld\n\r", rem);
	DPRINTF("offset %ld\n\r", offset);
	DPRINTF("----\n\r");
	DPRINTF("capacity: %lu\n\r", vdsk->media_size);
	DPRINTF("sectorsize: %d\n\r", vdsk->sector_size);
	DPRINTF("clustersz: %ld\n\r", disk->clustersz);
	DPRINTF("disksz: %lu\n\r", disk->disksz);
	DPRINTF("=================================\n\r");
	for (i = 0; i < iovcnt; i++) {
		rem += iov[i].iov_len;
		DPRINTF("%zu ", iov[i].iov_len);
	}
	DPRINTF("sum: %ld\n\r", offset + rem);
	DPRINTF("\n\r=================================\n\r");

	if (offset < 0) {
		printf("Exit with off < 0; off = %ld\n\r", offset);

#ifdef SMP
		pthread_rwlock_unlock(&disk->lock);
#endif

		return -1;
	}
	while (rem > 0) {
		for (d = vdsk; d; d = qcow_deref(d)->base) {
			if ((phys_off = xlate(d, offset, NULL)) > 0) {
				break;
			}
		}

		cluster_off = offset % disk->clustersz;
		sz = disk->clustersz - cluster_off;
		if (sz > rem)
			sz = rem;

		total = 0;
		DPRINTF("%s: cnt: %d rem: %lx phys_off: %lx ioc %lu off: %lx\n\r",
			__func__, iovcnt, rem, phys_off, ioc, offset);

		if (!d) {
			while (total < sz) {

				if (iov_rem) {
					to_set = MIN(iov_rem, sz - total);
					memset((char *) iov[ioc].iov_base +
						(iov[ioc].iov_len - iov_rem), 0,
						to_set);
					total += to_set;
					iov_rem -= to_set;
				} else {
					to_set = MIN((ssize_t) iov[ioc].iov_len,
							sz - total);
					memset(iov[ioc].iov_base, 0,
						to_set);
					total += to_set;
					iov_rem = iov[ioc].iov_len - to_set;
				}

				if (!iov_rem)
					ioc++;

			}
		} else {
			while (total < sz) {
				if (iov_rem) {
					read = pread(d->fd, (char *) iov[ioc].iov_base +
						(iov[ioc].iov_len - iov_rem),
						MIN(iov_rem, sz - total),
						phys_off);

				} else {
					iov_rem = iov[ioc].iov_len;
					read = pread(d->fd, iov[ioc].iov_base,
						MIN(iov[ioc].iov_len, (size_t) sz - total),
						phys_off);
				}
				DPRINTF("%s: read %lx ioc %lu sz %lx iov_len %lx "
					"total %lx iov_rem %lx\r\n", __func__,
					read, ioc, sz, iov[ioc].iov_len, total,
					iov_rem);

				if (read == -1) {
					printf("%s: (%d) %s\r\n", __func__,
						errno, strerror(errno));

#ifdef SMP
					pthread_rwlock_unlock(&disk->lock);
#endif

					return (-1);
				}

				iov_rem -= read;
				phys_off += read;
				total += read;

				if (!iov_rem)
					ioc++;
			}
		}

		offset += sz;
		rem -= sz;
	}
	DPRINTF("%s: finished rem: %lx\r\n", __func__, rem);

#ifdef SMP
	pthread_rwlock_unlock(&disk->lock);
#endif

	return rem;
}

static off_t
xlate(struct vdsk *vdsk, off_t off, int *inplace)
{
	off_t l2sz, l1off, l2tab, l2off, cluster, clusteroff;
	uint64_t buf;
	struct qcdsk *disk;
	int read;

	disk = qcow_deref(vdsk);

	if (inplace)
		*inplace = 0;
	if (off < 0)
		goto err;

	l2sz = disk->clustersz / 8;
	l1off = (off / disk->clustersz) / l2sz;
	if (l1off >= disk->l1sz) {
		DPRINTF("%s: wrong l1\n\r", __func__);
		goto err;
	}

	l2tab = disk->l1[l1off];
	l2tab &= ~QCOW2_INPLACE;
	if (l2tab == 0) {
		DPRINTF("%s: no l2 table found\n\r", __func__);
		return 0;
	}

	l2off = (off / disk->clustersz) % l2sz;
	read = pread(vdsk->fd, &buf, sizeof(buf), l2tab + l2off * 8);
	if (read != sizeof(uint64_t)) {
		printf("%s: Could not read l2 cluster %d %lu\n\r", __func__,
			read, sizeof(uint64_t));
		printf("%s: (%d) %s\r\n", __func__, errno, strerror(errno));
		goto err;
	}

	cluster = be64toh(buf);
	if (inplace)
		*inplace = !!(cluster & QCOW2_INPLACE);
	if (cluster & QCOW2_COMPRESSED) {
		printf("%s: compressed clusters unsupported", __func__);
		goto err;
	}
	clusteroff = 0;
	cluster &= ~QCOW2_INPLACE;
	if (cluster)
		clusteroff = off % disk->clustersz;
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
	off_t phys_off, wrote, cluster_off;
	ssize_t sz, rem, iov_rem, total;
	uint64_t ioc;
	int inplace, i;

	iov_rem = 0;
	wrote = 0;
	ioc = 0;
	disk = qcow_deref(vdsk);
	rem = 0;
	inplace = 1;

#ifdef SMP
	pthread_rwlock_wrlock(&disk->lock);
#endif

	DPRINTF("TRYING TO %s\r\n", __func__);
	DPRINTF("iov->iov_len: %lu\n\r", iov->iov_len);
	DPRINTF("rem: %ld\n\r", rem);
	DPRINTF("offset %ld\n\r", offset);
	DPRINTF("----\n\r");
	DPRINTF("capacity: %lu\n\r", vdsk->media_size);
	DPRINTF("sectorsize: %d\n\r", vdsk->sector_size);
	DPRINTF("clustersz: %ld\n\r", disk->clustersz);
	DPRINTF("disksz: %lu\n\r", disk->disksz);
	DPRINTF("=================================\n\r");
	for (i = 0; i < iovcnt; i++) {
		rem += iov[i].iov_len;
		DPRINTF("%zu ", iov[i].iov_len);
	}
	DPRINTF("sum: %ld\n\r", offset + rem);
	DPRINTF("\n\r=================================\n\r");

	if (offset < 0) {
		printf("Exit with off < 0; off = %lx\n\r", offset);

#ifdef SMP
		pthread_rwlock_unlock(&disk->lock);
#endif

		return -1;
	}
	while (rem > 0) {
		cluster_off = offset % disk->clustersz;
		sz = disk->clustersz - cluster_off;
		total = 0;
		if (sz > rem)
			sz = rem;

		phys_off = xlate(vdsk, offset, &inplace);
		DPRINTF("%s: phys_off %lx\r\n",__func__, phys_off);
		if (phys_off == -1) {
			printf("Exit with phys_off == -1\n\r");

#ifdef SMP
			pthread_rwlock_unlock(&disk->lock);
#endif

			return -1;
		}

		if (phys_off == 0) {
			for (d = disk->base; d; d = qcow_deref(d)->base)
				if ((phys_off = xlate(d, offset, NULL)) > 0)
					break;
		}
		if (!inplace || phys_off == 0)
			phys_off = mkcluster(vdsk, d, offset, phys_off);
		if (phys_off == -1) {
			printf("Exit after mk_cluster phys_off == -1\n\r");

#ifdef SMP
			pthread_rwlock_unlock(&disk->lock);
#endif

			return -1;
		}
		if (phys_off < disk->clustersz) {
			printf("%s: writing reserved cluster\r\n", __func__);

#ifdef SMP
			pthread_rwlock_unlock(&disk->lock);
#endif

			return (EFAULT);
		}

		while (total < sz) {
			if (iov_rem) {
				wrote = pwrite(vdsk->fd, (char *)iov[ioc].iov_base +
					(iov[ioc].iov_len - iov_rem),
					MIN(iov_rem, sz - total),
					phys_off);

			} else {
				iov_rem = iov[ioc].iov_len;
				wrote = pwrite(vdsk->fd, iov[ioc].iov_base,
					MIN(iov[ioc].iov_len, (size_t) sz - total),
					phys_off);
			}

			DPRINTF("%s: wrote %lx ioc %lu sz %lx iov_len %lx "
				"total %lx iov_rem %lx\r\n", __func__,
				wrote, ioc, sz, iov[ioc].iov_len, total,
				iov_rem);

			if (wrote == -1) {

#ifdef SMP
				pthread_rwlock_unlock(&disk->lock);
#endif

				return (-1);
			}

			iov_rem -= wrote;
			phys_off += wrote;
			total += wrote;

			if (!iov_rem)
				ioc++;
		}

		offset += sz;
		rem -= sz;
	}
	DPRINTF("%s: finished rem: %lx\r\n", __func__, rem);

#ifdef SMP
	pthread_rwlock_unlock(&disk->lock);
#endif

	return rem;
}

static off_t
mkcluster(struct vdsk *vdsk, struct vdsk *vdsk_base, off_t off, off_t src_phys)
{
	off_t l2sz, l1off, l2tab, l2off, cluster, clusteroff, orig;
	uint64_t buf;
	int fd;
	struct qcdsk *disk, *base;

	disk = qcow_deref(vdsk);
	base = qcow_deref(vdsk_base);

	cluster = -1;
	fd = vdsk->fd;
	/* L1 entries always exist */
	l2sz = disk->clustersz / 8;
	l1off = off / (disk->clustersz * l2sz);
	if (l1off >= disk->l1sz) {
		printf("%s: l1 offset outside disk\n\r", __func__);
		return (-1);
	}

	disk->end = (disk->end + disk->clustersz - 1) & ~(disk->clustersz - 1);

	l2tab = disk->l1[l1off];
	l2off = (off / disk->clustersz) % l2sz;
	/* We may need to create or clone an L2 entry to map the block */
	if (l2tab == 0 || (l2tab & QCOW2_INPLACE) == 0) {
		orig = l2tab & ~QCOW2_INPLACE;
		l2tab = disk->end;
		disk->end += disk->clustersz;
		if ((vdsk->fflags & FWRITE) == FWRITE) {
			if (ftruncate(vdsk->fd, disk->end) == -1) {
				printf("%s: ftruncate failed\r\n", __func__);
				printf("%s: (%d) %s\r\n", __func__, errno,
					strerror(errno));
				return (-1);
			}
		} else {
			printf("%s: could not grow disk, no WRITE ACCESS\n\r",
				__func__);
			return (-1);
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
	if ((vdsk->fflags & FWRITE) == FWRITE) {
		if (ftruncate(vdsk->fd, disk->end + disk->clustersz) < 0) {
			printf("%s: ftruncate failed\r\n", __func__);
			printf("%s: (%d) %s\r\n", __func__, errno,
				strerror(errno));
			return (-1);
		}
	} else {
			printf("%s: could not grow disk, no WRITE ACCESS\n\r",
				__func__);
			return (-1);
	}

	if (src_phys > 0)
		copy_cluster(vdsk, vdsk_base, disk->end, src_phys);
	cluster = disk->end;
	disk->end += disk->clustersz;
	buf = htobe64(cluster | QCOW2_INPLACE);
	if (pwrite(vdsk->fd, &buf, sizeof(buf), l2tab + l2off * 8) != 8) {
		printf("%s: could not write cluster\r\n", __func__);
		printf("%s: (%d) %s\r\n", __func__, errno, strerror(errno));
		return (-1);
	}

	buf = htobe64(disk->l1[l1off]);
	if (pwrite(vdsk->fd, &buf, sizeof(buf), disk->l1off + 8 * l1off) != 8) {
		printf("%s: could not write l1\n\r", __func__);
		printf("%s: (%d) %s\r\n", __func__, errno, strerror(errno));
		return (-1);
	}
	inc_refs(vdsk, cluster, 1);

	clusteroff = off % disk->clustersz;
	if (cluster + clusteroff < disk->clustersz) {
		printf("%s: write would clobber header\n\r", __func__);
		printf("%s: (%d) %s\r\n", __func__, errno, strerror(errno));
		return (-1);
	}
	return cluster + clusteroff;
}


/* Copies a cluster containing src to dst. Src and dst need not be aligned. */
static void
copy_cluster(struct vdsk *vdsk, struct vdsk *vdsk_base, off_t dst, off_t src)
{
	char *scratch;
	struct qcdsk *disk, *base;
	off_t ret;

	ret = 0;

	disk = qcow_deref(vdsk);
	base = qcow_deref(vdsk_base);

	scratch = alloca(disk->clustersz);
	if (!scratch) {
		printf("%s: out of memory\n\r", __func__);
		printf("%s: (%d) %s\r\n", __func__, errno, strerror(errno));
		return;
	}
	src &= ~(disk->clustersz - 1);
	dst &= ~(disk->clustersz - 1);

	ret = pread(vdsk_base->fd, scratch, disk->clustersz, src);
	if (ret == -1) {
		printf("%s: could not read cluster", __func__);
		printf("%s: (%d) %s\r\n", __func__, errno, strerror(errno));
		return;
	}

	ret = pwrite(vdsk->fd, scratch, disk->clustersz, dst);
	if (ret == -1) {
		printf("%s: could not write cluster", __func__);
		printf("%s: (%d) %s\r\n", __func__, errno, strerror(errno));
		return;
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

	disk = qcow_deref(vdsk);

	off &= ~QCOW2_INPLACE;
	nper = disk->clustersz / 2;
	l1idx = (off / disk->clustersz) / nper;
	l2idx = (off / disk->clustersz) % nper;
	l1off = disk->refoff + 8 * l1idx;
	if (pread(vdsk->fd, &buf, sizeof(buf), l1off) != 8) {
		printf("%s: could not read refs\r\n", __func__);
		printf("%s: (%d) %s\r\n", __func__, errno, strerror(errno));
		return;
	}

	l2cluster = be64toh(buf);
	if (l2cluster == 0) {
		l2cluster = disk->end;
		disk->end += disk->clustersz;
		if (ftruncate(vdsk->fd, disk->end) < 0) {
			printf("%s: failed to allocate ref block\r\n", __func__);
			printf("%s: (%d) %s\r\n", __func__, errno, strerror(errno));
			return;
		}
		buf = htobe64(l2cluster);
		if (pwrite(vdsk->fd, &buf, sizeof(buf), l1off) != 8) {
			printf("%s: failed to write ref block\r\n", __func__);
			printf("%s: (%d) %s\r\n", __func__, errno, strerror(errno));
			return;
		}
	}

	refs = 1;
	if (!newcluster) {
		if (pread(vdsk->fd, &refs, sizeof(refs),
		    l2cluster + 2 * l2idx) != 2) {
			printf("%s: could not read ref cluster\n\r", __func__);
			printf("%s: (%d) %s\r\n", __func__, errno, strerror(errno));
			return;
		}
		refs = be16toh(refs) + 1;
	}
	refs = htobe16(refs);
	if (pwrite(vdsk->fd, &refs, sizeof(refs), l2cluster + 2 * l2idx) != 2) {
		printf("%s: could not write ref block\n\r", __func__);
		printf("%s: (%d) %s\r\n", __func__, errno, strerror(errno));
		return;
	}
}

static int
qcow_trim(struct vdsk __unused *vdsk, off_t __unused offset, size_t __unused length)
{
	int error;

	error = 0;
	if (vdsk_is_dev(vdsk)) {
		printf("%s: You should't be here\r\n", __func__);
	} else {
		DPRINTF("%s: You should be here \r\n", __func__);
	}
	return (error);
}

static int
qcow_flush(struct vdsk *vdsk)
{
	int error;
	struct qcdsk *disk = qcow_deref(vdsk);

	error = 0;
	if (vdsk_is_dev(vdsk)) {
		printf("%s: You should't be here\r\n", __func__);
	} else {
		if (disk->base)
			qcow_flush(disk->base);
		if (fsync(vdsk->fd) == -1) {
			error = errno;
			printf("%s: (%d) %s\r\n", __func__, errno,
				strerror(errno));
		}
		DPRINTF("%s: You should be here\r\n", __func__);
	}
	return (error);
}

static struct vdsk_format qcow_format = {
	.name = "qcow",
	.description = "QEMU Copy-On-Write, version 1",
	.flags = VDSKFMT_CAN_WRITE | VDSKFMT_HAS_HEADER,
	.struct_size = sizeof(struct qcdsk),
	.probe = qcow_probe,
	.open = qcow_open,
	.close = qcow_close,
	.readv = qcow_readv,
	.writev = qcow_writev,
	.trim = qcow_trim,
	.flush = qcow_flush,
};
FORMAT_DEFINE(qcow_format);
