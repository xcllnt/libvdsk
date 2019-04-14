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
__FBSDID("$FreeBSD: user/marcel/libvdsk/libvdsk/raw.c 286996 2015-08-21 15:20:01Z marcel $");

#include <sys/ioctl.h>
#include <sys/disk.h>
#include <sys/param.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "vdsk_int.h"

static ssize_t raw_geom_read(struct vdsk *, const struct iovec *, int, off_t);
static ssize_t raw_geom_write(struct vdsk *, const struct iovec *, int, off_t);

static int
raw_probe(struct vdsk *vdsk __unused)
{

	return (0);
}

static int
raw_open(struct vdsk *vdsk)
{

	/*
	 * Handle scatter/gather problems when the device is a GEOM
	 * device.  I/O must always be a multiple of the sector
	 * size, which is not guaranteed when we give the iovec to
	 * the kernel to work on.  This seems to be due to how
	 * physio() works.
	 */
	if (vdsk->options & VDSK_IS_GEOM) {
		vdsk->fmt_data = malloc(vdsk->sector_size);
		if (vdsk->fmt_data == NULL)
			return (ENOMEM);
	}
	return (0);
}

static int
raw_close(struct vdsk *vdsk)
{

	if (vdsk->fmt_data != NULL)
		free(vdsk->fmt_data);
	return (0);
}

static ssize_t
raw_read(struct vdsk *vdsk, void *buf, size_t nbytes, off_t offset)
{
	ssize_t res;

	res = pread(vdsk->fd, buf, nbytes, offset);
	return (res);
}

static ssize_t
raw_write(struct vdsk *vdsk, const void *buf, size_t nbytes, off_t offset)
{
	ssize_t res;

	res = pwrite(vdsk->fd, buf, nbytes, offset);
	return (res);
}

static ssize_t
raw_readv(struct vdsk *vdsk, const struct iovec *iov, int iovcnt, off_t offset)
{
	ssize_t res;

	if ((vdsk->options & VDSK_IS_GEOM) && iovcnt > 1)
		res = raw_geom_read(vdsk, iov, iovcnt, offset);
	else
		res = preadv(vdsk->fd, iov, iovcnt, offset);
	return (res);
}

static ssize_t
raw_writev(struct vdsk *vdsk, const struct iovec *iov, int iovcnt, off_t offset)
{
	ssize_t res;

	if ((vdsk->options & VDSK_IS_GEOM) && iovcnt > 1)
		res = raw_geom_write(vdsk, iov, iovcnt, offset);
	else
		res = pwritev(vdsk->fd, iov, iovcnt, offset);
	return (res);
}

static int
raw_trim(struct vdsk *vdsk, off_t offset, size_t length)
{
	int error;

	error = 0;
	if (vdsk_is_dev(vdsk)) {
		off_t arg[2];

		arg[0] = offset;
		arg[1] = length;
		if (ioctl(vdsk->fd, DIOCGDELETE, arg) < 0)
			error = errno;
	} else {
		/* XXX what about creating a sparse file? */
	}
	return (error);
}

static int
raw_flush(struct vdsk *vdsk)
{
	int error;

	error = 0;
	if (vdsk_is_dev(vdsk)) {
		if (ioctl(vdsk->fd, DIOCGFLUSH) < 0)
			error = errno;
	} else {
		if (fsync(vdsk->fd) == -1)
			error = errno;
	}
	return (error);
}

static ssize_t
raw_geom_read(struct vdsk *vdsk, const struct iovec *iov, int iovcnt,
    off_t offset)
{
	char	*iobuf, *buf;
	ssize_t	nbytes, res;
	size_t	iosz, iov_ofs;
	int	iovidx;

	buf = vdsk->fmt_data;
	iovidx = 0;
	iosz = 0;
	nbytes = 0;
	while (iovidx < iovcnt) {
		iobuf = iov[iovidx].iov_base;
		/*
		 * NOTE: iosz and iov_ofs are carried over from the previous
		 * iteration.  This to handle partial sector reads.
		 */
		if (iosz > 0) {
			memcpy(iobuf, buf + iov_ofs, iosz);
			nbytes += iosz;
		}
		iov_ofs = iosz;
		while (iov_ofs < iov[iovidx].iov_len) {
			iosz = MIN(iov[iovidx].iov_len - iov_ofs, MAXPHYS);
			if (iosz < (size_t)vdsk->sector_size) {
				res = pread(vdsk->fd, buf, vdsk->sector_size,
				    offset + nbytes);
				if (res == -1)
					goto errout;
				if (res != vdsk->sector_size) {
					errno = EIO;
					goto errout;
				}
				memcpy(iobuf + iov_ofs, buf, iosz);
				nbytes += iosz;
				iov_ofs = iosz;
				iosz = vdsk->sector_size - iosz;
				break;
			}
			iosz -= (iosz % vdsk->sector_size);
			res = pread(vdsk->fd, iobuf + iov_ofs, iosz,
			    offset + nbytes);
			if (res == -1)
				goto errout;
			if (res == 0) {
				errno = EIO;
				goto errout;
			}
			nbytes += res;
			iov_ofs += res;
			iosz = 0;
		}
		iovidx++;
	}
	return (nbytes);

 errout:
	return ((nbytes > 0) ? nbytes : -1);
}

static ssize_t
raw_geom_write(struct vdsk *vdsk, const struct iovec *iov, int iovcnt,
    off_t offset)
{
	char	*iobuf, *buf;
	ssize_t	nbytes, res;
	size_t	iosz, iov_ofs;
	int	iovidx;

	buf = vdsk->fmt_data;
	iovidx = 0;
	iosz = 0;
	nbytes = 0;
	while (iovidx < iovcnt) {
		iobuf = iov[iovidx].iov_base;
		/*
		 * NOTE: iosz and iov_ofs are carried over from the previous
		 * iteration.  This to handle partial sector writes.
		 */
		if (iosz > 0) {
			memcpy(buf + iov_ofs, iobuf, iosz);
			res = pwrite(vdsk->fd, buf, vdsk->sector_size,
			    offset + nbytes);
			if (res == -1)
				goto errout;
			if (res != vdsk->sector_size) {
				errno = EIO;
				goto errout;
			}
			nbytes += vdsk->sector_size;
		}
		iov_ofs = iosz;
		while (iov_ofs < iov[iovidx].iov_len) {
			iosz = MIN(iov[iovidx].iov_len - iov_ofs, MAXPHYS);
			if (iosz < (size_t)vdsk->sector_size) {
				memcpy(buf, iobuf + iov_ofs, iosz);
				iov_ofs = iosz;
				iosz = vdsk->sector_size - iosz;
				break;
			}
			iosz -= (iosz % vdsk->sector_size);
			res = pwrite(vdsk->fd, iobuf + iov_ofs, iosz,
			    offset + nbytes);
			if (res == -1)
				goto errout;
			if (res == 0) {
				errno = EIO;
				goto errout;
			}
			nbytes += res;
			iov_ofs += res;
			iosz = 0;
		}
		iovidx++;
	}
	return (nbytes);

 errout:
	return ((nbytes > 0) ? nbytes : -1);
}

static struct vdsk_format raw_format = {
	.name = "raw",
	.description = "Raw Disk File or Device",
	.flags = VDSKFMT_CAN_WRITE | VDSKFMT_DEVICE_OK | VDSKFMT_NO_METADATA,
	.probe = raw_probe,
	.open = raw_open,
	.close = raw_close,
	.read = raw_read,
	.write = raw_write,
	.readv = raw_readv,
	.writev = raw_writev,
	.trim = raw_trim,
	.flush = raw_flush,
};
FORMAT_DEFINE(raw_format);

