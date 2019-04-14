/*-
 * Copyright (c) 2014, 2019 Marcel Moolenaar
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
__FBSDID("$FreeBSD: user/marcel/libvdsk/libvdsk/vdsk.c 286996 2015-08-21 15:20:01Z marcel $");

#include <sys/disk.h>
#include <sys/param.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "vdsk_int.h"

static int vdsk_options;

static __attribute__((constructor)) void
vdsk_initialize(void)
{
	char *env;

	vdsk_options = 0;

	/*
	 * Check for LIBVDSK_TRACE in the environment.  If set, we'll
	 * use syslog(3) to log trace messages.
	 */
	env = getenv("LIBVDSK_TRACE");
	if (env != NULL)
		vdsk_options |= VDSK_TRACE;
}

static struct vdsk *
vdsk_deref(vdskctx ctx)
{
	struct vdsk *vdsk = ctx;

	return (vdsk - 1);
}

static struct vdsk_format *
vdsk_probe(struct vdsk *vdsk)
{
	struct vdsk_format **fmts;
	struct vdsk_format *f, *fmt;
	size_t idx, nfmts;
	int error, probe;

	/*
	 * Create a mutable copy of the linker set.
	 */
	nfmts = SET_COUNT(libvdsk_formats);
	fmts = malloc(nfmts * sizeof(*fmts));
	if (fmts == NULL)
		return (NULL);
	memcpy(fmts, SET_BEGIN(libvdsk_formats), nfmts * sizeof(*fmts));

	fmt = NULL;
	probe = VDSKFMT_HAS_HEADER | VDSKFMT_HAS_FOOTER;
	probe |= (vdsk_is_dev(vdsk)) ? VDSKFMT_DEVICE_OK : 0;
	probe |= (vdsk->fflags & FWRITE) ? VDSKFMT_CAN_WRITE : 0;
	while (fmt == NULL && probe >= 0) {
		for (idx = 0; idx < nfmts; idx++) {
			f = fmts[idx];
			/* Skip formats we've probed already. */
			if (f == NULL)
				continue;
			/* Skip formats we shouldn't probe now. */
			if ((f->flags & probe) != probe)
				continue;
			/* White-out this format and probe it. */
			fmts[idx] = NULL;
			error = f->probe(vdsk);
			if (!error) {
				/* We have a match. */
				fmt = f;
				break;
			}
		}
		if (fmt == NULL)
			probe -= VDSKFMT_HAS_FOOTER;
	}
	free(fmts);
	if (fmt == NULL)
		errno = EFTYPE;

	return (fmt);
}

vdskctx
vdsk_open(const char *path, int flags, size_t size)
{
	vdskctx ctx;
	struct vdsk *vdsk;
	struct diocgattr_arg attr;
	int lck;

	if (vdsk_options & VDSK_TRACE)
		vdsk_trace_enter(__func__, 3,
		    "path", "%s", path,
		    "flags", "%d", flags,
		    "size", "%zu", size);

	ctx = NULL;

	do {
		size += sizeof(struct vdsk);
		vdsk = calloc(1, size);
		if (vdsk == NULL)
			break;

		/* Set system-wide options */
		vdsk->options = vdsk_options;

		vdsk->fflags = flags + 1;
		if ((vdsk->fflags & ~(O_ACCMODE | O_DIRECT | O_SYNC)) != 0) {
			errno = EINVAL;
			break;
		}

		vdsk->filename = realpath(path, NULL);
		if (vdsk->filename == NULL)
			break;

		flags = (flags & O_ACCMODE) | O_CLOEXEC;
		vdsk->fd = open(vdsk->filename, flags);
		if (vdsk->fd == -1)
			break;

		if (fstat(vdsk->fd, &vdsk->fsbuf) == -1)
			break;

		if (vdsk_is_dev(vdsk)) {
			/*
			 * Get required media & sector size information.
			 */
			if (ioctl(vdsk->fd, DIOCGMEDIASIZE,
			    &vdsk->media_size) < 0)
				break;
			if (ioctl(vdsk->fd, DIOCGSECTORSIZE,
			    &vdsk->sector_size) < 0)
				break;
			/*
			 * Get optional stripe information
			 */
			if (ioctl(vdsk->fd, DIOCGSTRIPESIZE,
			    &vdsk->stripe_size) < 0)
				vdsk->stripe_size = 0;
			if (vdsk->stripe_size > 0 && ioctl(vdsk->fd,
			    DIOCGSTRIPEOFFSET, &vdsk->stripe_offset) < 0)
				vdsk->stripe_offset = 0;
			/*
			 * Get optional GEOM attributes.
			 */
			strlcpy(attr.name, "GEOM::candelete",
			    sizeof(attr.name));
			attr.len = sizeof(attr.value.i);
			if (ioctl(vdsk->fd, DIOCGATTR, &attr) == 0) {
				if (attr.value.i)
					vdsk->options |= VDSK_DOES_TRIM;
				/* Distinguish between ZFS and GEOM. */
				strlcpy(attr.name, "GEOM::ident",
				    sizeof(attr.name));
				attr.len = sizeof(attr.value.str);
				if (ioctl(vdsk->fd, DIOCGATTR, &attr) == 0)
					vdsk->options |= VDSK_IS_GEOM;
			}
		} else {
			vdsk->media_size = vdsk->fsbuf.st_size;
			vdsk->sector_size = DEV_BSIZE;
			vdsk->stripe_size = vdsk->fsbuf.st_blksize;
		}

		vdsk->fmt = vdsk_probe(vdsk);
		if (vdsk->fmt == NULL)
			break;

		lck = (vdsk->fflags & FWRITE) ? LOCK_EX : LOCK_SH;
		if (flock(vdsk->fd, lck | LOCK_NB) == -1)
			break;

		errno = vdsk->fmt->open(vdsk);
		if (errno != 0) {
			flock(vdsk->fd, LOCK_UN);
			break;
		}

		/* Complete... */
		ctx = vdsk + 1;
	} while (0);

	if (ctx == NULL) {
		if (vdsk != NULL) {
			if (vdsk->fd != -1)
				close(vdsk->fd);
			if (vdsk->filename != NULL)
				free(vdsk->filename);
			free(vdsk);
		}
	}

	if (vdsk_options & VDSK_TRACE) {
		if (ctx != NULL)
			vdsk_trace_leave(__func__, 4,
			    "ctx", "%p", ctx,
			    "format", "%s", vdsk->fmt->name,
			    "options", "0x%08x", vdsk->options,
			    "st_mode", "0%06o", vdsk->fsbuf.st_mode);
		else
			vdsk_trace_leave(__func__, 2,
			    "ctx", "%p", ctx,
			    "errno", "%d", errno);
	}
	return (ctx);
}

int
vdsk_close(vdskctx ctx)
{
	struct vdsk *vdsk = vdsk_deref(ctx);

	vdsk->fmt->close(vdsk);
	flock(vdsk->fd, LOCK_UN);
	close(vdsk->fd);
	free(vdsk->filename);
	free(vdsk);
	return (0);
}

int
vdsk_fd(vdskctx ctx)
{
	struct vdsk *vdsk = vdsk_deref(ctx);

	return (vdsk->fd);
}

int
vdsk_does_trim(vdskctx ctx)
{
	struct vdsk *vdsk = vdsk_deref(ctx);

	return ((vdsk->options & VDSK_DOES_TRIM) ? 1 : 0);
}

off_t
vdsk_media_size(vdskctx ctx)
{
	struct vdsk *vdsk = vdsk_deref(ctx);

	return (vdsk->media_size);
}

int
vdsk_sector_size(vdskctx ctx)
{
	struct vdsk *vdsk = vdsk_deref(ctx);

	return (vdsk->sector_size);
}

int
vdsk_stripe_size(vdskctx ctx)
{
	struct vdsk *vdsk = vdsk_deref(ctx);

	return (vdsk->stripe_size);
}

int
vdsk_stripe_offset(vdskctx ctx)
{
	struct vdsk *vdsk = vdsk_deref(ctx);

	return (vdsk->stripe_offset);
}

ssize_t
vdsk_readv(vdskctx ctx, const struct iovec *iov, int iovcnt, off_t offset)
{
	struct vdsk *vdsk = vdsk_deref(ctx);

	return (vdsk->fmt->readv(vdsk, iov, iovcnt, offset));
}

ssize_t
vdsk_read(vdskctx ctx, void *buffer, size_t nbytes, off_t offset)
{
	struct vdsk *vdsk = vdsk_deref(ctx);

	return (vdsk->fmt->read(vdsk, buffer, nbytes, offset));
}

ssize_t
vdsk_writev(vdskctx ctx, const struct iovec *iov, int iovcnt, off_t offset)
{
	struct vdsk *vdsk = vdsk_deref(ctx);

	if ((vdsk->fflags & FWRITE) == 0)
		return (EROFS);
	return (vdsk->fmt->writev(vdsk, iov, iovcnt, offset));
}

ssize_t
vdsk_write(vdskctx ctx, const void *buffer, size_t nbytes, off_t offset)
{
	struct vdsk *vdsk = vdsk_deref(ctx);

	return (vdsk->fmt->write(vdsk, buffer, nbytes, offset));
}

int
vdsk_trim(vdskctx ctx, off_t offset, size_t length)
{
	struct vdsk *vdsk = vdsk_deref(ctx);

	if ((vdsk->fflags & FWRITE) == 0)
		return (EROFS);
	return (vdsk->fmt->trim(vdsk, offset, length));
}

int
vdsk_flush(vdskctx ctx)
{
	struct vdsk *vdsk = vdsk_deref(ctx);

	if ((vdsk->fflags & FWRITE) == 0)
		return (0);
	return (vdsk->fmt->flush(vdsk));
}

