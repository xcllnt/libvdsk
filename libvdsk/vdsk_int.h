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
 *
 * $FreeBSD: user/marcel/libvdsk/libvdsk/vdsk_int.h 286996 2015-08-21 15:20:01Z marcel $
 */

#ifndef __VDSK_INT_H__
#define	__VDSK_INT_H__

#include <sys/linker_set.h>

#define DPRINTF(params) if (vdsk_debug) printf params
#define WPRINTF(params) printf params

struct vdsk;

/*
 * The disk format registration structure.
 */
struct vdsk_format {
	const char	*name;
	const char	*description;
	int	flags;
#define	VDSKFMT_DEVICE_OK	1
#define	VDSKFMT_CAN_WRITE	2
#define	VDSKFMT_NO_METADATA	0
#define	VDSKFMT_HAS_FOOTER	4
#define	VDSKFMT_HAS_HEADER	8
	int	(*probe)(struct vdsk *);
	int	(*open)(struct vdsk *);
	int	(*close)(struct vdsk *);
	ssize_t	(*readv)(struct vdsk *, const struct iovec *, int, off_t);
	ssize_t	(*read)(struct vdsk *, void *, size_t, off_t);
	ssize_t	(*writev)(struct vdsk *, const struct iovec *, int, off_t);
	ssize_t	(*write)(struct vdsk *, void *, size_t, off_t);
	int	(*trim)(struct vdsk *, off_t, ssize_t);
	int	(*flush)(struct vdsk *, unsigned long);
};

SET_DECLARE(libvdsk_formats, struct vdsk_format);
#define	FORMAT_DEFINE(nm)	DATA_SET(libvdsk_formats, nm)

/*
 * The internal representation of a "disk".
 */
struct vdsk {
	struct vdsk_format *fmt;
	int	fd;
	int	fflags;
	char	*filename;
	struct stat fsbuf;
	off_t	capacity;
	int	sectorsize;
} __attribute__((aligned(16)));

#endif /* __VDSK_INT_H__ */
