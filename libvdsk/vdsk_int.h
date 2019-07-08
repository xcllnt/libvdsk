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
 *
 * $FreeBSD: user/marcel/libvdsk/libvdsk/vdsk_int.h 286996 2015-08-21 15:20:01Z marcel $
 */

#ifndef __VDSK_INT_H__
#define	__VDSK_INT_H__

#include <sys/linker_set.h>
#include <sys/stat.h>
#include <stdarg.h>
#include <vdsk.h>
#ifdef SMP
#include <pthread.h>
#endif

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
	size_t	struct_size;
	int	(*probe)(struct vdsk *);
	int	(*open)(struct vdsk *);
	int	(*close)(struct vdsk *);
	ssize_t	(*readv)(struct vdsk *, const struct iovec *, int, off_t);
	ssize_t	(*writev)(struct vdsk *, const struct iovec *, int, off_t);
	int	(*trim)(struct vdsk *, off_t, size_t);
	int	(*flush)(struct vdsk *);
};

SET_DECLARE(libvdsk_formats, struct vdsk_format);
#define	FORMAT_DEFINE(nm)	DATA_SET(libvdsk_formats, nm)

/*
 * The internal representation of a "disk".
 */
struct vdsk {
	struct vdsk_format *fmt;
	void	*fmt_data;
	int	fd;
	int	fflags;
	char	*filename;
	struct stat fsbuf;
	off_t	media_size;
	int	sector_size;
	int	stripe_size;
	int	stripe_offset;
	int	options;
#define	VDSK_DOES_TRIM		1
#define	VDSK_IS_GEOM		2
#define	VDSK_TRACE		4
};


static inline int
vdsk_is_dev(struct vdsk *vdsk)
{

	return ((S_ISCHR(vdsk->fsbuf.st_mode)) ? 1 : 0);
}

void vdsk_trace(const char *, const char *, int, const char *, const char *,
    va_list);

static inline void
vdsk_trace_enter(const char *func, int count, const char *arg1,
    const char *fmt1, ...)
{
	va_list ap;

	va_start(ap, fmt1);
	vdsk_trace("ENTER", func, count, arg1, fmt1, ap);
	va_end(ap);
}

static inline void
vdsk_trace_leave(const char *func, int count, const char *arg1,
    const char *fmt1, ...)
{
	va_list ap;

	va_start(ap, fmt1);
	vdsk_trace("LEAVE", func, count, arg1, fmt1, ap);
	va_end(ap);
}

#ifdef DEBUG
#define DPRINTF(format, arg...) printf(format, ##arg)
#else
#define DPRINTF(format, arg...)
#endif

#define ERRPRINTF(format, arg...) dprintf(STDERR_FILENO, format, ##arg)

#endif /* __VDSK_INT_H__ */
