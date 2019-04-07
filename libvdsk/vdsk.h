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
 * $FreeBSD: user/marcel/libvdsk/libvdsk/vdsk.h 286996 2015-08-21 15:20:01Z marcel $
 */

#ifndef __VDSK_H__
#define	__VDSK_H__

#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

typedef void *vdskctx;

vdskctx	vdsk_open(const char *, int, size_t);
int	vdsk_close(vdskctx);

int	vdsk_fd(vdskctx);

int	vdsk_does_trim(vdskctx);

off_t	vdsk_media_size(vdskctx);
int	vdsk_sector_size(vdskctx);

int	vdsk_stripe_size(vdskctx);
int	vdsk_stripe_offset(vdskctx);

ssize_t	vdsk_read(vdskctx, void *, size_t, off_t);
ssize_t	vdsk_write(vdskctx, const void *, size_t, off_t);

ssize_t	vdsk_readv(vdskctx, const struct iovec *, int, off_t);
ssize_t	vdsk_writev(vdskctx, const struct iovec *, int, off_t);

int	vdsk_trim(vdskctx, off_t offset, size_t);
int	vdsk_flush(vdskctx);

#endif /* __VDSK_H__ */
