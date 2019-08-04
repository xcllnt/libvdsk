# $FreeBSD: user/marcel/libvdsk/libvdsk/Makefile 275095 2014-11-26 00:58:36Z marcel $

LIB=	vdsk
SHLIB_MAJOR= 0

SRCS=	vdsk.c vdsk_trace.c
INCS=	vdsk.h

# List of formats to support
SRCS+=	\
	qcow.c \
	raw.c \
	vhd.c \
	vmdk.c

DEBUG_FLAGS=-O0 -gdwarf-2 -DSMP

MAN=	\
	libvdsk.3 \
	vdsk_close.3 \
	vdsk_does_trim.3 \
	vdsk_fd.3 \
	vdsk_flush.3 \
	vdsk_media_size.3 \
	vdsk_open.3 \
	vdsk_read.3 \
	vdsk_readv.3 \
	vdsk_sector_size.3 \
	vdsk_stripe_offset.3 \
	vdsk_stripe_size.3 \
	vdsk_trim.3 \
	vdsk_write.3 \
	vdsk_writev.3

.include <bsd.lib.mk>
