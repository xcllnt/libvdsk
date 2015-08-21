# $FreeBSD: user/marcel/libvdsk/libvdsk/Makefile 275095 2014-11-26 00:58:36Z marcel $

LIB=	vdsk
SHLIB_MAJOR= 0

SRCS=	vdsk.c
INCS=	vdsk.h

# List of formats to support
SRCS+=	\
	qcow.c \
	raw.c \
	vhd.c \
	vmdk.c

DEBUG_FLAGS=-O0 -gdwarf-2

.include <bsd.lib.mk>
