# $FreeBSD: user/marcel/libvdsk/Makefile.inc 274801 2014-11-21 17:23:15Z marcel $

CFLAGS +=	-I${.CURDIR}/../libvdsk
LDFLAGS +=	-L${.OBJDIR}/../libvdsk
LIBVDSK ?=	${.OBJDIR}/../libvdsk/libvdsk.a

BINDIR ?=	/usr/sbin
SHLIB_MAJOR ?=	5
WARNS ?=	6
