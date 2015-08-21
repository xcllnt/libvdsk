# $FreeBSD: user/marcel/libvdsk/bhyveload/Makefile 286979 2015-08-21 05:02:26Z marcel $

PROG=	bhyveload
SRCS=	bhyveload.c
MAN=	bhyveload.8

DPADD+=	${LIBVDSK} ${LIBVMMAPI}
LDADD+=	-lvdsk -lvmmapi

WARNS?=	3

CFLAGS+=-I/sys/boot/userboot

.include <bsd.prog.mk>
