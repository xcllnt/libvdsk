#
# $FreeBSD: user/marcel/libvdsk/bhyve/Makefile 286979 2015-08-21 05:02:26Z marcel $
#

PROG=	bhyve

DEBUG_FLAGS= -g -O0

MAN=	bhyve.8

SRCS=	\
	atkbdc.c		\
	acpi.c			\
	bhyverun.c		\
	block_if.c		\
	bootrom.c		\
	consport.c		\
	dbgport.c		\
	inout.c			\
	ioapic.c		\
	mem.c			\
	mevent.c		\
	mptbl.c			\
	pci_ahci.c		\
	pci_emul.c		\
	pci_hostbridge.c	\
	pci_irq.c		\
	pci_lpc.c		\
	pci_passthru.c		\
	pci_virtio_block.c	\
	pci_virtio_net.c	\
	pci_virtio_rnd.c	\
	pci_uart.c		\
	pm.c			\
	post.c			\
	rtc.c			\
	smbiostbl.c		\
	task_switch.c		\
	uart_emul.c		\
	virtio.c		\
	xmsr.c			\
	spinup_ap.c

.PATH:	/sys/amd64/vmm
SRCS+=	vmm_instruction_emul.c

DPADD=	${LIBVDSK} ${LIBVMMAPI} ${LIBMD} ${LIBPTHREAD}
LDADD=	-lvdsk -lvmmapi -lmd -lpthread

WARNS?=	2

.include <bsd.prog.mk>
