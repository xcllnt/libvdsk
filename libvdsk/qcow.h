/*-
 * Copyright (c) 2019 Sergiu Weisz
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
 */

#ifndef __QCOW_H__
#define	__QCOW_H__

/* QCOW HEADER */
struct qcheader {
	uint32_t	magic;
	uint32_t	version;
	uint64_t	backingoff;
	uint32_t	backingsz;
	uint32_t	clustershift;
	uint64_t	disksz;
	/* v2 */
	uint32_t	cryptmethod;
	uint32_t	l1sz;
	uint64_t	l1off;
	uint64_t	refoff;
	uint32_t	refsz;
	uint32_t	snapcount;
	uint64_t	snapsz;
	/* v3 */
	uint64_t	incompatfeatures;
	uint64_t	compatfeatures;
	uint64_t	autoclearfeatures;
	uint32_t	reforder; /* Bits = 1 << reforder */
	uint32_t	headersz;
} __packed;

struct qcdsk {
	/* QCOW */
	struct qcheader header;
	struct vdsk *vdsk;
	struct vdsk *base;

	uint64_t	*l1;
	off_t		end;
	off_t		clustersz;
	off_t		disksz; /* In bytes */
	uint32_t	cryptmethod;

	uint32_t	l1sz;
	off_t		l1off;

	uint32_t	l2sz;
	off_t		l2off;

	off_t		refoff;
	off_t		refsz;

	uint32_t	nsnap;
	off_t		snapoff;

	/* v3 */
	uint64_t	incompatfeatures;
	uint64_t	autoclearfeatures;
	uint32_t	refssz;
	uint32_t	headersz;

#ifdef SMP
	pthread_rwlock_t lock;
#endif
};
#endif
