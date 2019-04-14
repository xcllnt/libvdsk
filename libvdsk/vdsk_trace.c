/*-
 * Copyright (c) 2019 Marcel Moolenaar
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
__FBSDID("$FreeBSD$");

#include <sys/types.h>
#include <sys/sbuf.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>

#include "vdsk_int.h"

void
vdsk_trace(const char *when, const char *func, int count, const char *var1,
    const char *fmt1, va_list ap)
{
	const char *fmt, *var;
	char *logmsg, *msg1, *msg2;

	var = var1;
	fmt = fmt1;

	asprintf(&logmsg, "LIBVDSK::%s function=\'%s\'", when, func);

	while (logmsg != NULL && count-- > 0) {
		vasprintf(&msg1, fmt, ap);
		asprintf(&msg2, "%s='%s'", var, msg1);
		free(msg1);
		msg1 = logmsg;
		asprintf(&logmsg, "%s %s", msg1, msg2);
		free(msg2);
		free(msg1);
		if (count > 0) {
			var = va_arg(ap, const char *);
			fmt = va_arg(ap, const char *);
		}
	}

	if (logmsg != NULL) {
		syslog(LOG_DEBUG, "%s", logmsg);
		free(logmsg);
	}
}
