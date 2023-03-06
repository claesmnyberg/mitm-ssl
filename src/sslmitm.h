/*
 *  Copyright (c) 2005 Claes M. Nyberg <cmn@darklab.org>
 *  All rights reserved, all wrongs reversed.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions
 *  are met:
 *
 *  1. Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *  2. Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *  3. The name of author may not be used to endorse or promote products
 *     derived from this software without specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 *  INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 *  AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
 *  THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 *  EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 *  PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 *  OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 *  WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 *  OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 *  ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * $Id: sslmitm.h,v 1.3 2005-07-08 13:36:59 cmn Exp $
 */

#ifndef _SSLMITM
#define _SSLMITM

#include <sys/types.h>
#include "print.h"
#include "mem.h"
#include "net.h"
#include "ssl.h"
#include "str.h"
#include "tcproute.h"
#include "utils.h"
#include "scan.h"

struct options {
	const char *keyfile;
	const char *certfile;
	const char *c_logdir;
	const char *s_logdir;
	const char *pwfile;
	const char *iface;   /* ARP spoof interface */
	size_t size;         /* Number of bytes to log */
	u_short *ports; 	 /* Ports to listen on */
	u_char verbose;
	u_int resolve:1;
	u_int r_addr;		/* Route all traffic to host */
	u_short r_port;
	u_int daemon:1;
	const char *logfile;
};

/* daemon.h */
extern int daemonize(void);
#endif /* _SSLMITM */
