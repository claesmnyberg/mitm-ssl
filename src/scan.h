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
 * $Id: scan.h,v 1.2 2005-07-08 13:36:59 cmn Exp $
 */

#ifndef _SCAN_H
#define _SCAN_H

#ifndef NO_PASSWD_SCAN

/* scan.c */
extern void scan_buffer(time_t, FILE *, u_int, u_short, 
	u_int, u_short, u_int8_t *, size_t);

/* decode_*.c */
extern int decode_http(u_int8_t *, size_t, u_int8_t *, size_t);
extern int decode_ftp(u_int8_t *, size_t, u_int8_t *, size_t);
extern int decode_imap(u_int8_t *, size_t, u_int8_t *, size_t);
extern int decode_irc(u_int8_t *, size_t, u_int8_t *, size_t);
extern int decode_ldap(u_int8_t *, size_t, u_int8_t *, size_t);
extern int decode_pop(u_int8_t *, size_t, u_int8_t *, size_t);
extern int decode_smtp(u_int8_t *, size_t, u_int8_t *, size_t);

#endif /* NO_PASSWD_SCAN */
#endif /* _SCAN_H */
