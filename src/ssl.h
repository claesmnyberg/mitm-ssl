/*
 * ssl.h - SSL routines header file
 *
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
 * $Id: ssl.h,v 1.2 2005-02-13 21:09:46 cmn Exp $
 */

#ifndef _CMN_SSL
#define _CMN_SSL

#include <openssl/ssl.h>

struct sslsocket {

	SSL_CTX *ctx;
	SSL_METHOD *meth;
	SSL *ssl;

	u_short lport;	/* Local-Listen port */

	/* Socket descriptor */
	int fd;	
};

/* ssl.c */
extern void ssl_server(uint32_t, uint16_t, const char *, 
	const char *, void *(*)(void *));
extern struct sslsocket * ssl_connect(uint32_t ipv4, uint16_t port);
extern const char *ssl_errstr(SSL *, int);
extern struct sslsocket *ssl_init_ctx(const char *, const char *);
extern ssize_t ssl_read(struct sslsocket *, void *, size_t);
extern ssize_t ssl_readn(struct sslsocket *, void *, size_t);
extern ssize_t ssl_readline(struct sslsocket *, void *, size_t);
extern ssize_t ssl_write(struct sslsocket *, void *, size_t);
extern ssize_t ssl_writen(struct sslsocket *, void *, size_t);
extern void ssl_close(struct sslsocket *);
extern int ssl_check_cert(struct sslsocket *);

#endif /* _CMN_SSL */
