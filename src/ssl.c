/*
 * ssl.c - SSL routines
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
 * $Id: ssl.c,v 1.5 2005-07-08 11:25:16 cmn Exp $
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/stat.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include "print.h"
#include "random.h"
#include "ssl.h"
#include "net.h"

/* Local routines */
static int ssl_load_random(size_t);

/*  
 * Set up SSL connection.
 * port and ipv4 in network byte order.
 * Returns NULL on error, a pointer to a sslsocket structure on success.
 */    
struct sslsocket *
ssl_connect(uint32_t ipv4, uint16_t port)
{
    struct sslsocket *ss;
    struct sockaddr_in sin;
    BIO *bio;
    int r;
	const char *pt;
 
    memset(&sin, 0x00, sizeof(struct sockaddr_in));
    sin.sin_addr.s_addr = ipv4;
    sin.sin_port = port;
    sin.sin_family = AF_INET;

    if ( (ss = ssl_init_ctx(NULL, NULL)) == NULL) {
        err("ssl_init_ctx failed.\n");
		return(NULL);
	}

    if ( (ss->fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        err_errno("socket");
        free(ss);
        return(NULL);
    }

    if (connect(ss->fd, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
        pt = net_sockstr(&sin, 0);
		err_errno("connect %s", pt);
        close(ss->fd);
        free(ss);
		free((void *)pt);
        return(NULL);
    }

    /* Set up SSL */
    if ( (bio = BIO_new_socket(ss->fd, BIO_NOCLOSE)) == NULL) {
        err("BIO_new_socket() failed\n");
        debug("%s\n", ERR_error_string(ERR_get_error(), NULL));
        close(ss->fd);
        return(NULL);
    }

    if ( (ss->ssl = SSL_new(ss->ctx)) == NULL) {
        err("SSL_new() failed\n");
        debug("%s\n", ERR_error_string(ERR_get_error(), NULL));
        close(ss->fd);
        return(NULL);
    }

    SSL_set_bio(ss->ssl, bio, bio);

    if ( (r = SSL_connect(ss->ssl)) <= 0) {
        err("SSL_connect() failed: %s\n", ssl_errstr(ss->ssl, r));
        debug("%s\n", ERR_error_string(ERR_get_error(), NULL));
        close(ss->fd);
        free(ss);
        return(NULL);
    }

    /* Check the cert chain at this time if you care ...*/

    return(ss);
}

/*
 * Create and load random file
 */
int
ssl_load_random(size_t size)
{
	int ret = 0;
	char randfile[2048];
	char *pt;
	int fd;
	
    if ( (pt = getenv("TMP")) != NULL || (pt = getenv("TEMP")) != NULL)
        snprintf(randfile, sizeof(randfile)-1, "%s/rexecXXXXXX", pt);
    else
        snprintf(randfile, sizeof(randfile)-1, "/tmp/rexecXXXXXX");

    if ( (fd = mkstemp(randfile)) < 0) {
        err_errno("Failed to create random file '%s'", randfile);
        return(-1);
    }

	if ( (pt = malloc(size)) == NULL) {
		err_errno("Failed to allocate memory");
		close(fd);
		return(-1);
	}
	
	random_bytes((u_char *)pt, size);
	if (write(fd, pt, size) != size) {
		err_errno("Failed to write random file");
		free(pt);
		close(fd);
		return(-1);
	}
	free(pt);
	close(fd);

    if (RAND_load_file(randfile, size) == 0) {
        err("Could not load random file '%s'\n", randfile);
        debug("%s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
    }

	unlink(randfile);
	return(ret);
}

/*
 * Initialize context 
 */
struct sslsocket *
ssl_init_ctx(const char *certfile, const char *keyfile)
{
	struct sslsocket ss;
	struct sslsocket *ssp;
	memset(&ss, 0x00, sizeof(struct sslsocket));

	/* Global system initialization */
	SSL_library_init();
	SSL_load_error_strings();

	/* Create context */
	ss.meth = SSLv23_method();
	ss.ctx = SSL_CTX_new(ss.meth);

	/* Load keys and certificates */
	if (certfile != NULL) {
		if (SSL_CTX_use_certificate_file(ss.ctx, certfile, SSL_FILETYPE_PEM) == 0) {
			err("Could not read certificate file '%s'\n", certfile);
			debug("%s\n", ERR_error_string(ERR_get_error(), NULL));
			return(NULL);
		}
	}
	
	if (keyfile != NULL) {
		if (SSL_CTX_use_PrivateKey_file(ss.ctx, keyfile, SSL_FILETYPE_PEM) == 0) {
			err("Could not read key file '%s'\n", keyfile);
			debug("%s\n", ERR_error_string(ERR_get_error(), NULL));
			return(NULL);
		}
	}

	/* Load random file */
	if (ssl_load_random(2048) < 0) {
		err("Failed to load random\n");
		return(NULL);
	}
	
	if ( (ssp = calloc(1, sizeof(struct sslsocket))) == NULL)
		err_errnox("Failed to allocate memory");
	memcpy(ssp, &ss, sizeof(struct sslsocket));
	return(ssp);
}


/*
 * Set up SSL server and pass clients on to client_loop
 * localip - The local ip address (big endian) to listen for connections on
 * port    - The local port (big endian) to listen for connections on
 * client_loop - The function to handle clients
 */
void
ssl_server(uint32_t localip, uint16_t port,
		const char *keyfile, const char *certfile, 
		void *(*client_handler)(void *))
{
	struct sockaddr_in sin;
	struct sockaddr_in cin;
	unsigned int addrlen; 
	const char *pt;
	const char *pt2;
	int sfd;
	int cfd;

	addrlen = sizeof(struct sockaddr_in );
	memset(&cin, 0x00, sizeof(cin));
	memset(&sin, 0x00, sizeof(sin));
	sin.sin_addr.s_addr	= localip;
	sin.sin_family = AF_INET;
	sin.sin_port = port;

	if ( (sfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		err_errno("socket");
		return;
	}

	if (bind(sfd, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
		err_errno("bind");
		return;
	}

	if (listen(sfd, 5) < 0) {
		err_errno("bind");
		return;
	}
	
	pt = net_ntoa_ip(localip);
	if ( (pt2 = net_tcpserv_byport(port)) != NULL) {
		verbose(0, "SSL MITM Server Listening on %s:%s\n", 
			pt, pt2);
		free((void *)pt2);
	}
	else
		verbose(0, "SSL MITM Server Listening on %s:%u\n",
			pt, ntohs(port));
	free((void *)pt);
	
	/* Accept connection */
	while (1) {
		struct sslsocket *css;
		pthread_t thread;
		BIO *bio;	
		int r;

		if ( (cfd = accept(sfd, (struct sockaddr *)&cin, &addrlen)) < 0) {
			err_errno("accept");
			continue;
		}

		if (getpeername(cfd, (struct sockaddr *)&cin, &addrlen) < 0) {
			verbose(0, "** Error: getpeername: %s\n", strerror(errno));
			close(cfd);
			continue;
		}
		
		verbose(0, "%s:%u connected.\n", inet_ntoa(cin.sin_addr), 
			ntohs(cin.sin_port));

		if ( (css = ssl_init_ctx(certfile, keyfile)) == NULL) {
			err("Failed to init SSL context\n");
			close(cfd);
			continue;
		}
		css->fd = cfd;
		css->lport = port;
		
		/* Set up SSL */
		if ( (bio = BIO_new_socket(cfd, BIO_NOCLOSE)) == NULL) {
			err("BIO_new_socket() failed\n");
			debug("%s\n", ERR_error_string(ERR_get_error(), NULL));
			ssl_close(css);
			continue;
		}
		if ( (css->ssl = SSL_new(css->ctx)) == NULL) {
			err("SSL_new() failed\n");
			debug("%s\n", ERR_error_string(ERR_get_error(), NULL));
			ssl_close(css);
			continue;
		}

		SSL_set_bio(css->ssl, bio, bio);

		if ( (r = SSL_accept(css->ssl)) != 1) {
			err("SSL_accept() failed: %s\n", ssl_errstr(css->ssl, r));
			debug("%s\n", ERR_error_string(ERR_get_error(), NULL));
			ssl_close(css);
			continue;
		}

		if (pthread_create(&thread, NULL, client_handler, (void *)css) < 0) 
			warn("Failed to start client thread\n");

	}
	close(sfd);
}


/*
 * Close SSL connection
 */
void
ssl_close(struct sslsocket *ss)
{

/* IE Seems to shut down SSL connections in a bad way,
 * resulting in a SIGPIPE, so we just close the socket for now
 *	if (ss != NULL && ss->ssl != NULL) {
 *		SSL_shutdown(ss->ssl);
 *		ss->ssl = NULL;
 *	}
 */
	
	if (ss != NULL) 
		close(ss->fd);
	
	if (ss != NULL && ss->ctx != NULL) {
		SSL_CTX_free(ss->ctx);
		ss->ctx = NULL;
	}
}


/*
 * Translate SSL error into a string
 */
const char *
ssl_errstr(SSL *ssl, int ret)
{
	int errno;
	errno = SSL_get_error(ssl, ret);

	switch (errno) {
		case SSL_ERROR_NONE: 
			return("No error");
			break;
		case SSL_ERROR_ZERO_RETURN:
			return("The TLS/SSL connection has been closed");
			break;
		case SSL_ERROR_WANT_READ:
		case SSL_ERROR_WANT_WRITE:
			return("The read/write operation did not complete");
			break;
		case SSL_ERROR_WANT_CONNECT:
		case SSL_ERROR_WANT_ACCEPT:
			return("The connect/accept operation did not complete");
			break;
		case SSL_ERROR_WANT_X509_LOOKUP:
			return("The operation did not complete (application callback request)");
			break;
		case SSL_ERROR_SYSCALL:
			return("Some I/O error occurred.");
			break;
		case SSL_ERROR_SSL:
			return("A (protocol) failure in the SSL library occurred");
			break;
		default:
			return("Unknown error");
	}
}


/*
 * Read data from sslsocket
 * Returns the number of bytes read.
 */
ssize_t
ssl_read(struct sslsocket *ss, void *buf, size_t len)
{
	return(SSL_read(ss->ssl, buf, len));
}


/*
 * Read n bytes of data from sslsocket
 * Returns the number of bytes read on success, -1 on error.
 */
ssize_t
ssl_readn(struct sslsocket *ss, void *buf, size_t len)
{
    ssize_t n = 0;
	char c;

	do {
		/* We do not lose much by reading a single byte at the time
         * since SSL_read simply copy a byte from the internal buffer */
		if (SSL_read(ss->ssl, &c, 1) != 1) {
			err("Failed to read: %s\n", ssl_errstr(ss->ssl, n));
			return(-1);
		}
		((char *)buf)[n++] = c;
	} while (n < len);
    return(n);
}



/*
 * Read one line or a maximum of len bytes from sslsocket
 * preserving the newline character at the end if one line was read.
 * Returns the number of bytes read on success, -1 on error.
 */
ssize_t
ssl_readline(struct sslsocket *ss, void *buf, size_t len)
{
    ssize_t n = 0;
	char c;
	int r;

	while (n < len) {
        /* We do not lose much by reading a single byte at the time
         * since SSL_read simply copy a byte from the internal buffer */
		if ( (r = SSL_read(ss->ssl, &c, 1)) != 1) {

			if (ss->ssl != NULL)
				err("Failed to read: %s\n", ssl_errstr(ss->ssl, n));
			else
				err("Failed to read from SSL socket\n");
			return(-1);
		}
		((char *)buf)[n++] = c;
		if (c == '\n')
			break;
	}

    return(n);
}



/*
 * Write n bytes of data to sslsocket
 * Return the number of bytes written on succes, -1 on failure.
 */
ssize_t
ssl_write(struct sslsocket *ss, void *buf, size_t len)
{
	return(SSL_write(ss->ssl, buf, len));
}

/*
 * Write n bytes of data to sslsocket
 * Returns the number of bytes written on succes, -1 on failure.
 */
ssize_t
ssl_writen(struct sslsocket *ss, void *buf, size_t len)
{
    ssize_t n;

	do {
		if ( (n = SSL_write(ss->ssl, buf, len)) <= 0) {
			if (ss->ssl != NULL)
				err("Failed to write: %s\n", ssl_errstr(ss->ssl, n));
			else
				err("Failed to write SSL data\n");
			return(-1);
		}
	} while (n != len);

    return(n);
}
