/*
 * print.c - Commonly used print routines
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
 * $Id: print.c,v 1.2 2005-02-13 21:09:46 cmn Exp $
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include "sslmitm.h"

/* Local routines */
static void err_v(const char *, va_list);
static void warn_v(const char *, va_list);

extern struct options opt;

/*
 * Only print if verbose level is high enough
 */
void
verbose(unsigned int level, char *fmt, ...)
{
    va_list ap;

    if (opt.verbose < level)
        return;

	printf("%s ", str_time(time(NULL), NULL));
	if (level)
		printf("[verbose %d] ", level);
    va_start(ap, fmt);
    vfprintf(stdout, fmt, ap);
    va_end(ap);
	fflush(stdout);
}

/*
 * Print a warning message like perror.
 */
void
warn_errno(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    warn_v(fmt, ap);
    va_end(ap);
	fprintf(stderr, ": %s\n", strerror(errno));
}

/*
 * Print debug message
 */
void
debug(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	fprintf(stderr, "(debug) ");
	vfprintf(stderr, fmt, ap);
	va_end(ap);
}

/*
 * Print a warning message like perror
 * and call exit.
 */
void
warn_errnox(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    warn_v(fmt, ap);
    va_end(ap);
    fprintf(stderr, ": %s\n", strerror(errno));
	exit(EXIT_FAILURE);
}


/*
 * Print error message like perror.
 */
void
err_errno(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    err_v(fmt, ap);
    va_end(ap);
	fprintf(stderr, ": %s\n", strerror(errno));
}

/*
 * Print error message like perror
 * and call exit.
 */
void
err_errnox(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    err_v(fmt, ap);
    va_end(ap);
    fprintf(stderr, ": %s\n", strerror(errno));
	exit(EXIT_FAILURE);
}


/*
 * Print warning message
 */
void
warn(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    warn_v(fmt, ap);
    va_end(ap);
}

/*
 * Print warning message and exit
 */
void
warnx(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    warn_v(fmt, ap);
    va_end(ap);
	exit(EXIT_FAILURE);
}

/*
 * Print error message
 */
void
err(const char *fmt, ...)
{
    va_list ap;

	va_start(ap, fmt);
    err_v(fmt, ap);
	va_end(ap);
}


/*
 * Print error message and exit
 */
void
errx(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    err_v(fmt, ap);
    va_end(ap);
	exit(EXIT_FAILURE);
}


/*
 * Print warning
 */
static void
warn_v(const char *fmt, va_list ap)
{
    fprintf(stderr, "** Warning: ");
    vfprintf(stderr, fmt, ap);
}


/*
 * Print error message
 */
static void
err_v(const char *fmt, va_list ap)
{
    fprintf(stderr, "** Error: ");
    vfprintf(stderr, fmt, ap);
}

