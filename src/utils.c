/*
 *  File: utils.c
 *  Author: Claes M. Nyberg <md0claes@mdstud.chalmers.se>
 *  Description: Common used routines.
 *
 *  Copyright (c) 2003 Claes M. Nyberg <md0claes@mdstud.chalmers.se>
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
 * $Id: utils.c,v 1.1.1.1 2005-02-11 23:54:45 cmn Exp $
 */

#include <stdio.h>
#include <time.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/time.h>
#include "utils.h"



/*
 * Write N bytes to a file descriptor
 */
ssize_t
writen(int fd, void *buf, size_t n)
{
	size_t tot = 0;
	ssize_t w;

	do {
		if ( (w = write(fd, (void *)((u_char *)buf + tot), n - tot)) <= 0)
			return(w);
		tot += w;
	} while (tot < n);
	
	return(tot);
}

/*
 * Read N bytes from a file descriptor
 */
ssize_t
readn(int fd, void *buf, size_t n)
{
	size_t tot = 0;
	ssize_t r;
	
	do {
		if ( (r = read(fd, (void *)((u_char *)buf + tot), n - tot)) <= 0)
			return(r);
		tot += r;
	} while (tot < n);
	
	return(tot);	
}

/*
 * Returns 1 if file descriptor is ready for writing,
 * 0 otherwise.
 */
int
ready_write(int fd)
{
    fd_set writeset;
    struct timeval tv;

    memset(&tv, 0x00, sizeof(tv));
    FD_ZERO(&writeset);
    FD_SET(fd, &writeset);

    if (select(fd+1, NULL, &writeset, NULL, &tv) > 0)
        return(1);

    return(0);
}

