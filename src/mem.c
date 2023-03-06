/*
 * mem.c - Commonly used memory routines
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
 * $Id: mem.c,v 1.2 2005-02-15 21:27:33 cmn Exp $
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * Allocate n bytes of dynamic memory, calls exit on failure
 */
void *
memx(size_t n)
{
	void *pt;
	if ( (pt = malloc(n)) == NULL) {
		perror("malloc");
		exit(EXIT_FAILURE);
	}
	return(pt);
}


/*
 * Allocate n bytes of dynamic memory set to zero, 
 * calls exit on failure
 */
void *
zmemx(size_t n)
{
    void *pt;

	pt = memx(n);
	memset(pt, 0x00, n);	
    return(pt);
}


/*
 * Resize dynamic memory chunk.
 * The contents of the old buffer is copyed into
 * the new buffer up to the new size. 
 * Any undefined region is set to zero.
 * exit is called upon failure.
 */
void *
rememx(void *old, unsigned int oldlen, unsigned int newlen)
{
	void *new;

	new = zmemx(newlen);
	
	if (old != NULL) {
		memcpy(new, old, oldlen < newlen ? oldlen : newlen);
		free(old);
	}
	return(new);
}

