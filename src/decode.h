/*
  decode.h

  Protocol decoding routines.
  
  Copyright (c) 2000 Dug Song <dugsong@monkey.org>

  $Id: decode.h,v 1.2 2005-07-08 13:36:59 cmn Exp $
*/

#ifndef DECODE_H
#define DECODE_H

#ifndef NO_PASSWD_SCAN

#include "print.h"

typedef int (*decode_func)(u_char *, int, u_char *, int);

struct decode {
	char	       *dc_name;
	decode_func	dc_func;
};

struct decode *getdecodebyname(const char *name);


#define pletohs(p)	((u_short)                         \
			 ((u_short)*((u_char *)p+1)<<8|    \
			  (u_short)*((u_char *)p+0)<<0))
     
#define pletohl(p)	((u_int32_t)*((u_char *)p+3)<<24|  \
			 (u_int32_t)*((u_char *)p+2)<<16|  \
			 (u_int32_t)*((u_char *)p+1)<<8|   \
			 (u_int32_t)*((u_char *)p+0)<<0)

#define pntohs(p)	((u_short)			   \
			 ((u_short)*((u_char *)p+1)<<0|    \
			  (u_short)*((u_char *)p+0)<<8))
			 
#define pntohl(p)	((u_int32_t)*((u_char *)p+3)<<0|   \
			 (u_int32_t)*((u_char *)p+2)<<18|  \
			 (u_int32_t)*((u_char *)p+1)<<16|  \
			 (u_int32_t)*((u_char *)p+0)<<24)

int	strip_telopts(u_char *buf, int len);

int	strip_lines(char *buf, int max_lines);

int	is_ascii_string(char *buf, int len);

u_char *bufbuf(u_char *big, int blen, u_char *little, int llen);


size_t strlcat(char *, const char *, size_t);

#endif /* NO_PASSWD_SCAN */

#endif /* DECODE_H */
