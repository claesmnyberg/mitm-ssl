/*
  decode.c
 
  Copyright (c) 2000 Dug Song <dugsong@monkey.org>
  
  $Id: decode.c,v 1.2 2005-07-08 13:36:59 cmn Exp $
*/


#ifndef NO_PASSWD_SCAN

#include <sys/types.h>
#include <arpa/telnet.h>
#include <rpc/rpc.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include "decode.h"

extern int decode_ftp(u_char *, int, u_char *, int);
extern int decode_smtp(u_char *, int, u_char *, int);
extern int decode_http(u_char *, int, u_char *, int);
extern int decode_poppass(u_char *, int, u_char *, int);
extern int decode_pop(u_char *, int, u_char *, int);
extern int decode_imap(u_char *, int, u_char *, int);
extern int decode_ldap(u_char *, int, u_char *, int);
extern int decode_irc(u_char *, int, u_char *, int);

static struct decode decodes[] = {
	{ "ftp",	decode_ftp },
	{ "smtp",	decode_smtp },
	{ "http",	decode_http },
	{ "pop",	decode_pop },
	{ "imap",	decode_imap },
	{ "ldap",	decode_ldap },
	{ "irc",	decode_irc },
	{ NULL }
};

struct decode *
getdecodebyname(const char *name)
{
	struct decode *dc;
	
	for (dc = decodes; dc->dc_name != NULL; dc++) {
		if (strcasecmp(dc->dc_name, name) == 0)
			return (dc);
	}
	return (NULL);
}

/* Strip telnet options, as well as suboption data. */
int
strip_telopts(u_char *buf, int len)
{
	int i, j, subopt = 0;
	char *p, *q;
	
	for (i = j = 0; i < len; i++) {
		if (buf[i] == IAC) {
			if (++i >= len) break;
			else if (buf[i] > SB)
				i++;
			else if (buf[i] == SB) {
				/* XXX - check for autologin username. */
				p = buf + i + 1;
				if ((q = bufbuf(p, len - i, "\xff", 1))
				    != NULL) {
					if ((p = bufbuf(p, q - p, "USER\x01",
							5)) != NULL) {
						p += 5;
						buf[j++] = '[';
						memcpy(buf + j, p, q - p);
						j += q - p;
						buf[j++] = ']';
						buf[j++] = '\n';
					}
				}
				subopt = 1;
			}
			else if (buf[i] == SE) {
				if (!subopt) j = 0;
				subopt = 0;
			}
		}
		else if (!subopt) {
			/* XXX - convert isolated returns to newlines. */
			if (buf[i] == '\r' && i + 1 < len &&
			    buf[i + 1] != '\n')
				buf[j++] = '\n';
			/* XXX - strip binary nulls. */
			else if (buf[i] != '\0')
				buf[j++] = buf[i];
		}
	}
	buf[j] = '\0';
	
	return (j);
}

/* Strip a string buffer down to a maximum number of lines. */
int
strip_lines(char *buf, int max_lines)
{
	char *p;
	int lines, nonascii;
	
	if (!buf) return (0);
	
	lines = nonascii = 0;
	
	for (p = buf; *p && lines < max_lines; p++) {
		if (*p == '\n') lines++;
		if (!isascii(*p)) nonascii++;
	}
	if (*p) *p = '\0';
	
	/* XXX - lame ciphertext heuristic */
	if (nonascii * 3 > p - buf)
		return (0);
	
	return (lines);
}

int
is_ascii_string(char *buf, int len)
{
	int i;
	
	for (i = 0; i < len; i++)
		if (!isascii(buf[i])) return (0);
	
	return (1);
}

u_char *
bufbuf(u_char *big, int blen, u_char *little, int llen)
{
	u_char *p;
	
         for (p = big; p <= big + blen - llen; p++) {
		 if (memcmp(p, little, llen) == 0)
			 return (p);
	 }
	 return (NULL);
}

#endif /* NO_PASSWD_SCAN */
