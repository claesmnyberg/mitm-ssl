/*
 *  Copyright (c) 2005 Claes M. Nyberg <cmn@fuzzpoint.com>
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
 */

#ifndef _CMN_CAPTURE_H
#define _CMN_CAPTURE_H

#ifndef NOPCAP

#include <pcap.h>
#include <sys/types.h>
#include <stdint.h>

/* Make sure we get the whole payload */
#define CAP_SNAPLEN        65535 
#define CAP_TIMEOUT        1000

/*
 * "Need to know" when using the capture functions
 */
struct capture {
    pcap_t *c_pcapd;       /* Pcap descriptor */
    int c_offset;          /* Link layer offset */
	int c_datalink;
	char *c_dev;
    bpf_u_int32 c_net;     /* Local network address */
    bpf_u_int32 c_mask;    /* Netmask of local network */
};

/* capture.c */
extern struct capture *cap_open(const char *, int);
extern int cap_setfilter(struct capture *, const char *);
extern long cap_iface_ipv4(const char *);

#endif /* NOPCAP */
#endif /* _CMN_CAPTURE_H */

