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
#ifndef NOPCAP

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <pcap.h>
#include "capture.h"
#include "print.h"
#include "mem.h"


/*
 * Opens a device/file to capture/read packets from (NULL for lookup).
 * Returns a NULL pointer on error and a pointer
 * to a struct capture on success.
 * Arguments:
 *  dev     - Device to open
 *  promisc - Should be one for open in promisc mode, 0 otherwise
 */
struct capture *
cap_open(const char *dev, int promisc)
{
    char ebuf[PCAP_ERRBUF_SIZE];   /* Pcap error string */
	struct capture cap;
	struct capture *pt;
    struct stat sb;


	/* Open file */
	if ( (stat(dev, &sb) == 0) && S_ISREG(sb.st_mode)) {
		
		if (sb.st_size == 0) {
			err("Target file '%s' is empty\n", dev);
			return(NULL);
		}
		
		if ( (cap.c_pcapd = pcap_open_offline(dev, ebuf)) == NULL) {
			err("%s\n", err);
			return(NULL);
		}
	}
	/* Open device */
	else {

		/* Let pcap pick an interface to listen on */
		if (dev == NULL) {
			if ( (dev = pcap_lookupdev(ebuf)) == NULL) {
				err("%s\n", err);
				return(NULL);
			}
		}

    	/* Init pcap */
    	if (pcap_lookupnet(dev, &cap.c_net, 
				&cap.c_mask, ebuf) != 0) 
        	warn("%s\n", ebuf);

    	/* Open the interface */
    	if ( (cap.c_pcapd = pcap_open_live(dev, 
        	    CAP_SNAPLEN, promisc, CAP_TIMEOUT, ebuf)) == NULL) {
        	err("%s\n", ebuf);
        	return(NULL);
    	}
	}

    /* Set linklayer offset 
	 * Offsets gatheret from various places (Ethereal, ipfm, ..) */
    switch( (cap.c_datalink = pcap_datalink(cap.c_pcapd))) {

#ifdef DLT_EN10MB
        case DLT_EN10MB:
            cap.c_offset = 14;
			verbose(1, "Resolved datalink to Ethernet\n");
            break;
#endif
#ifdef DLT_ARCNET
		case DLT_ARCNET:
			cap.c_offset = 6;
			verbose(1, "Resolved datalink to ARCNET\n");
			break;
#endif
#ifdef DLT_PPP_ETHER
		case DLT_PPP_ETHER:
			cap.c_offset = 8;
			verbose(1, "Resolved datalink to PPPoE\n");
			break;
#endif
#ifdef DLT_NULL
        case DLT_NULL:
            cap.c_offset = 4;
			verbose(1, "Resolved datalink to BSD "
				"loopback encapsulation\n");
            break;
#endif
#ifdef DLT_LOOP
		case DLT_LOOP:
            cap.c_offset = 4;
			verbose(1, "Resolved datalink to OpenBSD "
				"loopback encapsulation\n");
            break;
#endif
#ifdef DLT_PPP
		case DLT_PPP:
            cap.c_offset = 4;
			verbose(1, "Resolved datalink to PPP\n");
            break;
#endif
#ifdef DLT_C_HDLC
		case DLT_C_HDLC:		/* BSD/OS Cisco HDLC */
            cap.c_offset = 4;
			verbose(1, "Resolved datalink to Cisco PPP with HDLC framing\n");
            break;
#endif
#ifdef DLT_PPP_SERIAL
		case DLT_PPP_SERIAL:	/* NetBSD sync/async serial PPP */
            cap.c_offset = 4;
			verbose(1, "Resolved datalink to PPP in HDLC-like framing\n");
            break;
#endif
#ifdef DLT_RAW
        case DLT_RAW:
            cap.c_offset = 0;
			verbose(1, "Resolved datalink to raw IP\n");
            break;
#endif
#ifdef DLT_SLIP
        case DLT_SLIP:
            cap.c_offset = 16;
			verbose(1, "Resolved datalink to SLIP\n");
            break;
#endif
#ifdef DLT_SLIP_BSDOS
        case DLT_SLIP_BSDOS:
			cap.c_offset = 24;
			verbose(1, "Resolved datalink to DLT_SLIP_BSDOS\n");
			break;
#endif
#ifdef DLT_PPP_BSDOS
        case DLT_PPP_BSDOS:
            cap.c_offset = 24;
			verbose(1, "Resolved datalink to DLT_PPP_BSDOS\n");
            break;
#endif
#ifdef DLT_ATM_RFC1483
        case DLT_ATM_RFC1483:
            cap.c_offset = 8;
			verbose(1, "Resolved datalink to RFC 1483 "
				"LLC/SNAP-encapsulated ATM\n");
            break;
#endif
#ifdef DLT_IEEE802
        case DLT_IEEE802:
            cap.c_offset = 22;
			verbose(1, "Resolved datalink to IEEE 802.5 Token Ring\n");
            break;
#endif
#ifdef DLT_IEEE802_11
		case DLT_IEEE802_11:
			cap.c_offset = 32;
			verbose(1, "Resolved datalink to IEEE 802.11 wireless LAN\n");
			break;
#endif
#ifdef DLT_ATM_CLIP
		/* Linux ATM defines this */
		case DLT_ATM_CLIP:   
			cap.c_offset = 8;
			verbose(1, "Resolved datalink to DLT_ATM_CLIP\n");
			break;
#endif 
#ifdef DLT_PRISM_HEADER
		case DLT_PRISM_HEADER:
		    cap.c_offset = 144+30;
			verbose(1, "Resolved datalink to Prism monitor mode\n");
		    break;
#endif 
#ifdef DLT_LINUX_SLL
        /* fake header for Linux cooked socket */
        case DLT_LINUX_SLL:  
            cap.c_offset = 16;
			verbose(1, "Resolved datalink to Linux "
				"\"cooked\" capture encapsulation\n");
            break;
#endif
#ifdef DLT_LTALK
		case DLT_LTALK:
			cap.c_offset = 0;
			verbose(1, "Resolved datalink to Apple LocalTalk\n");
			break;
#endif
#ifdef DLT_PFLOG
		case DLT_PFLOG:
			cap.c_offset = 50;
			verbose(1, "Resolved datalink to OpenBSD pflog\n");
			break; 
#endif
#ifdef DLT_SUNATM
		case DLT_SUNATM:
			cap.c_offset = 4;
			verbose(1, "Resolved datalink to SunATM device\n");
			break;
#endif
#if 0
		/* Unknown offsets */
		case DLT_IP_OVER_FC: /* RFC  2625  IP-over-Fibre Channel */
		case DLT_FDDI: /* FDDI */
		case DLT_FRELAY: /* Frame Relay */
		case DLT_IEEE802_11_RADIO:
		case DLT_ARCNET_LINUX:
		case DLT_LINUX_IRDA:
#endif

		default:
            err("Unknown datalink type (%d) received for iface %s\n", 
				pcap_datalink(cap.c_pcapd), dev);
            return(NULL);
    }
	cap.c_dev = (char *)dev;	
	
	verbose(0, "Opened device %s\n", cap.c_dev);
	pt = zmemx(sizeof(struct capture));
    memcpy(pt, &cap, sizeof(struct capture));
	return(pt);
}


/*
 * Set capture filter.
 * Returns -1 on error and 0 on success.
 */
int
cap_setfilter(struct capture *cap, const char *filter)
{
    struct bpf_program fp; /* Holds compiled program */

    /* Compile filter string into a program and optimize the code */
    if (pcap_compile(cap->c_pcapd, &fp, (char *)filter, 1, cap->c_net) == -1) {
        err("Filter: %s\n", pcap_geterr(cap->c_pcapd));
        return(-1);
    }

    /* Set filter */
    if (pcap_setfilter(cap->c_pcapd, &fp) == -1) {
        err("Failed to set pcap filter\n");
        return(-1);
    }

	pcap_freecode(&fp);
    return(0);
}


/*
 * Returns the IPv4 adresses of the given interface, 
 * -1 on error or if no address is set.
 */
long
cap_iface_ipv4(const char *iface)
{
	static long ip = -1;
	u_char perr[PCAP_ERRBUF_SIZE];
	pcap_if_t *alldevs;
	pcap_if_t *curif;
	pcap_addr_t *addr;

	if (iface == NULL) {
		err("cap_iface_ipv4: Interface is NULL\n");
		return(-1);
	}
	
	if (pcap_findalldevs(&alldevs, perr) == -1) {
		err("pcap_findalldevs: %s\n", perr);
		return(-1);
	}

	curif = alldevs;
	while (curif != NULL) {
		if (!strcmp(curif->name, iface)) 
			break;
		curif = curif->next;
	}

	if (curif == NULL) {
		err("cap_iface_ipv4: Interface not found\n");
		return(-1);
	}

	/* Find addresses */
	for (addr = curif->addresses; addr != NULL; addr = addr->next) {
		if (addr->addr->sa_family == AF_INET) {
			ip = ((struct sockaddr_in *)addr->addr)->sin_addr.s_addr;
			break;
		}
	}
	return(ip);
}

#endif /* NOPCAP */
