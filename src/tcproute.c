/*
 *  Copyright (c) 2005 Claes M. Nyberg <cmn@darklab.org>
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
 * $Id: tcproute.c,v 1.5 2005-07-08 13:36:59 cmn Exp $
 */

#ifndef NOPCAP

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <pthread.h>
#include <netinet/in.h>
#include <sys/time.h>
#include "capture.h"
#include "iraw.h"
#include "tcproute.h"
#include "sslmitm.h"

/* Maximum number of active connections from a single host.
 * When this value is reached, things get broken ...  */
#define MAX_CONNECTIONS		1024

/* table lock */
static pthread_mutex_t rtable_lock;

struct rtable {
	u_int saddr;
	struct conninfo *cinfo;
	struct rtable *left;
	struct rtable *right;
};

/* Local variables */
static struct rtable *root = NULL;
static size_t routes = 0;

/* Local routines */
static struct rtable *rtable_update(struct rtable *, u_int, struct conninfo *);
static struct rtable *rtable_getroute(struct rtable *, u_int, u_short, struct conninfo *);
static struct rtable *rtable_addrtable(struct rtable *, struct rtable *);
		
/*
 * Add route for client
 */
static void
tcproute_add(u_int saddr, u_short sport, u_int daddr, u_short dport)
{
	struct conninfo cinfo;
	
	pthread_mutex_lock(&rtable_lock);
	memset(&cinfo, 0x00, sizeof(cinfo));
	cinfo.sport = sport;
	cinfo.daddr = daddr;
	cinfo.dport = dport;
	cinfo.stamp = time(NULL);
	
	root = rtable_update(root, saddr, &cinfo);
	verbose(3, "%d route%s in table\n", routes, routes > 1 ? "s" : "");
	pthread_mutex_unlock(&rtable_lock);
}

/*
 * Get route for client, returns 0 on sucess, -1 on error.
 */
int
tcproute_get(u_int saddr, u_short sport, u_int *daddr, u_short *dport)
{
	struct conninfo cinfo;

	pthread_mutex_lock(&rtable_lock);
	memset(&cinfo, 0x0, sizeof(cinfo));
	root = rtable_getroute(root, saddr, sport, &cinfo);
	*daddr = cinfo.daddr;
	*dport = cinfo.dport;
	pthread_mutex_unlock(&rtable_lock);
	
	if (cinfo.daddr == 0)
		return(-1);

	return(0);
}


/*
 * Update/Add routing for source host 
 */ 
static struct rtable *
rtable_update(struct rtable *root, u_int saddr, struct conninfo *cinfo)
{
	if (root == NULL) {
		root = zmemx(sizeof(struct rtable));
		root->saddr = saddr;
		root->cinfo = zmemx(sizeof(struct conninfo));
		memcpy(root->cinfo, cinfo, sizeof(struct conninfo));
		root->cinfo->next = NULL;
		routes++;
		return(root);
	}

	else if (root->saddr > saddr)
		root->left = rtable_update(root->left, saddr, cinfo);
	
	else if (root->saddr < saddr)
		root->right = rtable_update(root->right, saddr, cinfo);

	/* Append route information */
	else if (root->saddr == saddr) {
		struct conninfo *end;	
		size_t n;

		/* Find end (overwrite any existing source port entry) */
		for (n = 0, end = root->cinfo; end != NULL; end = end->next, n++) {
		
			/* Reused source port (first entry) */
			if (end->sport == cinfo->sport) {
				end->daddr = cinfo->daddr;
				end->dport = cinfo->dport;
				end->stamp = cinfo->stamp;
				return(root);
			}
			
			/* Reused source port */
			if (end->next != NULL && end->next->sport == cinfo->sport) {
				end->next->daddr = cinfo->daddr;
				end->next->dport = cinfo->dport;
				return(root);
			}

			/* Last entry */
			if (end->next == NULL) {
				break;
			}
		}

		if (end == NULL) {
			err("FATAL: List end is NULL\n");
			return(root);
		}
	
		/* Apped target */
		end->next = zmemx(sizeof(struct conninfo));
		memcpy(end->next, cinfo, sizeof(struct conninfo));
		end->next->next = NULL;
		routes++;
		
		/* Maximum number of connections reached, remove first 
		 * (this is not very likely to happen though) */
		if (n >= MAX_CONNECTIONS) {
			struct conninfo *tmp;
				
			fprintf(stderr, "** Warning: Maximum number of connections reached\n");
			tmp = root->cinfo->next;
			free(root->cinfo);
			root->cinfo = tmp;
			routes--;
		}
	}

	return(root);	
}


/*
 * Get route for given source address/port and delete it from table
 */
static struct rtable *
rtable_getroute(struct rtable *root, u_int saddr, 
		u_short sport, struct conninfo *save)
{
	/* Entry not found */
	if (root == NULL) 
		return(NULL);

	else if (root->saddr > saddr)
		root->left = rtable_getroute(root->left, saddr, sport, save);

	else if (root->saddr < saddr)
		root->right = rtable_getroute(root->right, saddr, sport, save);

	else if (root->saddr == saddr) {
		struct conninfo *pt;
		
		/* Find source port */
		for (pt = root->cinfo; pt != NULL; pt = pt->next) {

			/* First entry in list */
			if (pt->sport == sport)
				break;

			if (pt->next && pt->next->sport == sport)
				break;
		}

		if (pt == NULL) {
			/* fprintf(stderr, "** Warning: Entry not found\n"); */
			return(root);
		}

		/* Copy route information */
		memcpy(save, pt->sport == sport ? pt : pt->next, sizeof(struct conninfo));
		save->next = NULL;

		/* Last route, delete entry */
		if (pt == root->cinfo && pt->next == NULL) {
			struct rtable *tmp = root;

			if ((root->right == NULL) && (root->left != NULL))
				root = root->left;
			else if ((root->right != NULL) && (root->left == NULL))
				root = root->right;
			else if ((root->right != NULL) && (root->left != NULL))
				root = rtable_addrtable(root->right, root->left);
			else
				root = NULL;

			free(pt);
			free(tmp);
		}

		/* Unlink route from list */
		else if (pt->sport == sport) {
			root->cinfo = pt->next;
			free(pt);
		}
		else if (pt->next && pt->next->sport == sport) {
			struct conninfo *tmp = pt->next;
			pt->next = pt->next->next;
			free(tmp);	
		}
		else {
			printf("FUCK, this should never happen\n");
		}
		routes--;
	}
	
	return(root);	
}


/*
 * Add subtree to root (when deleting)
 */
static struct rtable *
rtable_addrtable(struct rtable *root, struct rtable *sub)
{
	/* Nothing to do */
	if (sub == NULL)
		return(root);

	/* New tree, replace with sub */
	else if (root == NULL)
		return(sub);

	else if (root->saddr == sub->saddr)
		err("Fatal: Entry already exist in tree when deleting\n");
	
	/* Smaller, go left */
	else if (root->saddr > sub->saddr)
		root->left = rtable_addrtable(root->left, sub);

	/* Bigger, go right */
	else if (root->saddr < sub->saddr)
		root->right = rtable_addrtable(root->right, sub);

	return(root);
}


/*
 * Thread entry, kick the sniffer
 */
void *
destination_tracker(void *opts)
{
	struct options *opt;
	
	/* Init table lock */
	pthread_mutex_init(&rtable_lock, NULL);
	
	opt = (struct options *)opts;
	if (route_sniff(opt->iface, opt->ports, opt->resolve) < 0)
		exit(EXIT_FAILURE);
	return(NULL);
}

/*
 * Sniff SYN packets to given port and keep
 * track of the source port and destination address.
 */
int
route_sniff(const char *iface, unsigned short *ports, int resolve)
{
	#define STR "tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack == 0 and "
	long ip;
	char buf[8192];
	char *filter;
	struct capture *cap;
	size_t i;
	size_t w;
	size_t len;
	
	/* Count ports */
	for (i=0; ports[i] != 0; i++)
		;
	
	/* Open device */
	if ( (cap = cap_open(iface, 1)) == NULL) 
		return(-1);
	
	if ( (long)(ip = cap_iface_ipv4(iface)) == -1) {
		err("Failed to get IPv4 address of interface '%s'\n", iface);
		return(-1);
	}
	
	/* Build filter */
	len = sizeof(STR)+(i*24)+128;
	filter = zmemx(len);
	w = snprintf(filter, len, "%s", STR);
	for (i=0; ports[i] != 0; i++)
		w += snprintf(&filter[w], len-w, "tcp dst port %u %s ", 
			ntohs(ports[i]), ports[i+1] != 0 ? "or" : "");
	
	/* Ignore address of sniff interface */
	if (cap->c_net) {
		w += snprintf(&filter[w], len-w-1, 
			"and not host %s", net_ntoa_ip(ip));
	}
		
	verbose(2, "Packet filter: %s\n", filter);
	if (cap_setfilter(cap, filter) < 0) 
		return(-1);
	free(filter);
	
	/* Sniff and add routing info to table */
	for (;;) {
		struct pcap_pkthdr ph;
		IPv4_hdr *iph;
		TCP_hdr *tph;
		const u_char *pt;

		pt = pcap_next(cap->c_pcapd, &ph);	
		
		iph = (IPv4_hdr *)(pt + cap->c_offset);
		tph = (TCP_hdr *)(pt + cap->c_offset + (iph->ip_hlen)*4);
	
		i = snprintf(buf, sizeof(buf), "Adding route %s -> ", 
			net_sockstr_ip(iph->ip_sadd, tph->tcp_sprt, resolve));
		verbose(2, "%s%s\n", buf, net_sockstr_ip(iph->ip_dadd, tph->tcp_dprt, resolve));
		tcproute_add(iph->ip_sadd, tph->tcp_sprt, iph->ip_dadd, tph->tcp_dprt);
	}
	return(0);		
}

#endif /* NOPCAP */
