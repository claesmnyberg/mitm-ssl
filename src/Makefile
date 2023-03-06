 #
 #  Copyright (c) 2005 Claes M. Nyberg <cmn@darklab.org>
 #  All rights reserved, all wrongs reversed.
 #
 #  Redistribution and use in source and binary forms, with or without
 #  modification, are permitted provided that the following conditions
 #  are met:
 #
 #  1. Redistributions of source code must retain the above copyright
 #	 notice, this list of conditions and the following disclaimer.
 #  2. Redistributions in binary form must reproduce the above copyright
 #	 notice, this list of conditions and the following disclaimer in the
 #	 documentation and/or other materials provided with the distribution.
 #  3. The name of author may not be used to endorse or promote products
 #	 derived from this software without specific prior written permission.
 #
 #  THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 #  INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 #  AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
 #  THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 #  EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 #  PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 #  OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 #  WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 #  OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 #  ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 #
 # $Id: Makefile,v 1.7 2005-07-08 13:36:59 cmn Exp $
 #

#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#
SHELL   = /bin/sh
CC	  = gcc
CFLAGS  = -s -O -Wall -I/usr/include/openssl -I/usr/kerberos/include
OBJS	= sslmitm.o net.o mem.o random.o print.o ssl.o tcproute.o capture.o \
		  str.o utils.o buf.o asn1.o base64.o decode.o decode_http.o \
		  decode_ldap.o decode_ftp.o decode_imap.o decode_irc.o decode_pop.o \
		  decode_smtp.o strlcat.o scan.o daemon.o
LIBS	= -lpthread -lpcap -lssl -lcrypto 
PROG	= mitm-ssl


# Install path
# Root dir must end with '/' to avoid trouble ..
ROOT_DIR  = /usr/local/
BIN_DIR	  = ${ROOT_DIR}/bin
#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#

none: all

new: clean all

all: ${OBJS}
	${CC} ${CFLAGS} -o ${PROG} ${OBJS} ${LIBS}

debug: clean
	@make CFLAGS='${CFLAGS} -DDEBUG' all

clean:
	rm -f ${PROG} ${OBJS} *.core

static::
	@make CFLAGS='-DSTATIC_COMPILE ${CFLAGS} -static -s' all

proxy::
	@make CFLAGS='${CFLAGS} -DNOPCAP -DNO_PASSWD_SCAN' ${OBJS}
	${CC} ${CFLAGS} -o ${PROG} ${OBJS} -lssl -lcrypto -lpthread

install:
	@strip ${PROG}
	@mkdir -p ${BIN_DIR}
	@strip ${PROG}
	@chmod 0755 ${BIN_DIR}
	@chown root:0 ${PROG}
	@chmod 0555 ${PROG}
	cp -pi ${PROG} ${BIN_DIR}/${PROG}

uninstall:
	rm -f ${BIN_DIR}/${PROG}
	rmdir ${BIN_DIR}
	rmdir ${ROOT_DIR}

