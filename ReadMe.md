-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
            
              SSL Man In The Middle tool
              Copyright (C) 2005 Claes M Nyberg <cmn@signedness.org>

-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-


--[ Disclamer

  This tool is for educational purposes ONLY and is not intented to be used
  for illegal purposes. The author is not responsible for any damage which
  this tool might cause.


--[ Credits

  The decode routines used (HTTP, LDAP, FTP, IMAP, IRC, POP3 and SMTP) 
  are taken from dsniff-2.3 (and in some cases slightly modified), 
  credits to Dug Song <dugsong@monkey.org> who wrote dsniff.


--[ What is this?

  This is a tool for performing Man In The Middle attacks against SSL services.
  The tool listens on port 443 (HTTPS) by default and redirects connecting clients
  to the address specified as 'Host:' in the HTTP header (a static route can be 
  set with the -r option).
  
  The data sent from the client to the real server are scanned for passwords 
  (at least for the protocols HTTP, LDAP, FTP, IMAP, IRC, POP3 and SMTP) but 
  it can also be logged to a file (named "<timestamp> <ip>':'<port>' -> '<ip>':'<port>") 
  in the directory specified with the -c option (data sent from the server to the client 
  can also be logged, but keep in mind that more data is often sent in this direction) 
 

--[ MITM setup
  
  There are a couple of ways to re-route clients to your machine and make it 
  possible to set up an unencrypted gap between the client and the real server. 
  
  One way is to respond faster than the target DNS server to a DNS query, 
  and theirby controlling the IP address that the client will connect to 
  if a hostname is entered rather than an IP address. 
  
  This is convinient if data sent to a specific machine is of interest (such 
  as a webmail service or the machine that wireless clients enter their 
  username and passwords on to get an Internet connection), but makes it hard 
  to find out where the clients really want to go in the general case since most 
  protocols do not carry this information. It works great for HTTPS though, 
  since 'Host:' is set by most browsers.

  Another way is to send fake ARP replys and overwrite the hardware address
  of a given IP in the ARP table. By replacing the hardware address of the
  gateway with the address of your machine, you become the gateway for the
  clients receiving the fake ARP reply. 
  The nice thing with this method is that you can easily find out where
  the client really wants to go by sniffing for SYN packets to the port
  of the service that you are intercepting since nothing is changed in
  the headers except for the hardware address.

  You only have to set up IPv4 forwarding and port forward the service 
  that you are attacking to the MITM tool which will connect to the real 
  target and scan for passwords in the data transmitted by the client.
  
  On Linux:
  echo 1 > /proc/sys/net/ipv4/ip_forward
  iptables -tnat -A PREROUTING -p tcp --dport<port> -i<iface> -jDNAT --to<host>:<port>


--[ Creating the server key and certificate

  You have to feed the tool with a private key and a certificate, which
  can be created using OpenSSL:

  Create the private key
  $ openssl genrsa -des3 -out server.key 1024

  Decrypt the private key (no need to enter a password when starting the server)
  $ openssl rsa -in server.key -out server.pem

  Generate a certificate signing request
  $ openssl req -new -key server.pem -out server.csr

  Self sign the certificate (or send it to Thawte or Verisign if you like)
  $ openssl x509 -req -days 360 -in server.csr -signkey server.pem -out server.crt
  

--[ Usage

  Usage: ./sslmitm <keyfile> <certfile> [option(s)]

  Options:
    -p port,[port..]   - Port(s) to listen for connections on, default is 443
    -n                 - Do not attempt to resolve host names
    -v                 - Verbose, increase to be more verbose

  Routing Options (Mutual Exclusive) scan for 'Host:' by default)
    -a iface           - ARP-spoof in progress, sniff routing information from iface
    -r host[:port]     - Static, route connections to port on host

  Log Options:
    -c logdir          - Log data from client in directory
    -s logdir          - Log data from server in directory
    -o file            - Log passwords to file
                         Scan for HTTP,LDAP,FTP,IMAP,IRC,POP3 and SMTP

--[ Bugs/Limitations
  
  It is possible to fill up the routing information (when sniffing for routes) 
  for a client machine by sending a lot of SYN packets without establishing any 
  connection. This will block connections to the target service for that machine 
  since no routing information is ever removed from the table except when the 
  client connects and the route is requested. 
  
  A suspicious client can easily detect the MITM attack by connecting to the 
  attacked SSL service of a machine not running that service. Since the MITM 
  tool will accept the connection before connecting to the real target, 
  and close the connection when the connection is refused by the target machine; 
  the client knows that he is a victim of a MITM attack (not to mention sniffing 
  for false ARP replys if ARP poisoning is used to redirect clients ...). 

--[ TODO

  Use socket option SO_ORIGINAL_DST


Have Fun, and behave :-)
/C <cmn@fuzzpoint.com>

