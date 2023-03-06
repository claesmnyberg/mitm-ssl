/*
  asn1.h

  ASN.1 routines.
 
  Copyright (c) 2000 Dug Song <dugsong@monkey.org>
  
*/

#ifndef ASN1_H
#define ASN1_H

#define ASN1_INTEGER	2
#define ASN1_STRING	4
#define ASN1_SEQUENCE	16

int	asn1_type(buf_t buf);
int	asn1_len(buf_t buf);

#endif /* ASN1_H */

