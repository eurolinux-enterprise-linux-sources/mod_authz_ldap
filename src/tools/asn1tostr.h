/*
 * asn1tostr.h -- convert an ASN1_INTEGER to a string
 *
 * $Id: asn1tostr.h,v 1.1 2001/08/25 15:54:06 afm Exp $
 *
 * (c) 2000 Dr. Andreas Mueller, Beratung und Entwicklung
 */
#ifndef _ASN1TOSTR_H
#define _ASN1TOSTR_H

#include <stdlib.h>
#include <stdio.h>
#include <openssl/x509.h>

/*
 * convert an ASN1_INTEGER into a suitable text representation
 */
extern char	*asn1_to_string(ASN1_INTEGER *i);

#endif /* _ASN1TOSTR_H */
