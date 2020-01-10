/*
 * asn1tostr.c -- convert an ASN1_INTEGER to a string
 *
 * $Id: asn1tostr.c,v 1.2 2002/10/10 08:36:05 afm Exp $
 *
 * (c) 2000 Dr. Andreas Mueller, Beratung und Entwicklung
 */
#include <stdlib.h>
#include <stdio.h>
#include <openssl/x509.h>
#include <openssl/bio.h>
#include <asn1tostr.h>

/*
 * convert an ASN1_INTEGER into a suitable text representation
 */
char	*asn1_to_string(ASN1_INTEGER *i) {
	char	*cp;
	int	n;
	BIO	*bio;

	if (NULL == (bio = BIO_new(BIO_s_mem())))
		return NULL;
	i2a_ASN1_INTEGER(bio, i);
	n = BIO_pending(bio);
	cp = (char *)malloc(n + 1);
	n = BIO_read(bio, cp, n);
	cp[n] = '\0';
	BIO_free(bio);
	return cp;
}
