/*
 * x509tomem.c -- convert an X509 certificate to a block of memory, or
 *                a quote string suitable for an LDAP filter
 *
 * (c) 2000 Dr. Andreas Mueller, Beratung und Entwicklung
 *
 * $Id: x509tomem.c,v 1.2 2003/05/29 06:09:58 afm Exp $
 */
#include <stdlib.h>
#include <stdio.h>
#include <lber.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <x509tomem.h>
#include <errno.h>

struct berval	*x509_to_mem(X509 *x) {
	BIO		*bio_mem;
	struct berval	*bv = (struct berval *)malloc(sizeof(struct berval));

	/* create a memory BIO to manipulate the certificate		*/
	bio_mem = BIO_new(BIO_s_mem());

	/* write the certificate to the memory BIO			*/
	if (!i2d_X509_bio(bio_mem, x)) {
		errno = EINVAL;
		return NULL;
	}

	/* hand the memory allocated by the memory BIO over to		*/
	/* the calling process, this also transfers 			*/
	/* responsibilty for allocation/deallocation to us		*/
	BIO_set_flags(bio_mem, BIO_FLAGS_MEM_RDONLY);
	bv->bv_len = BIO_get_mem_data(bio_mem, &bv->bv_val);
	BIO_free(bio_mem);

	/* return the berval containing the certificate data		*/
	return bv;
}

char	*quote_berval(struct berval *bv) {
	char		*cp, *p;
	unsigned int	j;

	/* convert the certificate into an escape string of hex bytes	*/
	cp = (char *)malloc(1 + (3 * bv->bv_len));
	p = cp;
	for (j = 0; j < bv->bv_len; j++) {
		snprintf(p, 4, "\\%02x", (unsigned char)bv->bv_val[j]); p += 3;
	}
	return cp;
}

