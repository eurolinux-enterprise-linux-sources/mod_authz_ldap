/*
 * x509tomem.h -- convert an X509 certificate to a block of memory, or
 *                a quote string suitable for an LDAP filter
 *
 * (c) 2000 Dr. Andreas Mueller, Beratung und Entwicklung
 *
 * $Id: x509tomem.h,v 1.1 2001/08/25 15:54:06 afm Exp $
 */
#ifndef _X509TOMEM_H
#define _X509TOMEM_H

#include <lber.h>
#include <x509tomem.h>

extern struct berval	*x509_to_mem(X509 *x);
extern char		*quote_berval(struct berval *);

#endif /* _X509TOMEM_H */
