##
## Makefile.am -- generates the Makefile.in
##
##  (c) 2000 Dr. Andreas Mueller, Beratung und Entwicklung
##
##  $Id: Makefile.am,v 1.3 2003/05/29 06:09:58 afm Exp $
##
VERSION = @VERSION@

#   additional user defines, includes and libraries
DEF= @DEFS@
INC = @CPPFLAGS@
LIB = @LIBS@
AM_CFLAGS = @CFLAGS@

noinst_LIBRARIES = libauthz.a
noinst_HEADERS = asn1tostr.h x509tomem.h

libauthz_a_SOURCES = asn1tostr.c x509tomem.c

bin_PROGRAMS = cert2ldap certfind

# the cert2ldap tool
cert2ldap_SOURCES = cert2ldap.c
cert2ldap_LDADD = libauthz.a

# the certfind tool, checks for a certificate in the directory
certfind_SOURCES = certfind.c
certfind_LDADD = libauthz.a

# distribution target
EXTRA_DIST = 								\
	adduser addgroup addcertmap

