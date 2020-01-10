##
## Makefile.am -- generates the Makefile.in
##
##  (c) 2000 Dr. Andreas Mueller, Beratung und Entwicklung
##
##  $Id: Makefile.am,v 1.9 2003/11/18 10:01:31 afm Exp $
##
VERSION = @VERSION@

# the used tools
APXS = @APXS@
APACHECTL = @APACHECTL@
SHAREDFLAG = @SHAREDFLAG@

# additional user defines, includes and libraries
DEF= @DEFS@
INC = @CPPFLAGS@
LIB = @LIBS@
AM_CFLAGS = @CFLAGS@
LIBGCCFLAGS = @LIBGCCFLAGS@

# consider the module a libtool library
lib_LTLIBRARIES = mod_authz_ldap.la

MODULESOURCES = auth.c authz.c certmap.c modconf.c utilities.c age.c	\
	filterexpand.c mod_authz_ldap.c
MODULEHEADERS = mod_authz_ldap.h
noinst_HEADERS = $(MODULEHEADERS)

mod_authz_ldap_la_SOURCES = $(MODULESOURCES)
mod_authz_ldap_la_LDFLAGS = -module `${APXS} -q LDFLAGS_SHLIB`
mod_authz_ldap_la_CPPFLAGS = -I`${APXS} -q INCLUDEDIR`
mod_authz_ldap_la_CFLAGS = `${APXS} -q CFLAGS` `${APXS} -q CFLAGS_SHLIB`
CC = `${APXS} -q CC`

#   install the DSO file into the Apache installation
#   and activate it in the Apache configuration
install-exec-local: all
	$(APXS) -i -a -n 'authz_ldap' .libs/mod_authz_ldap.so

# distribution target
EXTRA_DIST = README

