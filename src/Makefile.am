##
## Makefile.am -- generates the Makefile.in
##
##  (c) 2000 Dr. Andreas Mueller, Beratung und Entwicklung
##
##  $Id: Makefile.am,v 1.9 2003/05/29 06:09:58 afm Exp $
##
VERSION = @VERSION@

SUBDIRS = module tools docs ldap patches

# distribution target
EXTRA_DIST = README TODO install-sh

update-tools:
	libtoolize --copy --force
