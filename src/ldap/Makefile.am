##
## Makefile.am -- generates the Makefile.in
##
##  (c) 2000 Dr. Andreas Mueller, Beratung und Entwicklung
##
##  $Id: Makefile.am,v 1.4 2003/11/16 16:42:57 afm Exp $
##
VERSION = @VERSION@

# distribution target
EXTRA_DIST = authzldap.slapd.conf authzldap.schema README 	\
	slapd.conf.in authzldap.ldif

BUILT_SOURCES = slapd.conf

# the following sed command seems to require GNU sed, but as it is only
# needed for development, and serious open source developers will almost
# certainly have GNU sed, this is not an issue
slapd.conf:	slapd.conf.in
	AUTHZLDAPHOME=`(cd ..;pwd)`;					\
	sed -e s:AUTHZLDAPHOME:$${AUTHZLDAPHOME}: slapd.conf.in > slapd.conf

ldap:	slapd.conf database
	-@if [ -r ldbm/slapd.pid ]; then kill `cat ldbm/slapd.pid`; fi
	/usr/local/libexec/slapd -h ldap://localhost:33389 -f slapd.conf

LDBMFILES = ldbm/dn2id.bdb ldbm/id2entry.bdb ldbm/nextid.bdb 		\
	ldbm/objectClass.bdb __db.001 __db.002 __db.003 __db.004	\
	__db.005 log.0000000001

database:	ldbm/nextid.dbb

ldbm/nextid.dbb: authzldap.ldif slapd.conf
	-@if [ -r ldbm/slapd.pid ]; then kill `cat ldbm/slapd.pid`; fi
	rm -f $(LDBMFILES)
	slapadd -v -f slapd.conf -l authzldap.ldif
