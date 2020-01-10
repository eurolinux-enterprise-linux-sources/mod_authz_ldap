##
## Makefile.am -- generates the Makefile.in
##
##  (c) 2000 Dr. Andreas Mueller, Beratung und Entwicklung
##
##  $Id: Makefile.am,v 1.8 2002/10/11 07:56:26 afm Exp $
##
VERSION = @VERSION@

man_MANS = cert2ldap.1 certfind.1

# distribution target
EXTRA_DIST = configuration.html download.html.in howto.html index.html	\
	installation.html reference.html ldap.html			\
	configuration.jpg download.jpg howto.jpg installation.jpg	\
	introduction.jpg ldap.jpg mod_authz_ldap.jpg reference.jpg	\
	authzldap.txt mod_authz_ldap.HOWTO				\
	README webactivate.in $(man_MANS) .message

all:	download.html

download.html:	download.html.in Makefile.am
	VERSION2=`echo $(VERSION) | sed -e 's/^.*\.//'`;		\
	sed 	-e 's/VeRsIoN/'"$${VERSION2}"'/g'			\
		-e 's/VeRsIo1/'"`expr $${VERSION2} - 1`"'/g'		\
		-e 's/VeRsIo2/'"`expr $${VERSION2} - 2`"'/g'		\
		-e 's/VeRsIo3/'"`expr $${VERSION2} - 3`"'/g'		\
		-e 's/VeRsIo4/'"`expr $${VERSION2} - 4`"'/g'		\
		-e 's/VeRsIo5/'"`expr $${VERSION2} - 5`"'/g'		\
		-e 's/VeRsIo6/'"`expr $${VERSION2} - 6`"'/g'		\
		-e 's/VeRsIo7/'"`expr $${VERSION2} - 7`"'/g'		\
		download.html.in > download.html
