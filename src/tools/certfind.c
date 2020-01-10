/*
 * certfind.c -- search for a certificate in the directory
 *
 * $Id: certfind.c,v 1.3 2004/03/30 23:35:51 afm Exp $
 *
 * (c) 2000 Dr. Andreas Mueller, Beratung und Entwicklung
 */
#ifdef HAVE_CONFIG_H
#include <authz.h>
#endif /* HAVE_CONFIG_H */
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <lber.h>
#include <ldap.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <x509tomem.h>
#include <asn1tostr.h>
#include <unistd.h>

#ifndef HAVE_BER_FREE
#define	ber_free	free
#endif
#ifndef HAVE_LDAP_MSGFREE
#define ldap_msgfree	free
#endif
#ifndef HAVE_LDAP_MEMFREE
#define ldap_memfree	free
#endif

int	verbose = 0;
int	debug = 0;
char	*binddn = NULL;
char	*bindpw = NULL;
char	*ldapserver = "localhost";
char	*basedn = NULL;
int	ldapport = LDAP_PORT;
char	*infile = NULL;

extern int	optind;
extern char	*optarg;

static void	escape_parentheses(char *org, char *new) {
	char	*p = org, *q = new;
	while (*p) {
		if ((*p == '(') || (*q == ')')) {
			*q++ = '\\';
			*q++ = *p++;
		}
	}
	*q = '\0';
}

int	main(int argc, char *argv[]) {
	int		c;
	BIO		*in = NULL, *bio_err = NULL, *bio_out = NULL;
	X509		*x = NULL;
	LDAP		*ldap;
	LDAPMessage	*results, *e;
	char		*cp, *dn, *filter, *sn;
	char		issuer[1024], subject[1024];
	char		escaped_issuer[1024], escaped_subject[1024];
	int		use_subject = 0, use_serial = 0;
	struct berval	*bv;

	/* parse the command line					*/
	while ((c = getopt(argc, argv, "db:w:h:p:sn")) != EOF)
		switch (c) {
		case 'd':
			debug++;
			break;
		case 'b':
			binddn = optarg;
			if (debug)
				printf("%s:%d: bind dn set to '%s'\n",
					__FILE__, __LINE__, binddn);
			break;
		case 'w':
			bindpw = optarg;
			if (debug)
				printf("%s:%d: bind password set to '%s'\n",
					__FILE__, __LINE__,
					(debug > 1) ? bindpw : "******");
			break;
		case 'h':
			ldapserver = optarg;
			if (debug)
				printf("%s:%d: ldap server set to '%s'\n",
					__FILE__, __LINE__, ldapserver);
			break;
		case 'p':
			ldapport = atoi(optarg);
			if ((ldapport <= 0) || (ldapport > 65535)) {
				ldapport = LDAP_PORT;
				fprintf(stderr, "%s:%d: illegal port '%s', "
					"set to %d\n", __FILE__, __LINE__,
					optarg, ldapport);
			}
			if (debug) 
				printf("%s:%d: ldap port set to %d\n",
					__FILE__, __LINE__, ldapport);
			break;
		case 's':
			use_subject = 1;
			if (debug)
				printf("%s:%d: searching for subject and "
					"issuer instead of certificate",
					__FILE__, __LINE__);
			break;
		case 'n':
			use_serial = 1;
			if (debug)
				printf("%s:%d: searching for serial and "
					"issuer instead of certificate",
					__FILE__, __LINE__);
			break;
		}

	/* connect to the LDAP server and bind				*/
	if (NULL == (ldap = ldap_init(ldapserver, ldapport))) {
		fprintf(stderr, "%s:%d: cannot connect to LDAP server: "
			"%s (%d)\n", __FILE__, __LINE__, ldapserver, ldapport);
		exit(EXIT_FAILURE);
	}
	if (debug)
		printf("%s:%d: connected to %s:%d\n", __FILE__, __LINE__,
			ldapserver, ldapport);

	/* try to bind, this is necessary to acquire the necessary	*/
	/* privileges to perform the update				*/
	if (ldap_simple_bind_s(ldap, binddn, bindpw) != LDAP_SUCCESS) {
		ldap_perror(ldap, "cannot bind");
		exit(EXIT_FAILURE);
	}
	if (debug)
		printf("%s:%d: bind to ldap server succeeded\n", __FILE__,
			__LINE__);

	/* if there is another argument, it's a filename for a 		*/
	/* certificate							*/
	if (optind > argc) {
		infile = optarg;
		if (debug)
			printf("%s:%d: reading certificate form '%s'\n",
				__FILE__, __LINE__, infile);
	} else {
		if (debug)
			printf("%s:%d: reading certificate from stdin\n",
				__FILE__, __LINE__);
	}

	/* convert standard error to a bio for openssl to write the 	*/
	/* its error messages to					*/
	bio_err = BIO_new_fp(stderr, BIO_NOCLOSE);
	bio_out = BIO_new_fp(stdout, BIO_NOCLOSE);

	/* create a BIO structure					*/
	in = BIO_new(BIO_s_file());
	if (!in) {
		ERR_print_errors(bio_err);
		exit(EXIT_FAILURE);
	}
	if (debug) {
		printf("%s:%d: BIO for certificate created\n", __FILE__,
			__LINE__);
	}

	/* set up the BIO to read from stdin or a file			*/
	if (infile == NULL) {
		BIO_set_fp(in, stdin, BIO_NOCLOSE | BIO_FP_TEXT);
	} else {
		if (BIO_read_filename(in, infile) <= 0) {
			fprintf(stderr, "%s:%d: opening file '%s' failed: "
				"%s (%d)\n", __FILE__, __LINE__, infile,
				strerror(errno), errno);
			exit(EXIT_FAILURE);
		}
	}

	/* actually read the certificate				*/
	x = PEM_read_bio_X509(in, NULL, NULL, NULL);
	if (!x) {
		BIO_printf(bio_err, "%s:%d: unable to load certificate\n",
			__FILE__, __LINE__);
		ERR_print_errors(bio_err);
		exit(EXIT_FAILURE);
	}
	if (debug) {
		printf("%s:%d: certificate read successfully:\n", __FILE__,
			__LINE__);
	}

	/* convert the certificate into a ber value in memory		*/
	if (NULL == (bv = x509_to_mem(x))) {
		fprintf(stderr, "%s:%d: cannot convert certificate to DER\n",
			__FILE__, __LINE__);
		exit(EXIT_FAILURE);
	}

	/* convert the certificate into an escape string of hex bytes	*/
	cp = quote_berval(bv);

	/* convert the serial number to a string in case we need it	*/
	sn = asn1_to_string(X509_get_serialNumber(x));

	/* get the issuer and subject in case we need it		*/
	X509_NAME_oneline(X509_get_issuer_name(x), issuer, 1024);
	X509_NAME_oneline(X509_get_subject_name(x), subject, 1024);

	escape_parentheses(issuer, escaped_issuer);
	escape_parentheses(subject, escaped_subject);
	
	/* construct the filter for the certificate			*/
	if (use_subject) {
		filter = (char *)malloc(strlen(escaped_issuer)
			+ strlen(escaped_subject) + 64);
		sprintf(filter, "(&(issuerDN=%s)(subjectDN=%s)"
			"(objectclass=authzLDAPmap))",
			escaped_issuer, escaped_subject);
	} else if (use_serial) {
		filter = (char *)malloc(strlen(escaped_issuer) + strlen(sn)
			+ 74);
		sprintf(filter, "(&(issuerDN=%s)(serialNumber=%s)"
			"(objectclass=authzLDAPmap))", escaped_issuer, sn);
	} else {
		filter = (char *)malloc(strlen(cp) + 50);
		sprintf(filter, "(userCertificate=%s)", cp);
	}
	if (debug)
		printf("%s:%d: filter = %s\n", __FILE__, __LINE__, filter);

	/* search for a user						*/
	if (LDAP_SUCCESS != ldap_search_s(ldap, basedn, LDAP_SCOPE_SUBTREE,
		filter, NULL, 0, &results)) {
		ldap_perror(ldap, "node not found");
		exit(EXIT_FAILURE);
	}

	/* it is an error not to return anything			*/
	if (ldap_count_entries(ldap, results) == 0) {
		fprintf(stderr, "node not found\n");
		exit(EXIT_FAILURE);
	}

	/* list all users that have this certificate			*/
	for (e = ldap_first_entry(ldap, results); e != NULL;
		e = ldap_next_entry(ldap, e)) {
		dn = ldap_get_dn(ldap, e);
		printf("%s\n", dn);
		ldap_memfree(dn);
	}

	exit(EXIT_SUCCESS);
}
