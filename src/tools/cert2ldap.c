/*
 * cert2ldap.c -- take a certificate from a file and write characteristic
 *                data of the certificate a given node in the directory
 *
 * $Id: cert2ldap.c,v 1.3 2003/11/16 16:43:06 afm Exp $
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
char	*targetdn = NULL;
char	*owner = NULL;
int	ldapport = LDAP_PORT;
char	*infile = NULL;
int	operation = LDAP_MOD_ADD;

typedef	enum {
	include_none = 0, include_binary = 1, include_text = 2
} include_type;
char	*include_type_name[3] = { "not included", "include as binary",
		"include in text form" };
int	serial = include_none;
int	issuer = include_none;
int	subject = include_none;
int	certificate = include_none;

extern int	optind;
extern char	*optarg;

/*
 * prototypes
 */
char	*pwprompt(char *prompt);
void	add_name_mod(LDAPMod **mods, char *attributename, X509_NAME *name);
int	check_class(LDAP *ldap, char *tdn, char *type, LDAPMod **mods);

/*
 * check whether the target node belongs to some object class, add a suiteable
 * modification entry if not
 */
int	check_class(LDAP *ldap, char *tdn, char *type, LDAPMod **mods) {
	char		filter[1024];
	LDAPMessage	*results;

	/* filter for the objectclass					*/
	snprintf(filter, 1024, "(objectclass=%s)", type);
	if (LDAP_SUCCESS != ldap_search_s(ldap, tdn, LDAP_SCOPE_BASE,
		filter, NULL, 0, &results)) {
		fprintf(stderr, "%s:%d: node %s does still not exist\n",
			__FILE__, __LINE__, tdn);
		exit(EXIT_FAILURE);	
	}

	/* if no such entry exists, add a modification entry		*/
	if (ldap_count_entries(ldap, results) == 0) {
		if (debug)
			printf("%s:%d: object is not of authzLDAPmap "
				"class, update it\n", __FILE__,
				__LINE__);
		*mods = (LDAPMod *)malloc(sizeof(LDAPMod));
		(*mods)->mod_op = LDAP_MOD_ADD;
		(*mods)->mod_type = "objectclass";
		(*mods)->mod_values = (char **)malloc(2 * sizeof(char *));
		(*mods)->mod_values[0] = type;
		(*mods)->mod_values[1] = NULL;
		return 1;
	}

	/* if not, just return zero					*/
	return 0;
}


/*
 * add_name_mod(mods, attributename, name)
 *
 * convert a distinguished name from the directory either to oneline printable
 * form or to binary form
 */
void	add_name_mod(LDAPMod **mods, char *attributename, X509_NAME *name) {
	char		buf[1024];
	
	/* allocate a new modification record				*/
	(*mods) = (LDAPMod *)malloc(sizeof(LDAPMod));

	/* we will need the oneline form anyway, for logging		*/
	X509_NAME_oneline(name, buf, 1024);

	/* common fields of the modification record			*/
	(*mods)->mod_op = LDAP_MOD_REPLACE;
	(*mods)->mod_type = attributename;

	X509_NAME_oneline(name, buf, 1024);
	(*mods)->mod_values = (char **)malloc(2 * sizeof(char *));
	(*mods)->mod_values[0] = strdup(buf);
	(*mods)->mod_values[1] = NULL;
	if (debug)
		printf("%s:%d: %s = %s added\n", __FILE__, __LINE__,
			(*mods)->mod_type, (*mods)->mod_values[0]);
}

/*
 * pwprompt
 *
 * request a password from the user, by opening /dev/tty and not echoing
 * anything
 */
char	*pwprompt(char *prompt) {
	/* XXX prompt for password					*/
	return NULL;
}

int	main(int argc, char *argv[]) {
	int		c, modi, rc;
	BIO		*in = NULL, *bio_err = NULL, *bio_out = NULL;
	X509		*x = NULL;
	LDAPMod		*mods[6];
	ASN1_INTEGER	*ser;
	LDAP		*ldap;
	LDAPMessage	*results;
	int		mapping = 0, version = 2, needsbinary = 0;

	/* parse the command line					*/
	while ((c = getopt(argc, argv, "Bdevo:D:b:Ww:h:p:cisnLV:")) != EOF)
		switch (c) {
		case 'B':
			needsbinary = 1;
			break;
		case 'd':
			debug++;
			break;
		case 'e':
			operation = LDAP_MOD_DELETE;
			fprintf(stderr, "%s:%d: option -e not implemented\n",
				__FILE__, __LINE__);
			exit(EXIT_FAILURE);
			break;
		case 'v':
			verbose = 1;
			break;
		case 'D':
			targetdn = optarg;
			if (debug)
				printf("%s:%d: target DN set to '%s'\n",
					__FILE__, __LINE__, targetdn);
			break;
		case 'o':
			owner = optarg;
			mapping = 1;
			if (debug) 
				printf("%s:%d: owner set to '%s'\n", __FILE__,
					__LINE__, owner);
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
		case 'W':
			bindpw = pwprompt("Password:");
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
		case 'c':
			certificate = include_binary;
			break;
		case 's':
			subject = include_text;
			mapping = 1;
			break;
		case 'i':
			issuer = include_text;
			mapping = 1;
			break;
		case 'n':
			serial = include_text;
			mapping = 1;
			break;
		case 'V':
			version = atoi(optarg);
			break;
		}

	/* make sure we have consistent arguments			*/
	if (!targetdn) {
		fprintf(stderr, "%s:%d: must specify -D <targetdn>\n", __FILE__,
			__LINE__);
		exit(EXIT_FAILURE);
	}

	/* if we are creating a map, make sure we have enough arguments */
	/* for a working map						*/
	if (mapping) {
		if (!((issuer) && ((subject) || (serial)))) {
			fprintf(stderr, "%s:%d: insufficient attributes "
				"for a map\n", __FILE__, __LINE__);
			exit(EXIT_FAILURE);
		}
		if (!owner) {
			fprintf(stderr, "%s:%d: owner must be specified "
				"in a map\n", __FILE__, __LINE__);
			exit(EXIT_FAILURE);
		}
	}

	/* if debugging, display what we will include in the LDIF or 	*/
	/* update 							*/
	if (debug) {
		printf("%s:%d: the following attributes will be included:\n",
			__FILE__, __LINE__);
		printf("%s:%d: serialNumber     %s\n", __FILE__, __LINE__,
			include_type_name[serial]);
		printf("%s:%d: issuerDN         %s\n", __FILE__, __LINE__,
			include_type_name[issuer]);
		printf("%s:%d: subjectDN        %s\n", __FILE__, __LINE__,
			include_type_name[subject]);
		printf("%s:%d: certificate      %s\n", __FILE__, __LINE__,
			include_type_name[certificate]);
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

	/* set LDAP version 3 protocol options				*/
	if (LDAP_OPT_SUCCESS != ldap_set_option(ldap, LDAP_OPT_PROTOCOL_VERSION,
		&version)) {
		fprintf(stderr, "%s:%d: cannot set the protocol version\n",
			__FILE__, __LINE__);
	} else {
		if (debug)
			fprintf(stderr, "%s:%d: protocol version set to %d",
				__FILE__, __LINE__, version);
	}

	/* try to bind, this is necessary to acquire the necessary	*/
	/* privileges to perform the update				*/
	if (ldap_simple_bind_s(ldap, binddn, bindpw) != LDAP_SUCCESS) {
		ldap_perror(ldap, "cannot bind");
		exit(EXIT_FAILURE);
	}
	if (debug)
		printf("%s:%d: bind to ldap server succeeded\n", __FILE__,
			__LINE__);

	/* find out whether the node already exists			*/
	if (debug)
		printf("%s:%d: searching for target node %s\n", __FILE__,
			__LINE__, targetdn);
	rc = ldap_search_s(ldap, targetdn, LDAP_SCOPE_BASE, "(objectclass=*)",
		NULL, 0, &results);
	if ((LDAP_SUCCESS != rc) && (LDAP_NO_SUCH_OBJECT != rc)) {
		ldap_perror(ldap, "search for target node failed");
		exit(EXIT_FAILURE);
	}
	if (rc == LDAP_NO_SUCH_OBJECT) {
		LDAPMod	**attrs;
		if (debug)
			printf("%s:%d: node %s does not exist yet: create it\n",
				__FILE__, __LINE__, targetdn);
		attrs = (LDAPMod **)malloc(2 * sizeof(LDAPMod *));
		attrs[0] = malloc(sizeof(LDAPMod));
		attrs[0]->mod_op = 0;
		attrs[0]->mod_type = "objectclass";
		attrs[0]->mod_values = (char **)malloc(2 * sizeof(char *));
		attrs[0]->mod_values[0] = "top";
		attrs[0]->mod_values[1] = NULL;
		attrs[1] = NULL;
		if (LDAP_SUCCESS != ldap_add_s(ldap, targetdn, attrs)) {
			ldap_perror(ldap, "cannot add target");
			exit(EXIT_FAILURE);
		}
		free(attrs[0]->mod_values);
		free(attrs[0]);
		free(attrs);
		if (debug)
			printf("%s:%d: node %s added\n", __FILE__, __LINE__,
				targetdn);
	}

	/* the node exists, and we can start to update it with the new	*/
	/* data								*/

	/* if there is another argument, it's a filename for a 		*/
	/* certificate							*/
	if (optind < argc) {
		infile = argv[optind];
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

	/* XXX if verbose, display the contents of the certificate	*/

	/* convert the attributes into LDAP modify requests		*/
	modi = 0;

	/* certificate							*/
	if (certificate) {
		struct berval	*bv;
		
		bv = x509_to_mem(x);
		if (debug)
			printf("%s:%d: %ld bytes for certificate at %p\n",
				__FILE__, __LINE__, bv->bv_len, bv->bv_val);

		/* create the modification entry for the certificate	*/
		/* attribute (userCertificate)				*/
		mods[modi] = (LDAPMod *)malloc(sizeof(LDAPMod));
		mods[modi]->mod_op = LDAP_MOD_ADD | LDAP_MOD_BVALUES;
		/* the userCertificate attribute must be transfered 	*/
		/* with the ;binary option				*/
		if (needsbinary)
			mods[modi]->mod_type = "userCertificate;binary";
		else
			mods[modi]->mod_type = "userCertificate";
		mods[modi]->mod_bvalues = (struct berval **)malloc(
			2 * sizeof(struct berval *));
		mods[modi]->mod_bvalues[0] = bv;
		mods[modi]->mod_bvalues[1] = NULL;

		/* increment modi to commit this modification		*/
		modi++;
		if (debug)
			printf("%s:%d: %d modifications so far\n", __FILE__,
				__LINE__, modi);
	}


	/* serial number						*/
	if (serial) {
		ser = X509_get_serialNumber(x);
		if (debug)
			printf("%s:%d: including serial number\n",
				__FILE__, __LINE__);

		mods[modi] = (LDAPMod *)malloc(sizeof(LDAPMod));
		mods[modi]->mod_op = LDAP_MOD_REPLACE;
		mods[modi]->mod_type = "serialNumber";

		/* allocate value array				*/
		mods[modi]->mod_values = (char **)malloc(2 * sizeof(char *));
		mods[modi]->mod_values[0] = asn1_to_string(ser);
		if (debug)
			printf("%s:%d: text representation of serial "
				"number: %s\n", __FILE__, __LINE__,
				mods[modi]->mod_values[0]);
		mods[modi]->mod_values[1] = NULL;

		/* increment modi to commit this modification		*/
		modi++;
	}

	/* issuer DN							*/
	if (issuer) {
		if (debug)
			printf("%s:%d: including issuerDN\n", __FILE__,
				__LINE__);
		add_name_mod(&mods[modi], "issuerDN", X509_get_issuer_name(x));
		modi++;
	}

	/* subject DN 							*/
	if (subject) {
		if (debug)
			printf("%s:%d: including subjectDN\n", __FILE__,
				__LINE__);
		add_name_mod(&mods[modi], "subjectDN",
			X509_get_subject_name(x));
		modi++;
	}

	/* add owner attribute						*/
	if (owner) {
		mods[modi] = (LDAPMod *)malloc(sizeof(LDAPMod));
		mods[modi]->mod_op = LDAP_MOD_REPLACE;
		mods[modi]->mod_type = "owner";
		mods[modi]->mod_values = (char **)malloc(2 * sizeof(char *));
		mods[modi]->mod_values[0] = owner;
		mods[modi]->mod_values[1] = NULL;
		modi++;
	}

	/* if we are mapping, we must check whether the node is already	*/
	/* of the AuthzLDAPmap class					*/
	if (mapping) {
		if (check_class(ldap, targetdn, "authzLDAPmap",
			&mods[modi]))	modi++;
	}

	/* if we are not mapping, but still include the certificate	*/
	/* we must make sure the node is of the strongAuthentcationUser	*/
	/* objectclass							*/
	if (certificate) {
		if (check_class(ldap, targetdn, "strongAuthenticationUser",
			&mods[modi]))	modi++;
	}

	/* set the last modification to zero, to notify ldap_modify of	*/
	/* end of the array						*/
	mods[modi] = NULL;

	/* show list of attributes					*/
	if (debug) {
		int	i;
		printf("%s:%d: modifying the following attributes: ",
			__FILE__, __LINE__);
		for (i = 0; i < modi; i++) {
			if (i) printf(", ");
			printf("%s", mods[i]->mod_type);
		}
		printf("\n");
	}

	/* perform LDAP update						*/
	if (LDAP_SUCCESS != ldap_modify_s(ldap, targetdn, mods)) {
		ldap_perror(ldap, "modification failed");
		exit(EXIT_FAILURE);
	}

	/* report results						*/

	exit(EXIT_SUCCESS);
}
