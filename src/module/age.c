/* 
**  age.c -- Apache LDAP authorization module, password aging
**
**  Read the files README and mod_authz_ldap.html for instructions on
**  configuring the module. Details of the license can be found in the
**  HTML documentation.
**
**  (c) 2000 Dr. Andreas Mueller
**
**  $Id: age.c,v 1.3 2002/10/06 19:01:16 afm Exp $
*/ 
#include "mod_authz_ldap.h"

/*************************************************************************
** password aging							**
*************************************************************************/

/* utility function: verify last modification timestamp			*/
int	authz_ldap_age(request_rec *r, double age) {
	time_t			sage, ltime;
	authz_ldap_config_rec	*sec;
	char			filter[64];
	LDAPMessage		*result;
	int			nentries;
	char			*user;

	/* we need the request record to be able to retrieve the dn	*/
	sec = ap_get_module_config(r->per_dir_config, &authz_ldap_module);
	if (!sec->modifykey) {
		if (sec->loglevel >= APLOG_ERR)
		ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR,
			APLOG_STATUS r,
			"[%d] configuration error: age required but "
			"AuthzLDAPModifykey not set", (int)getpid());
		return 0;
	}

	/* age is in days, we need seconds				*/
	sage = 86400 * age;

	/* formulate a timestamp string as ldap filter, so that we can	*/
	/* decide about the age without actually parsing the the search	*/
	/* result							*/
	ltime = time(NULL) - sage;	/* last mod after this time	*/
	ap_snprintf(filter, 64, "(%s>=", sec->modifykey);
	strftime(&filter[strlen(filter)], 64 - strlen(filter),
		"%Y%m%d%H%M%SZ)", localtime(&ltime));

	/* get the user's distinguished name				*/
	user = authz_ldap_get_userdn(r);

	/* find the last modification timestamp of the user		*/
	AUTHZ_DEBUG4("[%d] authz_ldap_search('%s', '%s')", (int)getpid(), user,
		filter);
	if (LDAP_SUCCESS != authz_ldap_search(r, user,
		LDAP_SCOPE_BASE, filter, NULL, 0, &result)) {
		if (sec->loglevel >= APLOG_ERR)
		ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR,
			APLOG_STATUS r,
			"[%d] search last mod of '%s' with filter '%s' failed",
			(int)getpid(), USER(r), filter);
		return 0;
	}

	/* if we get exactly one entry back, then the search and the	*/
	/* age condition were satisified				*/
	nentries = ldap_count_entries(sec->ldap, result);
	ldap_msgfree(result);
	if (1 != nentries) {
		AUTHZ_DEBUG3("[%d] search for last mod returns wrong number of "
			"entries: %d != 1", (int)getpid(), nentries);
		return 0;
	}

	/* got exactly one entry					*/
	return 1;
}
