/* 
**  authz.c -- Apache LDAP authorization module, authorization
**
**  Read the files README and mod_authz_ldap.html for instructions on
**  configuring the module. Details of the license can be found in the
**  HTML documentation.
**
**  (c) 2000 Dr. Andreas Mueller
**
**  $Id: authz.c,v 1.10 2004/03/31 05:15:38 afm Exp $
*/ 
#include "mod_authz_ldap.h"

/*************************************************************************
** Authorization							**
*************************************************************************/

/* utility function: verify whether a filter returns anything for a	*/
/*                   given user and scope. return value is the number	*/
/*                   of records returned by the filter.			*/

int	authz_ldap_check_filter(request_rec *r, int scope,
		const char *filter) {
	const char		*user = NULL;
	authz_ldap_config_rec	*sec;
	LDAPMessage		*result;
	int			nentries;
	char			filterbuf[10240];

	/* get the server record, or we cannot resolve reply message	*/
	/* later on							*/
	sec = ap_get_module_config(r->per_dir_config, &authz_ldap_module);

	/* expand %-directives in the filter				*/
	if (NULL == authz_ldap_filter_expand(r, filterbuf, sizeof(filterbuf),
		filter)) {
		ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR,
			APLOG_STATUS r,
			"replacements in filter '%s' failed, using original",
			filter);
		apr_cpystrn(filterbuf, filter, sizeof(filterbuf));
	}

	/* get the user's distinguished name				*/
	user = authz_ldap_get_userdn(r);
	AUTHZ_DEBUG4("[%d] checking filter '%s' for user '%s'", (int)getpid(),
		user, filter);

	/* perform the ldap query with the role filter, based on the	*/
	/* user								*/
	if (LDAP_SUCCESS != authz_ldap_search(r, user, scope, filterbuf,
		NULL, 0, &result)) {
		if (sec->loglevel >= APLOG_ERR)
		ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR,
			APLOG_STATUS r, "ldap "
			"[%d] search for filter '%s', scope = %d on user '%s' "
			"failed", (int)getpid(), filterbuf, scope, user);
		return 0;
	}

	/* if we get exactly one entry back, then the search was 	*/
	/* satisified							*/
	nentries = ldap_count_entries(sec->ldap, result);
	ldap_msgfree(result);
	if (0 == nentries) {
		AUTHZ_DEBUG3("[%d] search for filter returns no "
			"entries: user '%s' doesn't verify",
			(int)getpid(), user);
		return 0;
	}
	AUTHZ_DEBUG2("[%d] search for filter succeeds", (int)getpid());
	return nentries;
}

/* utility function: verify user					*/
int	authz_ldap_is_user(request_rec *r, const char *username) {
	char			userdn[MAX_STRING_LEN];
	const char		*user;
	authz_ldap_config_rec	*sec;

	/* get the current configuration record				*/
	sec = ap_get_module_config(r->per_dir_config, &authz_ldap_module);
	AUTHZ_DEBUG4("[%d] check whether %s is %s", (int)getpid(),
		USER(r), username);

	/* if we are using certificates, the user name is in the ctx	*/
	/* otherwise use the connection record				*/
	user = authz_ldap_get_userdn(r);

	/* construct the distinguished name of the user			*/
	if ((NULL != sec->userbase) && (NULL != sec->userkey)) {
		ap_snprintf(userdn, MAX_STRING_LEN, "%s=%s,%s",
			sec->userkey, username, sec->userbase);
	} else {
		apr_cpystrn(userdn, username, MAX_STRING_LEN);
	}

	/* if the user name matches, we are ok, otherwise we don't know	*/
	/* the user (only valid DNs can make it into this function)	*/
	AUTHZ_DEBUG4("[%d] check '%s' == '%s'", (int)getpid(), userdn, user);
	return (strcmp(userdn, user)) ? 0 : 1;
}

/* utility function: verify group membership (in an LDAP group)		*/
int	authz_ldap_is_member(request_rec *r, const char *groupname) {
	char			basedn[MAX_STRING_LEN], filter[MAX_STRING_LEN];
	const char		*user = NULL;
	authz_ldap_config_rec	*sec;
	LDAPMessage		*result;
	int			nentries, rc;

	/* get the current configuration record				*/
	sec = ap_get_module_config(r->per_dir_config, &authz_ldap_module);

	/* find the name of the user					*/
	user = authz_ldap_get_user(r, sec->setgroup);

	AUTHZ_DEBUG4("[%d] check membership of %s in group %s", (int)getpid(),
		user, groupname);

	/* the group dn is not necessary, as we can always find out	*/
	/* about group membership by counting the number of objects	*/
	/* returned							*/

	/* make sure the scope is reasonably set			*/
	if ((sec->groupkey == NULL) && (sec->groupbase == NULL)
		&& (sec->groupscope != LDAP_SCOPE_BASE)) {
		/* warn the user about the configuration error, and fix	*/
		ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR,
			APLOG_STATUS r,
			"[%d] configuration error: if AuthzLDAPGroupBase "
			"and AuthzLDAPGroupKey are not set, the scope must "
			"be BASE", (int)getpid());
		sec->groupscope = LDAP_SCOPE_BASE;
	}

	/* if we have base scope, many things are different:		*/
	/*  - the filter does not necessarily include the key		*/
	/*  - the base is either computed or fixed			*/
	apr_cpystrn(basedn, groupname, MAX_STRING_LEN);
	if (sec->groupscope == LDAP_SCOPE_BASE) {
		/* compute a filter for the groupkey attribute		*/
		ap_snprintf(filter, MAX_STRING_LEN, "(%s=%s)",
			(sec->memberkey) ? sec->memberkey : "member",
			user);
		/* compute the group DN from base and key: in all other	*/
		/* cases we expect the full group DN in the requirement	*/
		if ((sec->groupbase != NULL) && (sec->groupkey != NULL)) {
			ap_snprintf(basedn, MAX_STRING_LEN, "%s=%s,%s",
				sec->groupkey, groupname, sec->groupbase);
		}
	} else {
		/* for non-BASE scope, the filter must include the 	*/
		/* a clause for the group name				*/
		ap_snprintf(filter, MAX_STRING_LEN, "(&(%s=%s)(%s=%s))",
			(sec->memberkey) ? sec->memberkey : "member",
			user, sec->groupkey, groupname);
		apr_cpystrn(basedn, sec->groupbase, MAX_STRING_LEN);
	}

	AUTHZ_DEBUG5("[%d] authz_ldap_search(r, '%s', %d, '%s', NULL, 0, "
		"&result)", (int)getpid(), basedn, sec->groupscope, filter);
		
	if ((rc = authz_ldap_search(r, basedn, sec->groupscope, filter,
		NULL, 0, &result)) != LDAP_SUCCESS) {
		AUTHZ_DEBUG3("[%d] authz_ldap_search returns error %d",
			(int)getpid(), rc);
		return 0;
	}
	nentries = ldap_count_entries(sec->ldap, result);
	ldap_msgfree(result);
	if (nentries != 1) {
		AUTHZ_DEBUG3("[%d] authz_ldap_search returns %d entries",
			(int)getpid(), nentries);
		return 0;
	}

	/* if we get to this point, then there is exactly one group in	*/
	/* the directory with the specified distinguished name and our	*/
	/* user as a member						*/
	AUTHZ_DEBUG4("[%d] %s is member of group %s", (int)getpid(), user,
		groupname);
	return 1;
}

/* utility function: verify whether a user has some role		*/
static int	authz_ldap_has_role(request_rec *r, const char *line) {
	char			*filter;
	authz_ldap_config_rec	*sec;
	int			len, rc;

	/* get configuration record					*/
	sec = ap_get_module_config(r->per_dir_config, &authz_ldap_module);

	/* count the number of white space characters in the line, then	*/
	/* compute the space required for the filter from it		*/
	len = strlen(sec->roleattrname) + 4 + strlen(line) + 4;
	AUTHZ_DEBUG3("[%d] allocating %d bytes for role filter", (int)getpid(),
		len);

	/* prepare memory for the ldap filter to apply for the role	*/
	filter = ap_palloc(r->pool, len); filter[0] = '\0';
	ap_snprintf(filter, len, "(%s=%s)", sec->roleattrname, line);
	AUTHZ_DEBUG3("[%d] role filter: %s", (int)getpid(), filter);

	/* check filter against directory				*/
	rc = authz_ldap_check_filter(r, LDAP_SCOPE_BASE, filter);
	if (!rc) {
		AUTHZ_DEBUG2("[%d] role requirement failed", (int)getpid());
		return 0;
	}

	/* if something is returned, the user has one of the roles	*/
	AUTHZ_DEBUG2("[%d] search for role filter succeeds", (int)getpid());
	return 1;
}

/* utility function: verify a filter expression				*/
int	authz_ldap_filter(request_rec *r, const char **line) {
	int			scope = LDAP_SCOPE_BASE, rc;
	const char		*filter;
	authz_ldap_config_rec	*sec;

	/* get configuration record					*/
	sec = ap_get_module_config(r->per_dir_config, &authz_ldap_module);

	/* extract the scope from the filter requirement command	*/
	if (strncmp(*line, "BASE", 4) == 0) {
		scope = LDAP_SCOPE_BASE;
		filter = *line + 4;
		while ((*filter) && (isspace((int)*filter))) filter++;
	} else if (strncmp(*line, "ONELEVEL", 8) == 0) {
		scope = LDAP_SCOPE_ONELEVEL;
		filter = *line + 8;
		while ((*filter) && (isspace((int)*filter))) filter++;
	} else if (strncmp(*line, "SUBTREE", 7) == 0) {
		scope = LDAP_SCOPE_SUBTREE;
		filter = *line + 7;
		while ((*filter) && (isspace((int)*filter))) filter++;
	} else {
		filter = *line;
	}
	AUTHZ_DEBUG4("[%d] require filter has scope = %d and filter '%s'",
		(int)getpid(), scope, filter);

	/* check filter against directory				*/
	rc = authz_ldap_check_filter(r, scope, filter);
	if (!rc) {
		AUTHZ_DEBUG2("[%d] filter requirement failed", (int)getpid());
		return 0;
	}

	/* if something is returned, the user has the role		*/
	AUTHZ_DEBUG2("[%d] search for filter succeeds", (int)getpid());
	return 1;
}

/* utility function: authorization based on file ownership		*/
int	authz_ldap_owner(request_rec *r) {
	struct stat		sb;
	char			filter[256];
	int			rc;
	authz_ldap_config_rec	*sec;

	/* we need the request record to be able to retrieve the dn	*/
	sec = ap_get_module_config(r->per_dir_config, &authz_ldap_module);

	/* if there is no filename, it's ok to access the resource	*/
	if (r->filename == NULL)
		return 1;
	AUTHZ_DEBUG3("[%d] owner check for file '%s'", (int)getpid(),
		r->filename);

	/* get more information about the file				*/
	if (stat(r->filename, &sb) < 0) {
		/* the file is not accessible to us, it's ok to try	*/
		AUTHZ_DEBUG3("[%d] file '%s' inaccessible", (int)getpid(),
			r->filename);
		return 1;
	}

	/* construct an LDAP filter requiring the uid of the user to be	*/
	/* the same as that of the file					*/
	ap_snprintf(filter, sizeof(filter), "(uidNumber=%d)", (int)sb.st_uid);
	AUTHZ_DEBUG3("[%d] owner filter: '%s'", (int)getpid(), filter);

	/* check the filter for this user				*/
	rc = authz_ldap_check_filter(r, LDAP_SCOPE_BASE, filter);
	if (!rc) {
		ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR,
			APLOG_STATUS r,
			"[%d] access to file '%s' with uid %d denied",
			(int)getpid(),
			(r->filename) ? "(unknown)" : r->filename,
			(int)sb.st_uid);
		return 0;
	}

	AUTHZ_DEBUG4("[%d] authz_ldap_owner grants access to file %s "
		"owned by %d", (int)getpid(),
		(r->filename) ? "(unknown)" : r->filename, (int)sb.st_uid);
	return 1;
}

/* utility function: authorization based on group ownership of file	*/
int	authz_ldap_groupowner(request_rec *r) {
	const char		*uid;
	struct stat		sb;
	authz_ldap_config_rec	*sec;
	char			filter[1024];
	int			nentries, rc;
	LDAPMessage		*result;

	/* we need the request record to be able to retrieve the dn	*/
	sec = ap_get_module_config(r->per_dir_config, &authz_ldap_module);

	/* get the user name						*/
	uid = authz_ldap_get_username(r);

	/* if there is no filename, it's ok to access the resource	*/
	if (r->filename == NULL)
		return 1;

	/* get more information about the file				*/
	if (stat(r->filename, &sb) < 0) {
		/* the file is not accessible to us, it's ok to try	*/
		return 1;
	}

	/* there are two cases, that unfortunately have to be dealt	*/
	/* with separately:						*/
	/*  1. the file is in the primary group of the user, i.e.	*/
	/*     the gidnumber attribute of the user has the value	*/
	/*     of sb.st_gid						*/
	/*  2. the file is in one of the secondary groups of the user,	*/
	/*     i.e. the user is member of the group with gidnumber	*/
	/*     equal to sb.st_gid					*/

	/* formulate a filter for the first case			*/
	ap_snprintf(filter, sizeof(filter), "(gidnumber=%d)", (int)sb.st_gid);
	rc = authz_ldap_check_filter(r, LDAP_SCOPE_BASE, filter);
	if (rc) {
		AUTHZ_DEBUG4("[%d] file %s is in primary group of %s",
			(int)getpid(), r->filename, authz_ldap_get_username(r));
		return 1;
	}

	/* the second case is only possible to check if the group base	*/
	/* is set							*/
	if (sec->groupbase != NULL)
		return 0;

	/* formulate a filter for the second case			*/
	ap_snprintf(filter, sizeof(filter), "(&(gidnumber=%d)(memberuid=%s))",
		(int)sb.st_gid, authz_ldap_get_username(r));

	/* perform the search						*/
	if (LDAP_SUCCESS != authz_ldap_search(r, sec->groupbase,
		sec->groupscope, filter, NULL, 0, &result)) {
		if (sec->loglevel >= APLOG_ERR)
		ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR,
			APLOG_STATUS r,
			"[%d] search last mod of '%s' with filter '%s' failed",
			(int)getpid(), USER(r), filter);
		return 0;
	}

	/* find the number of matching entries				*/
	nentries = ldap_count_entries(sec->ldap, result);
	ldap_msgfree(result);
	if (nentries > 0) {
		AUTHZ_DEBUG4("[%d] file '%s' is in a secondary group of %s",
			(int)getpid(), r->filename, authz_ldap_get_username(r));
		return 1;
	}

	/* if none of the decisions above resulted in a match, we must	*/
	/* deny access							*/
	return 0;
}

/* main authorization function						*/
/* all requirements must be satisfied					*/
int	authz_ldap_authz(request_rec *r) {
	authz_ldap_config_rec	*sec = NULL;
	const apr_array_header_t	*authz_requires = NULL;
	require_line		*reqs = NULL;
	int			i, res;
	int			rc = OK, rcfinal, linerc, sat;
	double			age;
	const char		*user;

	/* start the stopwatch						*/
	START_TIME;

	/* get the directory configuration record			*/
	sec = ap_get_module_config(r->per_dir_config, &authz_ldap_module);

	AUTHZ_DEBUG3("[%d] authz_ldap_authz for %s", (int)getpid(), r->uri);

	/* find out whether we are active at all			*/
	if (AUTHMETHOD_NONE == sec->method) {
		rc = DECLINED;
		AUTHZ_DEBUG3("[%d] declining auth checking for %s "
			"(AuthzLDAPMethod not set?)", (int)getpid(), r->uri);
		goto authz_end;
	}

	/* skip work if we are a subrequest that was already authorized	*/
	if (!ap_is_initial_req(r)) {
		rc = OK;
		AUTHZ_DEBUG2("[%d] reauthorization skipped", (int)getpid());
		goto authz_end;
	}

	/* find the user name						*/
	user = authz_ldap_get_userdn(r);

	/* inform the debugger what we are doing			*/
	AUTHZ_DEBUG4("[%d] authz_ldap_authz called by user '%s' for URI '%s'",
		(int)getpid(), user, r->uri);

	/* make sure we have an LDAP connection				*/
	if (sec->ldap == NULL) {
		if (OK != authz_ldap_connect(r)) {
			if (sec->loglevel >= APLOG_CRIT)
			ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_CRIT,
				APLOG_STATUS r,
				"[%d] no ldap connection", (int)getpid());
			goto authz_end;
		}
		AUTHZ_DEBUG2("[%d] LDAP connection established", (int)getpid());
	}

	/* get the requirement array					*/
	authz_requires = ap_requires(r);
	if (authz_requires == NULL) {
		if (sec->loglevel >= APLOG_ERR)
		ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR,
			APLOG_STATUS r,
			"[%d] no requirements for this request %s",
			(int)getpid(), r->uri);
		END_TIME("authz_ldap_authz()");
		rc = AUTHZZ_DECLINED;
		goto authz_end;
	}

	/* compute the return value if the requirements are not matched	*/
	rcfinal = AUTHZZ_DECLINED;	/* note that AUTHZZ_DECLINED is */
					/* a macro which may be 	*/
					/* HTTP_FORBIDDEN		*/
	if ((rcfinal == HTTP_UNAUTHORIZED)
		&& (sec->method & AUTHMETHOD_CERT)) {
		rcfinal = HTTP_FORBIDDEN;
	}
	AUTHZ_DEBUG3("[%d] starting with return code %d", (int)getpid(),
		rcfinal);

	/* go through all the requirements and verify that they are 	*/
	/* satisfied							*/
	reqs = (require_line *)authz_requires->elts;
		/* this causes a 'warning: cast increases required alignment
		   of target type' on SPARC, but this is acceptable because
		   at runtime we will only cast from structures that are
		   already correctly aligned.				*/

	/* the logic of requirement checking depends heavily on wether	*/
	/* all requirements must be satisfied or just one, as indicated	*/
	/* by the satisfies directive. 					*/
	/* - for `satisfy any', we can jump out of the list as soon as	*/
	/*   one requirement is satisfied				*/
	/* - for `satisfy all', we must go through all the list, and	*/
	/*   accept only if we still get an OK				*/
	sat = ap_satisfies(r);
	if (sat == SATISFY_NOSPEC)
		sat = SATISFY_ALL;
	AUTHZ_DEBUG3("[%d] must satisfy %s", (int)getpid(),
		(sat == SATISFY_ANY) ? "ANY" : (
			(sat == SATISFY_ALL) ? "ALL" : "unknown"));

	for (i = 0; i < authz_requires->nelts; i++) {
		/* the loop ends when all elements are processed.	*/
		/* the statments inside the loop must decide where to	*/
		/* jump if all/any requirements are satisfied		*/
		const char	*line, *requirement;

		/* process each requirement				*/
		AUTHZ_DEBUG3("[%d] processing requirement %s", (int)getpid(),
			reqs[i].requirement);

		/* retrieve the requirements from the array		*/
		line = reqs[i].requirement;
		requirement = ap_getword_conf(r->pool, &line);
		linerc = rcfinal;

		/* process the directives, these statements all jump	*/
		/* to the label reqdone if the requirement is, so the	*/
		/* requirement fails if we fall out at the end of the	*/
		/* list					 		*/
		if (!strcmp(requirement, "valid-user")) {
			/* as we cannot get here without mod_authz_ldap	*/
			/* having authenticated the user, this 		*/
			/* requirement is always satisfied		*/
			AUTHZ_DEBUG2("[%d] valid-user require: OK",
				(int)getpid());
			linerc = OK;
			goto reqdone;
		}
		if (!strcmp(requirement, "user")) {
			AUTHZ_DEBUG3("[%d] user required: %s", (int)getpid(),
				line);
			while (line[0]) {
				requirement = ap_getword_conf(r->pool, &line);
				if (authz_ldap_is_user(r, requirement)) {
					AUTHZ_DEBUG3("[%d] user %s ok",
						(int)getpid(), line);
					linerc = OK;
					break;
				}
			}
			goto reqdone;
		}
		if (!strcmp(requirement, "group")) {
			AUTHZ_DEBUG3("[%d] group required: %s", (int)getpid(),
				line);
			/* implies a valid user, of course		*/
			while (line[0]) {
				requirement = ap_getword_conf(r->pool, &line);
				if (authz_ldap_is_member(r, requirement)) {
					linerc = OK;
					break;
				}
			}
			goto reqdone;
		}
		if (!strcmp(requirement, "role")) {
			if (sec->roleattrname == NULL) {
				ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|
					APLOG_ERR, APLOG_STATUS r,
					"[%d] role required but "
					"role attr name not set",
					(int)getpid());
				goto reqdone;
			}
			AUTHZ_DEBUG3("[%d] role(s) required: %s", (int)getpid(),
				line);
			while (line[0]) {
				requirement = ap_getword_conf(r->pool, &line);
				if (authz_ldap_has_role(r, requirement)) {
					linerc = OK;
					break;
				}
			}
			goto reqdone;
		}
		if (!strcmp(requirement, "filter")) {
			AUTHZ_DEBUG3("[%d] filter match required: %s",
				(int)getpid(), line);
			if (authz_ldap_filter(r, &line)) {
				linerc = OK;
				break;
			}
			goto reqdone;
		}
		if (!strcmp(requirement, "owner")) {
			AUTHZ_DEBUG2("[%d] owner match required",
				(int)getpid());
			if (authz_ldap_owner(r)) {
				linerc = OK;
			}
			goto reqdone;
		}
		if (!strcmp(requirement, "group-owner")) {
			AUTHZ_DEBUG2("[%d] group match required",
				(int)getpid());
			if (authz_ldap_groupowner(r)) {
				linerc = OK;
			}
			goto reqdone;
		}
		if (!strcmp(requirement ,"age")) {
			AUTHZ_DEBUG3("[%d] age required: %s", (int)getpid(),
				line);
			requirement = ap_getword_conf(r->pool, &line);
			age = atof(requirement);
			if (authz_ldap_age(r, age)) {
				linerc = OK;
			}
			goto reqdone;
		}
		if (sec->loglevel >= APLOG_ERR)
		ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR,
			APLOG_STATUS r,
			"[%d] requirement '%s' not known to mod_authz_ldap",
			(int)getpid(), requirement);
	reqdone:
		AUTHZ_DEBUG3("[%d] done with require %s", (int)getpid(),
			requirement);
		/* when all requirements must be satisfied, we are only	*/
		/* allowed yet to jump out of the loop if the 		*/
		/* requirement is NOT satisfied				*/
		switch (sat) {
		case SATISFY_ALL:
			if (linerc != OK) {
				/* one requirement failed, so we reject */
				AUTHZ_DEBUG3("[%d] satisfy all: %s failed",
					(int)getpid(), requirement);
				rc = linerc;
				goto authz_end;
			}
			break;
		case SATISFY_ANY:
			if (linerc == OK) {
				/* one requirement succeeded, so we accept */
				AUTHZ_DEBUG3("[%d] satisfy any: %s accept",
					(int)getpid(), requirement);
				rc = linerc;
				goto authz_end;
			}
			break;
		}
	}
	/* at this point, we know that all requirements have been	*/
	/* processed, and no reason was found to prematurely terminate	*/
	/* loop. This means that for `satisfy all', we have satisfied	*/
	/* all the requirements, and for satisfy any, we have violated	*/
	/* all of them, i.e. satisfied none				*/
	AUTHZ_DEBUG2("[%d] requirements satisfied", (int)getpid());
	switch (sat) {
	case SATISFY_ALL:
		rc = OK;
		break;
	case SATISFY_ANY:
		rc = rcfinal;
		break;
	}

authz_end:
	/* if we get to this point, then an eventual age requirement	*/
	/* was satisfied, and if some other requirement was ok, rc	*/
	/* reflects this fact						*/
	if ((NULL != sec->ldap) && (!sec->cacheconnection)) {
		if (LDAP_SUCCESS != (res = authz_ldap_unbind(sec->ldap))) {
			ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR,
				APLOG_STATUS r,
				"[%d] problem during LDAP unbind: %d",
				(int)getpid(), res);
		}
		sec->ldap = NULL;
	}
	END_TIME("authz_ldap_authz()");
	AUTHZ_DEBUG4("[%d] return code from authz_ldap_authz: %s (%d)",
		(int)getpid(), (rc) ? "NOK" : "OK", rc);
	if (rc == OK) {
		AUTHZ_DEBUG2("[%d] setting ::authorized", (int)getpid());
		authz_ldap_set_authorized(r, "OK");
	}
	return rc;
}
