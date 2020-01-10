/* 
**  auth.c -- Apache LDAP authorization module, authentication part
**
**  Read the files README and mod_authz_ldap.html for instructions on
**  configuring the module. Details of the license can be found in the
**  HTML documentation.
**
**  (c) 2000 Dr. Andreas Mueller
**
**  $Id: auth.c,v 1.11 2004/03/31 05:15:37 afm Exp $
*/ 
#include "mod_authz_ldap.h"

/*************************************************************************
** Authentication							**
*************************************************************************/
static int	initial_authenticated = 0;

/* authenticate a user using an ordinary ldap bind call			*/
/* XXX This strategy causes frequent rebinds to the ldap server, and	*/
/*     a possibly large number of message digest computations for	*/
/*     password verification. A cache could improve performance		*/
/*     considerably							*/
int	authz_ldap_authenticate(request_rec *r, const char *userdn) {
	char	dn[MAX_STRING_LEN];
	LDAP			*ldap = NULL;
	authz_ldap_config_rec	*sec;
	char			*pw = NULL, *dnp, *newname = NULL;
	LDAPMessage		*result, *e;
	int			nentries, res;
	int			version = LDAP_VERSION3;
	char			*attrs[2];
	char			**vals;

	/* get configuration record					*/
	sec = ap_get_module_config(r->per_dir_config, &authz_ldap_module);

	/* for logging purposes, we would like to have user name and	*/
	/* password, so we get them here quite early. This should never	*/
	/* return NULL, as we go to this function only when doing	*/
	/* basic authentication						*/
	AUTHZ_DEBUG5("[%d] authz_ldap_authenticate(user = %s, pw = %s, dn = %s)",
		(int)getpid(),
		(USER(r)) ? USER(r) : "(null)",
		(pw) ? pw : "(null)",
		(userdn) ? userdn : "(null)");
	ap_get_basic_auth_pw(r, (const char **)&pw);

	/* remember the username, so that we can refer to it in the	*/
	/* autorization phase (may be null)				*/
	if (NULL == USER(r)) {
		AUTHZ_DEBUG2("[%d] cannot authenticate without user",
			(int)getpid());
		return HTTP_UNAUTHORIZED;
	}
	authz_ldap_set_username(r, USER(r));

	/* if a subtree search is required, do it on the anonymous	*/
	/* connection 							*/
	if (sec->userscope) {
		AUTHZ_DEBUG5("[%d] %s search for %s=%s", (int)getpid(),
			(sec->userscope == LDAP_SCOPE_ONELEVEL)	? "onelevel"
								: "subtree",
			sec->userkey, USER(r));

		/* formulate the search filter				*/
		ap_snprintf(dn, MAX_STRING_LEN, "(%s=%s)", sec->userkey,
			USER(r));
		AUTHZ_DEBUG3("[%d] search filter is %s", (int)getpid(), dn);

		/* if we have a AuthzLDAPMapUser attribute, we also ask	*/
		/* for it						*/
		if (sec->mapusertoattr) {
			attrs[0] = sec->mapusertoattr;
		} else {
			attrs[0] = LDAP_NO_ATTRS;
		}
		attrs[1] = NULL;
		
		/* search for the user					*/
		if (LDAP_SUCCESS != authz_ldap_search(r, sec->userbase,
			sec->userscope, dn, attrs, 0, &result)) {
			ldap_msgfree(result);
			if (sec->loglevel >= APLOG_ERR)
			ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR,
				APLOG_STATUS r,
				"[%d] filter: (%s=%s) base: %s, not found",
				(int)getpid(), sec->userkey,
				USER(r),
				sec->userbase);
			ap_note_basic_auth_failure(r);
			return HTTP_UNAUTHORIZED;
		}
		AUTHZ_DEBUG2("[%d] query succeeded", (int)getpid());

		/* user should be unique, or we must decline authent.	*/
		if ((nentries = ldap_count_entries(sec->ldap, result)) != 1) {
			ldap_msgfree(result);
			if (sec->loglevel >= APLOG_ERR)
			ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR,
				APLOG_STATUS r,
				"[%d] filter: (%s=%s) base: %s, not unique",
				(int)getpid(), sec->userkey,
				USER(r),
				sec->userbase);
			ap_note_basic_auth_failure(r);
			return HTTP_UNAUTHORIZED;
		}

		/* get the distinguished name of the node found		*/
		e = ldap_first_entry(sec->ldap, result);
		dnp = ldap_get_dn(sec->ldap, e);
		strcpy(dn, dnp);
		AUTHZ_DEBUG3("[%d] query returns %s", (int)getpid(), dn);
		ldap_memfree(dnp);

		/* if using the mapping, retrieve the map name		*/
		if (sec->mapusertoattr) {
			vals = ldap_get_values(sec->ldap, e,
				sec->mapusertoattr);
			if (vals != NULL) {
				int l = strlen(vals[0]);
				newname = ap_palloc(r->pool, l+1);
				apr_cpystrn(newname, vals[0], MAX_STRING_LEN);
				authz_ldap_set_mapped(r, newname);
				AUTHZ_DEBUG3("[%d] mapped name %s",
					(int)getpid(), newname);
				ldap_value_free(vals);
			}
		}

		/* clean up the search result				*/
		ldap_msgfree(result);

		/* if a distinguished name was specified, it should be	*/
		/* identical to what we just found			*/
		if (NULL != userdn) {
			if (strcmp(dn, userdn)) {
				ap_log_rerror(APLOG_MARK,
					APLOG_NOERRNO|APLOG_ERR,
					APLOG_STATUS r,
					"[%d] distinguished names for LDAP and "
					"certificate don't match: %s != %s",
					(int)getpid(), dn, userdn);
				ap_note_basic_auth_failure(r);
				return HTTP_UNAUTHORIZED;
			}
			AUTHZ_DEBUG2("[%d] distinguished names match",
				(int)getpid());
		}

		/* use the mapped name if mapping was required		*/
		if (sec->bindmapped) {
			strcpy(dn, authz_ldap_get_mapped(r));
		}
	} else {
		ap_snprintf(dn, MAX_STRING_LEN, "%s=%s,%s", sec->userkey,
			USER(r), sec->userbase);
	}
	AUTHZ_DEBUG3("[%d] authentication dn: %s", (int)getpid(), dn);

	/* now we know the DN of the user, bind as that user		*/
	res = ap_get_basic_auth_pw(r, (const char **)&pw);
	if (res) return res;

	/* make sure the password provided is not a zero password	*/
	if (strlen(pw) == 0) {
		ap_note_basic_auth_failure(r);
		return HTTP_UNAUTHORIZED;
	}

	/* we need our separate connection 				*/
	ldap = authz_ldap_init(r);
	if (ldap == NULL) {
		if (sec->loglevel >= APLOG_ERR)
		ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR,
			APLOG_STATUS r,
			"[%d] cannot establish ldap connection", (int)getpid());
		ap_note_basic_auth_failure(r);
		return HTTP_UNAUTHORIZED;
	}

	/* set LDAP version 3 protocol options				*/
	if (LDAP_OPT_SUCCESS != ldap_set_option(ldap, LDAP_OPT_PROTOCOL_VERSION,
		&version)) {
		ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR,
			APLOG_STATUS r,
			"[%d] cannot set the protocol version", (int)getpid());
	} else {
		AUTHZ_DEBUG3("[%d] protocol version set to %d", (int)getpid(),
			version);
	}

	/* check the password by binding against the directory		*/
	res =ldap_simple_bind_s(ldap, dn, pw);
	authz_ldap_unbind(ldap);
	if (res != LDAP_SUCCESS) {
		if (sec->loglevel >= APLOG_ERR)
		ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR,
			APLOG_STATUS r,
			"[%d] bind as %s/%s failed: %d", (int)getpid(), dn, pw,
			res);
		ap_note_basic_auth_failure(r);
		return HTTP_UNAUTHORIZED;
	}
	AUTHZ_DEBUG3("[%d] bind for %s succeeds", (int)getpid(), dn);

	/* remember the user distinguished name				*/
	authz_ldap_set_userdn(r, dn);

	return OK;
}
/*************************************************************************
** Authentication (part 2)						**
*************************************************************************/

/* main authentication function						*/
int	authz_ldap_auth(request_rec *r) {
	authz_ldap_config_rec	*sec;
	const char		*pw;
	int			res, rc = DECLINED;
	const char		*userdn = NULL;

	/* start the stop watch						*/
	START_TIME;

	/* get configuration record for this request			*/
	sec = ap_get_module_config(r->per_dir_config, &authz_ldap_module);
	AUTHZ_DEBUG3("[%d] authz_ldap_auth called for uri %s", (int)getpid(),
		r->uri);

	/* if this is a subrequest the primary of which has been	*/
	/* authenticated successfully, we simply return after copying	*/
	/* the notes							*/
	if (!ap_is_initial_req(r)) {
		authz_ldap_copynotes(r);
		AUTHZ_DEBUG3("[%d] subrequest shortcut (%d)", (int)getpid(),
			initial_authenticated);
		if (initial_authenticated) {
			rc = OK;
		} else { 
			rc = AUTHZ_DECLINED;
		}
		goto auth_end;
	}
	AUTHZ_DEBUG2("[%d] processing main request", (int)getpid());
	initial_authenticated = 0;

	/* find out whether we have to do anything at all		*/
	if (AUTHMETHOD_NONE == sec->method) {
		AUTHZ_DEBUG3("[%d] authz_ldap not activeated in %x (see "
			"AuthzLDAPMethod)", (int)getpid(), (unsigned int)sec);
		rc = DECLINED;
		goto auth_end;
	}

	/* find the default value to return (need sec for this to work)	*/
	rc = AUTHZ_DECLINED;

	/* reset the value of the userdn notes table entry 		*/
	ap_table_set(r->notes, "authz_ldap::userdn", "");
	AUTHZ_DEBUG2("[%d] clearing authz_ldap::userdn notes table entry",
		(int)getpid());

	/* if this is the first call to the authentication function	*/
	/* we have to establish an ldap connection			*/
	if (sec->ldap == NULL) {
		if (OK != authz_ldap_connect(r)) {
			if (sec->loglevel >= APLOG_CRIT)
			ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_CRIT,
				APLOG_STATUS r,
				"[%d] no ldap connection", (int)getpid());
			goto auth_end;
		}
		AUTHZ_DEBUG2("[%d] LDAP connection established", (int)getpid());
	}

	/* map the user from the certificate if configured to do so	*/
	if (sec->method & AUTHMETHOD_CERT) {
		AUTHZ_DEBUG2("[%d] user mapping required", (int)getpid());
		if (authz_ldap_map_user(r)) {
			userdn = authz_ldap_get_userdn(r);
			AUTHZ_DEBUG3("[%d] user mapped to '%s'", (int)getpid(),
				(userdn) ? userdn : "(null)");
			/* FIXME: i'm not sure whether this is really	*/
			/* what was intended originally (optionally	*/
			/* authenticate using passwords only)		*/
			if (!(AUTHMETHOD_LDAP & sec->method)) {
				rc = OK;
				goto auth_end;
			}
		} else {
			AUTHZ_DEBUG2("[%d] cert user maping failed",
				(int)getpid());
			if (sec->allowpasswd) { /* Still can try password */
				AUTHZ_DEBUG2("[%d] trying password",
					(int)getpid());
				goto try_password;
			}
			goto auth_end;
		}
		AUTHZ_DEBUG2("[%d] going to request additional LDAP "
			"credentials", (int)getpid());
	} else {
try_password:
		AUTHZ_DEBUG2("[%d] working with basic authentication",
			(int)getpid());
		/* try to get the password, this should set the user	*/
		if ((res = ap_get_basic_auth_pw(r, &pw))) {
			/* password not found, so we have to fail auth	*/
			ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO,
				APLOG_STATUS r, "[%d] no password?",
				(int)getpid());
			rc = res;
			goto auth_end;
		}
	}

	/* perform ordinary LDAP authentication				*/
	AUTHZ_DEBUG3("[%d] performing ldap authentication for dn %s",
		(int)getpid(), (userdn) ? userdn : "(null)");
	if (OK != authz_ldap_authenticate(r, userdn)) {
		if (sec->loglevel >= APLOG_ERR)
		ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR,
			APLOG_STATUS r,
			"[%d] basic LDAP authentication of user '%s' failed",
			(int)getpid(), USER(r) ? USER(r) : "(null)");
		goto auth_end;
	}

	/* if we get to this point, then all must be ok			*/
	rc = OK;

	/* common code when returning from the function (timing, 	*/
	/* debugging							*/
auth_end:
	/* set the user name to the distinguished name			*/
	if (sec->setauth)
		authz_ldap_setauth(r);
	END_TIME("authz_ldap_auth()");
	AUTHZ_DEBUG4("[%d] leaving authz_ldap_auth with %d/%s", (int)getpid(),
		rc, (rc == 0) ? "OK" : "NOK");

	/* clean up connection of necessary				*/
	if ((!sec->cacheconnection) && (NULL != sec->ldap)) {
		if (LDAP_SUCCESS != (res = authz_ldap_unbind(sec->ldap))) {
			ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR,
				APLOG_STATUS r,
				"[%d] problem during LDAP unbind: %d",
				(int)getpid(), res);
		}
		sec->ldap = NULL;
	}
	if (rc == OK)
		initial_authenticated = 1;
	return rc;
}
