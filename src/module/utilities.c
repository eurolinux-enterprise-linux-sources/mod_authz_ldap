/* 
**  utilities.c -- Apache LDAP authorization module, utilities
**
**  Read the files README and mod_authz_ldap.html for instructions on
**  configuring the module. Details of the license can be found in the
**  HTML documentation.
**
**  (c) 2000 Dr. Andreas Mueller
**
**  $Id: utilities.c,v 1.9 2004/03/31 05:15:38 afm Exp $
*/ 
#include "mod_authz_ldap.h"

struct tms	starttms, endtms;
struct timeval	starttv, endtv;

/*************************************************************************
** Utility functions to handle the connection to the LDAP server	**
**************************************************************************
** authz_ldap_init	initialize the connection, but don't connect yet
** authz_ldap_unbind	free the connection to the directory
** authz_ldap_connect	connect to the directory, without binding
** authz_ldap_reconnect	reestablish the connection to the directory
** authz_ldap_search	actually perform a search
*/

/* utility function: connect to the ldap server when required		*/
LDAP	*authz_ldap_init(request_rec *r) {
	char			*server, *pport;
	int			port;
	authz_ldap_config_rec	*sec = NULL;
	LDAP			*result = NULL;
	
	/* get configuration record					*/
	sec = ap_get_module_config(r->per_dir_config, &authz_ldap_module);
	
	/* log initialization of LDAP connection			*/
	AUTHZ_DEBUG2("[%d] initialize LDAP connection", (int)getpid());

	/* parse servername and port from the configuration		*/
	if (!(sec->server))
		server = "localhost";
	else
		server = ap_pstrdup(r->pool, sec->server);
	pport = strchr(server, ':');
	if (pport) {
		port = atoi(pport + 1);
		*pport = '\0';
	} else
		port = LDAP_PORT;
	result = ldap_init(server, port);
	if (NULL == result) {
		if (sec->loglevel >= APLOG_EMERG)
		ap_log_rerror(APLOG_MARK, APLOG_EMERG, APLOG_STATUS r,
			"cannot open LDAP "
			"[%d] connection to host %s, port %d", (int)getpid(),
			server, port);
	} else {
		AUTHZ_DEBUG5("[%d] got ldap connection to %s:%d at 0x%08x",
			(int)getpid(), server, port, (unsigned int)result);
	}

#ifdef HAVE_LDAP_SET_OPTION
	/* set LDAP version 3 protocol options, the necessity of this	*/
	/* was pointed out by Guy De Leeuw (G.De_Leeuw@eurofer.be)	*/
	if (sec->ldapversion != 0) {
		if (LDAP_OPT_SUCCESS != ldap_set_option(result,
			LDAP_OPT_PROTOCOL_VERSION, &sec->ldapversion)) {
		ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR,
			APLOG_STATUS r,
			"[%d] cannot set the protocol version", (int)getpid());
		} else {
			AUTHZ_DEBUG3("[%d] protocol version set to %d",
				(int)getpid(), sec->ldapversion);
		}
	}
#endif /* HAVE_LDAP_SET_OPTION */

#ifdef HAVE_LDAP_ENABLE_CACHE
	/* activate the cache if our library is capable of doing so	*/
	if (sec->cachesize > 0) {
		if (ldap_enable_cache(result, sec->timeout, sec->cachesize)
			< 0) {
			ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR,
				APLOG_STATUS r,
				"[%d] cannot allocate memory for ldap cache",
				(int)getpid());
		} else {
			AUTHZ_DEBUG4("[%d] caching enabled: timeout=%ds, cache "
				"size=%dbytes", (int)getpid(), sec->timeout,
				sec->cachesize);
		}
	}
#endif /* HAVE_LDAP_ENABLE_CACHE */

	return result;
}

/* utility function: tear down ldap connection when it is no longer	*/
/*                   used						*/
int	authz_ldap_unbind(LDAP *l) {
	return ldap_unbind_s(l);
}

/* utility function: establish the ldap connection in the conf rec	*/
int	authz_ldap_connect(request_rec *r) {
	authz_ldap_config_rec	*sec;
	int			rc;
	
	/* get configuration record					*/
	sec = ap_get_module_config(r->per_dir_config, &authz_ldap_module);
	
	/* nothing to do if we already have a connection to the server	*/
	if (sec->ldap) {
		AUTHZ_DEBUG2("[%d] ldap connection already established",
			(int)getpid());
		return OK;
	}

	/* build the connection now					*/
	sec->ldap = authz_ldap_init(r);
	if (sec->ldap == NULL)
		return -1;

	/* perform a nonanymous bind if bind user and password are set	*/
	if ((rc = ldap_simple_bind_s(sec->ldap, sec->binddn, sec->bindpw))
		!= LDAP_SUCCESS) {
		if (sec->loglevel >= APLOG_EMERG)
		ap_log_rerror(APLOG_MARK, APLOG_EMERG, APLOG_STATUS r,
			"cannot bind to "
			"[%d] LDAP Server as %s/%s: %d", (int)getpid(), 
			sec->binddn, sec->bindpw, rc);
		return -1;
	}
	AUTHZ_DEBUG2("[%d] bind to ldap server succeeded", (int)getpid());
	return OK;
}

/* utility function: rebuild the ldap connection, which may have gone	*/
/* away, e.g. through a TCP session timeout from Checkpoint Firewall-1	*/
/* This shouldn't be necessary, as the LDAP library is supposed to 	*/
/* handle this case							*/
int	authz_ldap_reconnect(request_rec *r) {
	authz_ldap_config_rec	*sec;
	
	/* get configuration record					*/
	sec = ap_get_module_config(r->per_dir_config, &authz_ldap_module);
	AUTHZ_DEBUG2("[%d] LDAP reconnect", (int)getpid());

	/* force closing of the connection, free of resources		*/
	authz_ldap_unbind(sec->ldap);
	sec->ldap = NULL;
	
	/* esablish connection using the method as previously		*/
	return authz_ldap_connect(r);
}

/* Perform an LDAP search, this may fail if the connection has gone	*/
/* away or was never established. In these cases, reestablish the	*/
/* connection.								*/
int	authz_ldap_search(request_rec *r, char *base, int scope,
		const char *filter, char *attrs[], int attrsonly,
		LDAPMessage **res) {
	int	rc;
	authz_ldap_config_rec	*sec;
	
	/* get configuration record					*/
	sec = ap_get_module_config(r->per_dir_config, &authz_ldap_module);

	/* try search 							*/
	rc = ldap_search_s(sec->ldap, base, scope, (char *)filter,
		attrs, attrsonly, res);
	if (rc != LDAP_SUCCESS) {
		/* display the cause for the problem as a string. We	*/
		/* use the normal apache functions for this, because	*/
		/* normally the filters succeed, what is interesting	*/
		/* about them is whether they return anything		*/
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
			"[%d] search from '%s' for '%s' returns %d = '%s'",
			(int)getpid(), base, filter, rc, ldap_err2string(rc));
	} else {
		/* if we succeed, return the result we were asking for	*/
		AUTHZ_DEBUG2("[%d] return successful ldap_search_s",
			(int)getpid());
		return rc;
	}

	/* only for some types of errors, we will try again		*/
	if ((rc == LDAP_OPERATIONS_ERROR) || (rc == LDAP_PROTOCOL_ERROR)
		|| (rc == LDAP_SERVER_DOWN)) {
		AUTHZ_DEBUG2("[%d] we must retry the call after reconnect",
			(int)getpid());
		authz_ldap_reconnect(r);
	}

	AUTHZ_DEBUG2("[%d] retry the search", (int)getpid());
	return ldap_search_s(sec->ldap, base, scope, (char *)filter, attrs,
		attrsonly, res);
}

/*************************************************************************
** utility functions to work with users					**
**************************************************************************
** authz_ldap_setauth		set the authorization header to what the
**				configuration asks it to
** authz_ldap_get_userdn	get the user's distinguished name
** authz_ldap_get_username	get the user's short name
** authz_ldap_set_userdn	save the user's distinguished name
** authz_ldap_set_username	save the user's short name (the cn usually)
*/

/* utility function: set the distinguished name as the user name	*/
void	authz_ldap_setauth(request_rec *r) {
	char			b[MAX_STRING_LEN];
	char			*uu;
	const char		*user;
	const char		*pw = "password";
	authz_ldap_config_rec	*sec;
	int			authtype;

	/* get the configuration structure				*/
	sec = ap_get_module_config(r->per_dir_config, &authz_ldap_module);

	/* if the password flag is enabled in setuath, then we can 	*/
	/* expect a password which we should use			*/
	if (sec->setauth & AUTHHEADER_PASSWORD) {
		ap_get_basic_auth_pw(r, &pw);
	}

	/* set the user name to what was required			*/
	if ((authz_ldap_get_user(r, sec->setauth)) == NULL)
		return;

	/* build an Authorization header				*/
	ap_snprintf(b, MAX_STRING_LEN, "%s:%s", user, pw);

	/* base64encode the string now, result goes to b2		*/
	uu = ap_pbase64encode(r->pool, b);
	ap_snprintf(b, MAX_STRING_LEN, "Basic %s", uu);

	/* set the basic authorization header				*/
	authtype = sec->proxyauth;
	if (sec->proxyauth == AUTHZ_AUTO) {
		authtype = (r->proxyreq) ? AUTHZ_PROXY : AUTHZ_AUTH;
	}
	AUTHZ_DEBUG4("[%d] doing %s authentication for %s", (int)getpid(),
		(authtype == AUTHZ_AUTH) ? "server" : "proxy", user);
	ap_table_set(r->headers_in, (authtype == AUTHZ_AUTH)
		? "Authorization" : "Proxy-Authorization", b);

	/* get the password (trivial) to make sure the ->user field	*/
	/* of the connection structure is set				*/
	ap_get_basic_auth_pw(r, &pw);
}

/* utility function: get username					*/
const char	*authz_ldap_get_username(request_rec *r) {
	return ap_table_get(r->notes, "authz_ldap::user");
}

/* utility function: get userdn						*/
const char	*authz_ldap_get_userdn(request_rec *r) {
	return ap_table_get(r->notes, "authz_ldap::userdn");
}

/* utility function: get mapped						*/
const char	*authz_ldap_get_mapped(request_rec *r) {
	return ap_table_get(r->notes, "authz_ldap::mapped");
}

/* utility function: get subject					*/
const char	*authz_ldap_get_subject(request_rec *r) {
	return ap_table_get(r->notes, "authz_ldap::subject");
}

/* utility function: get serial						*/
const char	*authz_ldap_get_serial(request_rec *r) {
	return ap_table_get(r->notes, "authz_ldap::serial");
}

/* utility function: get authorized					*/
const char	*authz_ldap_get_authorized(request_rec *r) {
	return ap_table_get(r->notes, "authz_ldap::authorized");
}

/* utility function: set username					*/
void	authz_ldap_set_username(request_rec *r, char *username) {
	authz_ldap_config_rec	*sec;
	sec = ap_get_module_config(r->per_dir_config, &authz_ldap_module);
	AUTHZ_DEBUG3("[%d] setting ::user to %s", (int)getpid(), username);
	ap_table_set(r->notes, "authz_ldap::user", username);
}

/* utility function: set userdn						*/
void	authz_ldap_set_userdn(request_rec *r, char *userdn) {
	authz_ldap_config_rec	*sec;
	sec = ap_get_module_config(r->per_dir_config, &authz_ldap_module);
	AUTHZ_DEBUG3("[%d] setting ::userdn to %s", (int)getpid(), userdn);
	ap_table_set(r->notes, "authz_ldap::userdn", userdn);
}

/* utility function: set mapped						*/
void	authz_ldap_set_mapped(request_rec *r, char *mapped) {
	authz_ldap_config_rec	*sec;
	sec = ap_get_module_config(r->per_dir_config, &authz_ldap_module);
	AUTHZ_DEBUG3("[%d] setting ::mapped to %s", (int)getpid(), mapped);
	ap_table_set(r->notes, "authz_ldap::mapped", mapped);
}

/* utility function: set subject					*/
void	authz_ldap_set_subject(request_rec *r, char *subject) {
	authz_ldap_config_rec	*sec;
	sec = ap_get_module_config(r->per_dir_config, &authz_ldap_module);
	AUTHZ_DEBUG3("[%d] setting ::subject to %s", (int)getpid(), subject);
	ap_table_set(r->notes, "authz_ldap::subject", subject);
}

/* utility function: set serial						*/
void	authz_ldap_set_serial(request_rec *r, char *serial) {
	authz_ldap_config_rec	*sec;
	sec = ap_get_module_config(r->per_dir_config, &authz_ldap_module);
	AUTHZ_DEBUG3("[%d] setting ::serial to %s", (int)getpid(), serial);
	ap_table_set(r->notes, "authz_ldap::serial", serial);
}

/* utility function: set authorized					*/
void	authz_ldap_set_authorized(request_rec *r, char *authorized) {
	authz_ldap_config_rec	*sec;
	sec = ap_get_module_config(r->per_dir_config, &authz_ldap_module);
	AUTHZ_DEBUG3("[%d] setting ::authorized to %s", (int)getpid(),
		authorized);
	ap_table_set(r->notes, "authz_ldap::authorized", authorized);
}

const char	*authz_ldap_get_user(request_rec *r, int nameflag) {
	const char	*user = NULL;
	authz_ldap_config_rec	*sec;

	/* get the configuration record */
	sec = ap_get_module_config(r->per_dir_config, &authz_ldap_module);

	AUTHZ_DEBUG3("[%d] looking for user with nameflag = %d", (int)getpid(),
		nameflag);
	if (nameflag & AUTHHEADER_USER) {
		user = ap_table_get(r->notes, "authz_ldap::user");
		AUTHZ_DEBUG2("[%d] looking form authz_ldap::user",
			(int)getpid());
	}
	if (nameflag & AUTHHEADER_LDAPDN) {
		user = ap_table_get(r->notes, "authz_ldap::userdn");
		AUTHZ_DEBUG2("[%d] looking form authz_ldap::userdn",
			(int)getpid());
	}
	if (nameflag & AUTHHEADER_SUBJECT) {
		user = ap_table_get(r->notes, "authz_ldap::subject");
		AUTHZ_DEBUG2("[%d] looking form authz_ldap::subject",
			(int)getpid());
	}
	if (nameflag & AUTHHEADER_MAP) {
		user = ap_table_get(r->notes, "authz_ldap::mapped");
		AUTHZ_DEBUG2("[%d] looking form authz_ldap::mapped",
			(int)getpid());
	}
	if (user == NULL) {
		AUTHZ_DEBUG2("[%d] no user name found", (int)getpid());
	} else {
		AUTHZ_DEBUG3("[%d] found user: %s", (int)getpid(), user);
	}

	return user;
}

/* copy notes from the main request to the subrequest */
void	authz_ldap_copynotes(request_rec *r) {
	const char	*c;
	authz_ldap_config_rec	*sec;

	/* get the configuration record */
	sec = ap_get_module_config(r->per_dir_config, &authz_ldap_module);
	if (r->main == NULL) {
		AUTHZ_DEBUG2("[%d] no request to copy from", (int)getpid());
		return;
	}
	AUTHZ_DEBUG2("[%d] copying notes to subrequest", (int)getpid());
	if ((c = ap_table_get(r->main->notes, "authz_ldap::user"))) {
		AUTHZ_DEBUG3("[%d] copy ::user %s", (int)getpid(), c);
		ap_table_set(r->notes, "authz_ldap::user", c);
	}
	if ((c = ap_table_get(r->main->notes, "authz_ldap::userdn"))) {
		AUTHZ_DEBUG3("[%d] copy ::userdn %s", (int)getpid(), c);
		ap_table_set(r->notes, "authz_ldap::userdn", c);
	}
	if ((c = ap_table_get(r->main->notes, "authz_ldap::subject"))) {
		AUTHZ_DEBUG3("[%d] copy ::subject %s", (int)getpid(), c);
		ap_table_set(r->notes, "authz_ldap::subject", c);
	}
	if ((c = ap_table_get(r->main->notes, "authz_ldap::mapped"))) {
		AUTHZ_DEBUG3("[%d] copy ::mapped %s", (int)getpid(), c);
		ap_table_set(r->notes, "authz_ldap::mapped", c);
	}
	if ((c = ap_table_get(r->main->notes, "authz_ldap::serial"))) {
		AUTHZ_DEBUG3("[%d] copy ::serial %s", (int)getpid(), c);
		ap_table_set(r->notes, "authz_ldap::serial", c);
	}
	if ((c = ap_table_get(r->main->notes, "authz_ldap::authorized"))) {
		AUTHZ_DEBUG3("[%d] copy ::authorized %s", (int)getpid(), c);
		ap_table_set(r->notes, "authz_ldap::authorized", c);
	}
}
