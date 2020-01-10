/* 
**  modconfig.c.c -- Apache LDAP authorization module configuration
**
**  Read the files README and mod_authz_ldap.html for instructions on
**  configuring the module. Details of the license can be found in the
**  HTML documentation.
**
**  (c) 2001 Dr. Andreas Mueller
**
**  $Id: modconf.c,v 1.10 2004/03/30 23:35:50 afm Exp $
*/ 
#include "mod_authz_ldap.h"

#ifndef AP_SERVER_MAJORVERSION
/* The content handler */
/* XXX it is planned that this displays statistics about the module	*/
static int authz_ldap_handler(request_rec *r)
{
    r->content_type = "text/html";      
    ap_send_http_header(r);
    if (!r->header_only)
        ap_rputs("Authz_LDAP statistics are not yet implemented.\n", r);
    return OK;
}
#endif /* AP_SERVER_MAJORVERSION */

#ifndef AP_SERVER_MAJORVERSION
/* Dispatch list of content handlers */
const handler_rec authz_ldap_handlers[] = { 
    { "authz_ldap", authz_ldap_handler }, 
    { NULL, NULL }
};
#endif /* AP_SERVER_MAJORVERSION */

/*************************************************************************
** Configuration							**
*************************************************************************/

/* parse scope configuration directive					*/
static const char	*authz_ldap_set_user_scope_slot(cmd_parms *parms,
	void *mconfig, const char *arg) {
	authz_ldap_config_rec	*sec;
	sec = (authz_ldap_config_rec *)mconfig;

#ifdef AUTHZ_LDAP_DEBUG
	fprintf(stderr, "%s:%d: setting user search scope at %p to '%s'\n",
		__FILE__, __LINE__, (void *)sec, (arg) ? arg : "(null)");
#endif
	/* check for correct directives					*/
	if (0 == strcasecmp("subtree", arg)) {
		sec->userscope = LDAP_SCOPE_SUBTREE;
	} else if (0 == strcasecmp("onelevel", arg)) {
		sec->userscope = LDAP_SCOPE_ONELEVEL;
	} else if (0 == strcasecmp("base", arg)) {
		sec->userscope = LDAP_SCOPE_BASE;
	} else {
		return "illegal argument to AuthzLDAPUserScope";
	}
	return NULL;
}

static const char	*authz_ldap_set_group_scope_slot(cmd_parms *parms,
	void *mconfig, const char *arg) {
	authz_ldap_config_rec	*sec;
	sec = (authz_ldap_config_rec *)mconfig;

#ifdef AUTHZ_LDAP_DEBUG
	fprintf(stderr, "%s:%d: setting group search scope at %p to '%s'\n",
		__FILE__, __LINE__, (void *)sec, (arg) ? arg : "(null)");
#endif
	/* check for correct directives					*/
	if (0 == strcasecmp("subtree", arg)) {
		sec->groupscope = LDAP_SCOPE_SUBTREE;
	} else if (0 == strcasecmp("onelevel", arg)) {
		sec->groupscope = LDAP_SCOPE_ONELEVEL;
	} else if (0 == strcasecmp("base", arg)) {
		sec->groupscope = LDAP_SCOPE_BASE;
	} else {
		return "illegal argument to AuthzLDAPUserScope";
	}
	return NULL;
}

static const char	*authz_ldap_set_map_scope_slot(cmd_parms *parms,
	void *mconfig, const char *arg) {
	authz_ldap_config_rec	*sec;
	sec = (authz_ldap_config_rec *)mconfig;

#if AUTHZ_LDAP_DEBUG
	fprintf(stderr, "%s:%d: setting map search scope at %p to '%s'\n",
		__FILE__, __LINE__, (void *)sec, (arg) ? arg : "(null)");
#endif
	/* check for correct directives					*/
	if (0 == strcasecmp("subtree", arg)) {
		sec->mapscope = LDAP_SCOPE_SUBTREE;
	} else if (0 == strcasecmp("onelevel", arg)) {
		sec->mapscope = LDAP_SCOPE_ONELEVEL;
	} else if (0 == strcasecmp("base", arg)) {
		sec->mapscope = LDAP_SCOPE_BASE;
	} else {
		return "illegal argument to AuthzLDAPMapScope";
	}
	return NULL;
}

static const char	*authz_ldap_set_loglevel_slot(cmd_parms *parms,
	void *mconfig, const char *arg) {
	authz_ldap_config_rec	*sec;
	sec = (authz_ldap_config_rec *)mconfig;

#if AUTHZ_LDAP_DEBUG
	fprintf(stderr, "%s:%d: setting loglevel at %p to '%s'\n",
		__FILE__, __LINE__, (void *)sec, (arg) ? arg : "(null)");
#endif
	/* check for the various possible legal values of the argument	*/
	if (0 == strcasecmp("emerg", arg)) {
		sec->loglevel = APLOG_EMERG; return NULL;
	}
	if (0 == strcasecmp("alert", arg)) {
		sec->loglevel = APLOG_ALERT; return NULL;
	}
	if (0 == strcasecmp("crit", arg)) {
		sec->loglevel = APLOG_CRIT; return NULL;
	}
	if (0 == strcasecmp("error", arg)) {
		sec->loglevel = APLOG_ERR; return NULL;
	}
	if (0 == strcasecmp("warn", arg)) {
		sec->loglevel = APLOG_WARNING; return NULL;
	}
	if (0 == strcasecmp("notice", arg)) {
		sec->loglevel = APLOG_NOTICE; return NULL;
	}
	if (0 == strcasecmp("info", arg)) {
		sec->loglevel = APLOG_INFO; return NULL;
	}
	if (0 == strcasecmp("debug", arg)) {
		sec->loglevel = APLOG_DEBUG; return NULL;
	}
	return "illegal argument to AuthzLDAPLogLevel";
}

#ifdef HAVE_LDAP_ENABLE_CACHE
/*
 * This part of the code implements the configuration parameters for
 * the LDAP cache, and is only compiled into the code if the library
 * implements the ldap_enable_cache function.
 */

/* read the cache timeout from the configuration			*/
static const char	*authz_ldap_set_timeout_slot(cmd_parms *parms,
	void *mconfig, const char *arg) {
	authz_ldap_config_rec	*sec;
	sec = (authz_ldap_config_rec *)mconfig;

#if AUTHZ_LDAP_DEBUG
	fprintf(stderr, "%s:%d: setting timeout at %p to '%s'\n",
		__FILE__, __LINE__, (void *)sec, (arg) ? arg : "(null)");
#endif

	sec->timeout = atoi(arg);
	if ((sec->timeout < 0) || (sec->timeout > 86400)) {
		ap_log_error(APLOG_MARK, APLOG_ERR, APLOG_STATUS parms->server,
			"[%d] illegal LDAP cache timeout: %d, using default %d",
			(int)getpid(), sec->timeout,
			AUTHZ_DEFAULT_CACHE_TIMEOUT);
		sec->timeout = AUTHZ_DEFAULT_CACHE_TIMEOUT;
	}
	return NULL;
}

/* read the cache size from the configuration				*/
static const char	*authz_ldap_set_cachesize_slot(cmd_parms *parms,
	void *mconfig, const char *arg) {
	authz_ldap_config_rec	*sec;
	sec = (authz_ldap_config_rec *)mconfig;

#if AUTHZ_LDAP_DEBUG
	fprintf(stderr, "%s:%d: setting cachesize at %p to '%s'\n",
		__FILE__, __LINE__, (void *)sec, (arg) ? arg : "(null)");
#endif

	sec->cachesize = atoi(arg);
	if ((sec->cachesize < 0) || (sec->cachesize > AUTHZ_MAX_CACHE_SIZE)) {
		ap_log_error(APLOG_MARK, APLOG_ERR, APLOG_STATUS parms->server,
			"[%d] illegal LDAP cache size: %d, cache disabled",
			(int)getpid(), sec->cachesize);
		sec->cachesize = 0;
	}
	return NULL;
}

#endif /* HAVE_LDAP_ENABLE_CACHE */

static const char	*authz_ldap_set_version_slot(cmd_parms *parms,
	void *mconfig, const char *arg) {
	authz_ldap_config_rec	*sec;
	sec = (authz_ldap_config_rec *)mconfig;

#if AUTHZ_LDAP_DEBUG
	fprintf(stderr, "%s:%d: setting ldap version at %p to '%s'\n",
		__FILE__, __LINE__, (void *)sec, (arg) ? arg : "(null)");
#endif

	sec->ldapversion = atoi(arg);
	if (0 == sec->ldapversion) {
		ap_log_error(APLOG_MARK, APLOG_WARNING,
			APLOG_STATUS parms->server,
			"[%d] version cannot be set: %s", (int)getpid(),
			arg);
	}
	return NULL;
}

static const char	*authz_ldap_set_method_slot(cmd_parms *parms,
	void *mconfig, const char *arg){
	authz_ldap_config_rec	*sec;
	sec = (authz_ldap_config_rec *)mconfig;

#if AUTHZ_LDAP_DEBUG
	fprintf(stderr, "%s:%d: setting auth method at %p to '%s'\n",
		__FILE__, __LINE__, (void *)sec, (arg) ? arg : "(null)");
#endif

	sec->method = AUTHMETHOD_NONE;
	if (0 == strcasecmp(arg, "certificate")) {
		sec->method = AUTHMETHOD_CERT;
		return NULL;
	}
	if (0 == strcasecmp(arg, "ldap")) {
		sec->method = AUTHMETHOD_LDAP;
		sec->bindmapped = 0;
		return NULL;
	}
	if (0 == strcasecmp(arg, "ldapmapped")) {
		sec->method = AUTHMETHOD_LDAP;
		sec->bindmapped = 1;
		return NULL;
	}
	if (0 == strcasecmp(arg, "both")) {
		sec->method = AUTHMETHOD_BOTH;
		return NULL;
	}
	return "unknown authentication method";
}

static const char	*authz_ldap_set_mapmethod_slot(cmd_parms *parms,
	void *mconfig, const char *arg) {
	authz_ldap_config_rec	*sec;
	sec = (authz_ldap_config_rec *)mconfig;

#if AUTHZ_LDAP_DEBUG
	fprintf(stderr, "%s:%d: setting map method at %p to '%s'\n",
		__FILE__, __LINE__, (void *)sec, (arg) ? arg : "(null)");
#endif

	sec->mapmethod = AUTHMAPMETHOD_NONE;
	if (0 == strcasecmp(arg, "certificate")) {
		sec->mapmethod = AUTHMAPMETHOD_CERTIFICATE;
		return NULL;
	}
	if (0 == strcasecmp(arg, "issuerserial")) {
		sec->mapmethod = AUTHMAPMETHOD_ISSUERSERIAL;
		return NULL;
	}
	if (0 == strcasecmp(arg, "issuersubject")) {
		sec->mapmethod = AUTHMAPMETHOD_ISSUERSUBJECT;
		return NULL;
	}
	if (0 == strcasecmp(arg, "ad")) {
		sec->mapmethod = AUTHMAPMETHOD_AD;
		return NULL;
	}
	return "unknown certificate mapping method";
}

static const char	*authz_ldap_set_setauth_slot(cmd_parms *parms,
	void *mconfig, const char *arg) {
	authz_ldap_config_rec	*sec;
	sec = (authz_ldap_config_rec *)mconfig;

#if AUTHZ_LDAP_DEBUG
	fprintf(stderr, "%s:%d: setting authoriziation header at %p to '%s'\n",
		__FILE__, __LINE__, (void *)sec, (arg) ? arg : "(null)");
#endif

	sec->setauth = AUTHHEADER_NONE;
	if (NULL != strstr(arg, "+password")) {
		sec->setauth |= AUTHHEADER_PASSWORD;
#if AUTHZ_LDAP_DEBUG
		fprintf(stderr, "%s:%d: password requested\n",
			__FILE__, __LINE__);
#endif
	}
	if (0 == strncasecmp(arg, "user", 4)) {
		sec->setauth |= AUTHHEADER_USER;
		return NULL;
	}
	if (0 == strncasecmp(arg, "ldapdn", 6)) {
		sec->setauth |= AUTHHEADER_LDAPDN;
		return NULL;
	}
	if (0 == strncasecmp(arg, "subject", 7)) {
		sec->setauth |= AUTHHEADER_SUBJECT;
		return NULL;
	}
	if (0 == strncasecmp(arg, "map", 3)) {
		sec->setauth |= AUTHHEADER_MAP;
		return NULL;
	}
	return "unknown authorization header field combination";
}

static const char	*authz_ldap_set_setgroup_slot(cmd_parms *parms,
	void *mconfig, const char *arg) {
	authz_ldap_config_rec   *sec;
	sec = (authz_ldap_config_rec *)mconfig;
	
#if AUTHZ_LDAP_DEBUG
	fprintf(stderr, "%s:%d: setting group attribute at %p to '%s'\n",
		__FILE__, __LINE__, (void *)sec, (arg) ? arg : "(null)");
#endif	 

	sec->setgroup = AUTHHEADER_USER;
	
	if (0 == strncasecmp(arg, "user", 4)) {
		sec->setgroup = AUTHHEADER_USER;
		return NULL;
	}       
	if (0 == strncasecmp(arg, "ldapdn", 6)) {
		sec->setgroup = AUTHHEADER_LDAPDN;
		return NULL;
	}       
	if (0 == strncasecmp(arg, "subject", 7)) {
		sec->setgroup = AUTHHEADER_SUBJECT;
		return NULL;
	}       
	if (0 == strncasecmp(arg, "map", 3)) {
		sec->setgroup = AUTHHEADER_MAP;
		return NULL;
	}       
	return "unknown group attribute field combination";
}

/* Configuration Directives for this module				*/
const command_rec	authz_ldap_cmds[] = {
	/* whether or not to be active at all!				*/
	AP_INIT_TAKE1(
		"AuthzLDAPMethod", authz_ldap_set_method_slot,
		(void *)APR_OFFSETOF(authz_ldap_config_rec, method),
		OR_AUTHCFG,
		"Select authentication method to use, also enables "
		"mod_authz_ldap. Valid arguments are `ldap', `certificate' "
		"and `both'."
	),
	AP_INIT_TAKE1(
		"AuthzLDAPMapMethod", authz_ldap_set_mapmethod_slot,
		(void *)APR_OFFSETOF(authz_ldap_config_rec, method),
		OR_AUTHCFG,
		"Select certificate mapping method, also enables certificate "
		"mapping. Valid arguments are `certificate', `issuerserial', "
		"`issuersubject' and `ad' (for active directory)"
	),
	AP_INIT_FLAG(
		"AuthzLDAPCacheConnection", ap_set_flag_slot,
		(void *)APR_OFFSETOF(authz_ldap_config_rec, cacheconnection),
		OR_AUTHCFG,
		"Set to 'on' if mod_authz_ldap should cache the connection "
		"to the directory"
	),
	/* User settings						*/
	AP_INIT_TAKE1(
		"AuthzLDAPServer", ap_set_string_slot,
		(void *)APR_OFFSETOF(authz_ldap_config_rec, server),
		OR_AUTHCFG,
		"Name of LDAP Server that should be queried"
	),
	AP_INIT_TAKE1(
		"AuthzLDAPBindDN", ap_set_string_slot,
		(void *)APR_OFFSETOF(authz_ldap_config_rec, binddn),
		OR_AUTHCFG,
		"DN as which to bind to the LDAP directory"
	),
	AP_INIT_TAKE1(
		"AuthzLDAPBindPassword", ap_set_string_slot,
		(void *)APR_OFFSETOF(authz_ldap_config_rec, bindpw),
		OR_AUTHCFG,
		"The password to use when binding to the directory"
	),
	AP_INIT_TAKE1(
		"AuthzLDAPProtocolVersion", authz_ldap_set_version_slot,
		(void *)APR_OFFSETOF(authz_ldap_config_rec, ldapversion),
		OR_AUTHCFG,
		"The version of the LDAP protocol to use to connect to the "
		"directory"
	),

	/* User settings						*/
	AP_INIT_TAKE1(
		"AuthzLDAPUserKey", ap_set_string_slot,
		(void *)APR_OFFSETOF(authz_ldap_config_rec, userkey),
		OR_AUTHCFG,
		"The attribute name associated with the userid"
	),
	AP_INIT_TAKE1(
		"AuthzLDAPUserBase", ap_set_string_slot,
		(void *)APR_OFFSETOF(authz_ldap_config_rec, userbase),
		OR_AUTHCFG,
		"The DN of the node immediate above the users"
	),
	AP_INIT_TAKE1(
		"AuthzLDAPUserScope", authz_ldap_set_user_scope_slot, NULL,
		OR_AUTHCFG,
		"the scope for a search for the user: subtree, onelevel, base"
	),
	

	/* Group membership settings					*/
	AP_INIT_TAKE1(
		"AuthzLDAPGroupBase", ap_set_string_slot,
		(void *)APR_OFFSETOF(authz_ldap_config_rec, groupbase),
		OR_AUTHCFG,
		"Base DN for searches for groups"
	),
	AP_INIT_TAKE1(
		"AuthzLDAPGroupKey", ap_set_string_slot,
		(void *)APR_OFFSETOF(authz_ldap_config_rec, groupkey),
		OR_AUTHCFG,
		"attribute name for groups"
	),
	AP_INIT_TAKE1(
		"AuthzLDAPGroupScope", authz_ldap_set_group_scope_slot, NULL,
		OR_AUTHCFG,
		"the scope for a search for the group: subtree, onelevel, base"
	),
	AP_INIT_TAKE1(
		"AuthzLDAPMemberKey", ap_set_string_slot,
		(void *)APR_OFFSETOF(authz_ldap_config_rec, memberkey),
		OR_AUTHCFG,
		"attribute name for group members"
	),

	/* X.509 certificate mapping					*/
	AP_INIT_FLAG(
		"AuthzLDAPAllowPassword", ap_set_flag_slot,
		(void *)APR_OFFSETOF(authz_ldap_config_rec, allowpasswd),
		OR_AUTHCFG,
		"Still allow password login if the user has no certificate"
	),
	AP_INIT_TAKE1(
		"AuthzLDAPMapBase", ap_set_string_slot,
		(void *)APR_OFFSETOF(authz_ldap_config_rec, mapbase),
		OR_AUTHCFG,
		"Where to start searching during a certificate lookup"
	),
	AP_INIT_TAKE1(
		"AuthzLDAPMapScope", authz_ldap_set_map_scope_slot, NULL,
		OR_AUTHCFG,
		"the scope for a search during the mapping of a X.509 "
			"certificate: subtree, onelevel, base"
	),
	AP_INIT_TAKE1(
		"AuthzLDAPSetAuthorization", authz_ldap_set_setauth_slot,
		(void *)APR_OFFSETOF(authz_ldap_config_rec, setauth),
		OR_AUTHCFG,
		"Specifies which fields in the authorization header should "
		"should be set to what values. Possible values are `user', "
		"`ldapdn', `subject', `map'. The password field is set to "
		"`password' unless `+password' is appended, in which case "
		"the user specified password is used"
	),

	AP_INIT_TAKE1(
		"AuthzLDAPSetGroupAuth", authz_ldap_set_setgroup_slot, 
		(void *)APR_OFFSETOF(authz_ldap_config_rec, setgroup),
		OR_AUTHCFG,
		"Spcifies which (mapped) username should be used to"
		"verify group membership. Possible values are `user', "
		"`ldapdn', `subject' and `map'"
	),

	/* mapping a user to any attribute 				*/
	AP_INIT_TAKE1(
		"AuthzLDAPMapUserToAttr", ap_set_string_slot,
		(void *)APR_OFFSETOF(authz_ldap_config_rec, mapusertoattr),
		OR_AUTHCFG,
		"attribute name that contains the name to be used for the user"
	),

	/* name of attribute containing role names			*/
	AP_INIT_TAKE1(
		"AuthzLDAPRoleAttributeName", ap_set_string_slot,
		(void *)APR_OFFSETOF(authz_ldap_config_rec, roleattrname),
		OR_AUTHCFG,
		"Name of attribute containing role designations"
	),

	/* Password aging mechanisms					*/
	AP_INIT_TAKE1(
		"AuthzLDAPModifyKey", ap_set_string_slot,
		(void *)APR_OFFSETOF(authz_ldap_config_rec, modifykey),
		OR_AUTHCFG,
		"Key to look for when trying to check for the last modification"
	),

#ifdef HAVE_LDAP_ENABLE_CACHE
	/* LDAP cache size						*/
	AP_INIT_TAKE1(
		"AuthzLDAPCacheTimeout", authz_ldap_set_timeout_slot,
		(void *)APR_OFFSETOF(authz_ldap_config_rec, timeout),
		OR_AUTHCFG,
		"Timout for entries in the LDAP cache in seconds, default 600, "
		"i.e. 10 minutes"
	),
	AP_INIT_TAKE1(
		"AuthzLDAPCacheSize", authz_ldap_set_cachesize_slot,
		(void *)APR_OFFSETOF(authz_ldap_config_rec, cachesize),
		OR_AUTHCFG,
		"Size of the LDAP cache, default 0, i.e. no caching"
	),
#endif /* HAVE_LDAP_ENABLE_CACHE */

	/* general variables						*/
	AP_INIT_FLAG(
		"AuthzLDAPAuthoritative", ap_set_flag_slot,
		(void *)APR_OFFSETOF(authz_ldap_config_rec, authoritative),
		OR_AUTHCFG,
		"Set to 'off' if you want to hand authentication to some "
			"other authentication handler further down"
	),
	AP_INIT_FLAG(
		"AuthzLDAPProxyAuthentication", ap_set_flag_slot,
		(void *)APR_OFFSETOF(authz_ldap_config_rec, proxyauth),
		OR_AUTHCFG,
		"Set to 'on' if proxy authentication is happening here"
	),
	AP_INIT_TAKE1(
		"AuthzLDAPLogLevel", authz_ldap_set_loglevel_slot,
		(void *)APR_OFFSETOF(authz_ldap_config_rec, loglevel),
		OR_AUTHCFG,
		"limit the debug information from the module"
	),

	{ NULL }
};

/* initialize a directory configuration record				*/
void	*authz_ldap_create_dir_config(apr_pool_t *p, char *d) {
	authz_ldap_config_rec	*sec
		= (authz_ldap_config_rec *)ap_palloc(p,
			sizeof(authz_ldap_config_rec));
#if AUTHZ_LDAP_DEBUG
	fprintf(stderr, "%s:%d: initializing dir config record at %p\n",
		__FILE__, __LINE__, (void *)sec);
#endif
	if (sec) {
		/* don't be active/caching connections by default	*/
		sec->method = AUTHMETHOD_NONE;
		sec->mapmethod = AUTHMAPMETHOD_NONE;
		sec->cacheconnection = 0;

		/* global configuration information			*/
		sec->server = NULL;
		sec->binddn = NULL;
		sec->bindpw = NULL;
#ifdef LDAP_VERSION3
		sec->ldapversion = LDAP_VERSION3;
#else
		sec->ldapversion = 0;	/* by default, don't set the	*/
					/* protocol version		*/
#endif

		/* user configuration					*/
		sec->userbase = NULL;
		sec->userkey = NULL;
		sec->userscope = LDAP_SCOPE_BASE;

		/* group configuration					*/
		sec->groupbase = NULL;
		sec->groupkey = NULL;
		sec->groupscope = LDAP_SCOPE_BASE;
		sec->memberkey = NULL;

		/* X.509 certificate mapping				*/
		sec->allowpasswd = 0;
		sec->mapbase = NULL;
		sec->mapscope = LDAP_SCOPE_SUBTREE;

		/* authorization header setting				*/
		sec->setauth = AUTHHEADER_NONE;
		sec->setgroup = AUTHHEADER_USER;

		/* map the user to some other attribute			*/
		sec->mapusertoattr = NULL;

		/* role attribute name					*/
		sec->roleattrname = NULL;

		/* password aging					*/
		sec->modifykey = NULL;

#ifdef HAVE_LDAP_ENABLE_CACHE
		/* LDAP cache						*/
		sec->timeout = AUTHZ_DEFAULT_CACHE_TIMEOUT;
		sec->cachesize = 0;	/* disabled by default		*/
#endif /* HAVE_LDAP_ENABLE_CACHE */

		/* generic configuration				*/
		sec->authoritative = 1;
		sec->proxyauth = AUTHZ_AUTO;
		sec->loglevel = APLOG_DEBUG;

		/* private data						*/
		sec->ldap = NULL;
	}
	return sec;
}

/* directory configuration merger					*/
#define	authz_ldap_link(f)	do {					\
		if ((parent->f) && (!child->f)) child->f = parent->f;	\
	} while (0)
void	*authz_ldap_merge_dir_config(apr_pool_t *p, void *pp, void *cp) {
	authz_ldap_config_rec	*parent = (authz_ldap_config_rec *)pp;
	authz_ldap_config_rec	*child = (authz_ldap_config_rec *)cp;
#ifdef AUTHZ_LDAP_DEBUG	
	fprintf(stderr, "%s:%d: merging from %p to %p\n",
		__FILE__, __LINE__, pp, cp);
#endif
	
	/* all values that were not set in the child but are set in the	*/
	/* parent are linked						*/
	authz_ldap_link(server);
	authz_ldap_link(binddn);
	authz_ldap_link(bindpw);

	authz_ldap_link(userbase);
	authz_ldap_link(userkey);

	authz_ldap_link(groupbase);
	authz_ldap_link(groupkey);
	authz_ldap_link(memberkey);
	
	authz_ldap_link(mapbase);
	authz_ldap_link(mapusertoattr);

	/* connections possibly cached from previous calls should be	*/
	/* restored							*/
	authz_ldap_link(ldap);

	/* the integers cannot possibly be merged, as we cannot decide	*/
	/* from the values in the child structure whether they are 	*/
	/* defaults, or set by the parent				*/
	return child;
}

