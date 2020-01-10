/*
 * mod_authz_ldap.h -- Apache authorization common definitions
 *
 * (c) 2001 Dr. Andreas Mueller, Beratung und Entwicklung
 *
 * $Id: mod_authz_ldap.h,v 1.13 2004/03/31 05:15:38 afm Exp $
 */
#ifndef _MOD_AUTHZ_LDAP_H
#define _MOD_AUTHZ_LDAP_H

#include "httpd.h"
#include "http_config.h"
#include "http_protocol.h"
#include "http_core.h"
#include "http_request.h"
#include "ap_config.h"
#include "ap_compat.h"
#ifdef AP_SERVER_MAJORVERSION
#include "apr_compat.h"
#endif /* AP_SERVER_MAJORVERSION */
#include "http_log.h"
#include "../authz.h"
#ifdef HAVE_LBER_H
#include <lber.h>
#endif
#ifdef HAVE_LDAP_H
#include <ldap.h>
#endif
#ifdef HAVE_SYS_TIMES_H
#include <sys/times.h>
#endif
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#ifdef HAVE_CTYPE_H
#include <ctype.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif

#ifndef HAVE_BER_FREE
#define	ber_free	free
#endif
#ifndef HAVE_LDAP_MSGFREE
#define ldap_msgfree	free
#endif
#ifndef HAVE_LDAP_MEMFREE
#define ldap_memfree	free
#endif

module	MODULE_VAR_EXPORT	authz_ldap_module;

#define	AUTHZ_AUTH	0
#define	AUTHZ_PROXY	1
#define	AUTHZ_AUTO	-1

#define AUTHMETHOD_NONE 0
#define	AUTHMETHOD_CERT	1
#define	AUTHMETHOD_LDAP	2
#define	AUTHMETHOD_BOTH	(AUTHMETHOD_CERT | AUTHMETHOD_LDAP)

#define	AUTHHEADER_NONE		0
#define	AUTHHEADER_PASSWORD	1 << 4
#define	AUTHHEADER_USER		1	/* default behavior, really */
#define	AUTHHEADER_LDAPDN	AUTHHEADER_USER << 1
#define	AUTHHEADER_SUBJECT	AUTHHEADER_LDAPDN << 1
#define	AUTHHEADER_MAP		AUTHHEADER_SUBJECT << 1

#define	AUTHMAPMETHOD_NONE		0
#define	AUTHMAPMETHOD_CERTIFICATE	1
#define	AUTHMAPMETHOD_ISSUERSERIAL	2
#define	AUTHMAPMETHOD_ISSUERSUBJECT	3
#define	AUTHMAPMETHOD_AD		4
#define	AUTHMAPMETHOD_NEEDSOWNER(s)	\
	((s == AUTHMAPMETHOD_ISSUERSERIAL) || \
	(s == AUTHMAPMETHOD_ISSUERSUBJECT))
#define	AUTHMAPMETHOD_RETURNSUSER(s)	\
	((s == AUTHMAPMETHOD_CERTIFICATE) || \
	(s == AUTHMAPMETHOD_AD))

#ifdef HAVE_LDAP_ENABLE_CACHE
/*
 * set the default values of the LDAP cache parameters, but only if they
 * have not been set by the 
 */
#ifndef AUTHZ_MAX_CACHE_SIZE
#define	AUTHZ_MAX_CACHE_SIZE	131072
#endif /* AUTHZ_MAX_CACHE_SIZE */

#ifndef	AUTHZ_DEFAULT_CACHE_TIMEOUT
#define	AUTHZ_DEFAULT_CACHE_TIMEOUT	600
#endif /* AUTHZ_DEFAULT_CACHE_TIMEOUT */

#endif /* HAVE_LDAP_ENABLE_CACHE */

typedef struct {
	/* whether or not to be active					*/
	int	method;		/* AuthzLDAPMethod			*/
	int	mapmethod;	/* AuthzLDAPMapMethod			*/
	int	cacheconnection;/* AuthzLDAPCacheConnection		*/

	/* server connections for ldap lookups				*/
	char	*server;	/* AuthzLDAPServer			*/
	char	*binddn;	/* AuthzLDAPBindDN			*/
	char	*bindpw;	/* AuthzLDAPBindPassword		*/
	int	ldapversion;	/* AuthzLDAPProtocolVersion		*/

	/* User settings						*/
	char	*userbase;	/* AuthzLDAPUserBase			*/
	char	*userkey;	/* AuthzLDAPUserKey			*/
	int	userscope;	/* AuthzLDAPUserScope			*/
	int	bindmapped;	/* set by AuthzLDAPMethod		*/

	/* Group membership settings					*/
	char	*groupbase;	/* AuthzLDAPGroupBase			*/
	char	*groupkey;	/* AuthzLDAPGroupKey			*/
	int	groupscope;	/* AuthzLDAPGroupScope			*/
	char	*memberkey;	/* AuthzLDAPMemberKey			*/

	/* X.509 Certifcate mapping					*/
	char	*mapbase;	/* AuthzLDAPMapBase			*/
	int	mapscope;	/* AuthzLDAPMapScope			*/
	char	*mapusertoattr;	/* AuthzLDAPMapUserToAttr		*/
	int	allowpasswd;	/* AuthzLDAPAllowPassword		*/

	/* setting authorization header					*/
	int	setauth;	/* AuthzLDAPSetAuthorization		*/
	int	setgroup;	/* AuthzLDAPSetGroup			*/
	char	*userpasswd;	/* AutzhLDAPUserPassword		*/

	/* name of role attribute					*/
	char	*roleattrname;	/* AuthzLDAPRoleAttributeName		*/

	/* Password aging						*/
	char	*modifykey;	/* AuthzLDAPModifyKey			*/

#ifdef HAVE_LDAP_ENABLE_CACHE
	/* LDAP cache size						*/
	int	timeout;	/* AuthzLDAPCacheTimeout		*/
	int	cachesize;	/* AuthzLDAPCacheSize			*/
#endif /* HAVE_LDAP_ENABLE_CACHE */

	/* general variables						*/
	int	authoritative;	/* AuthzLDAPAuthoritative		*/
	int	proxyauth;	/* AuthzLDAPProxyAuthentication		*/
	int	loglevel;	/* AuthzLDAPLogLevel			*/

	/* run time data structures per server process			*/
	LDAP	*ldap;		/* pointer to active ldap connection	*/
} authz_ldap_config_rec;

/*
 * The following macros serve to hide differences between Apache 1.3 and
 * Apache 2.0
 */
#ifdef AP_SERVER_MAJORVERSION
/* Apache 2 specific stuff */
#define	APLOG_STATUS	0,
#define USER(r)	r->user
#include <apr_strings.h>
#include <apr_base64.h>
#include <mod_ssl.h>
#define	AP_GET_REMOTE_HOST(a, b, c, d)	ap_get_remote_host(a, b, c, d)
#include <apr_hooks.h>
#ifdef AUTHZ_LDAP_HAVE_SSL
#include <openssl/pem.h>
#include <openssl/x509v3.h>
#endif /* AUTHZ_LDAP_HAVE_SSL */
#else /* AP_SERVER_MAJORVERSION */
/* Apache 1 specific stuff */
#define	apr_pool_t	pool
#define	apr_array_header_t	array_header
#define	apr_cpystrn	strncpy
#define	APLOG_STATUS
#define	USER(r) r->connection->user
#define	AP_INIT_FLAG(directive, function, what, where, comment)		\
	{ directive, function, what, where, FLAG, comment }
#define	AP_INIT_TAKE1(directive, function, what, where, comment)	\
	{ directive, function, what, where, TAKE1, comment }
#define	APR_OFFSETOF(a, b)	XtOffsetOf(a, b)
#define	AP_GET_REMOTE_HOST(a, b, c, d)	ap_get_remote_host(a, b, c)
#include <openssl/pem.h>
#include <openssl/x509v3.h>
#ifdef EAPI
#include <openssl/pem.h>
#include <openssl/x509v3.h>
extern char	*ssl_var_lookup(apr_pool_t *, server_rec *, conn_rec *,
			request_rec *, char *);
#ifndef AUTHZ_LDAP_HAVE_SSL
#define AUTHZ_LDAP_HAVE_SSL
#endif /* AUTHZ_LDAP_HAVE_SSL */
#endif /* EAPI */
#endif /* AP_SERVER_MAJORVERSION */

#define	AP_LOG_RERROR	if (sec->loglevel >= APLOG_DEBUG) ap_log_rerror
#if AUTHZ_LDAP_DEBUG
#define	AUTHZ_DEBUG1(a)							\
	if (sec->loglevel >= APLOG_DEBUG)				\
	ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG,		\
		APLOG_STATUS r, a)
#define	AUTHZ_DEBUG2(a, b)						\
	if (sec->loglevel >= APLOG_DEBUG)				\
	ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, 		\
		APLOG_STATUS r, a, b)
#define	AUTHZ_DEBUG3(a, b, c)						\
	if (sec->loglevel >= APLOG_DEBUG)				\
	ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG,		\
		APLOG_STATUS r, a, b, c)
#define	AUTHZ_DEBUG4(a, b, c, d)					\
	if (sec->loglevel >= APLOG_DEBUG)				\
	ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG,		\
		APLOG_STATUS r, a, b, c, d)
#define	AUTHZ_DEBUG5(a, b, c, d, e)					\
	if (sec->loglevel >= APLOG_DEBUG)				\
	ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG,		\
		APLOG_STATUS r, a, b, c, d, e)
#define	AUTHZ_DEBUG6(a, b, c, d, e, f)					\
	if (sec->loglevel >= APLOG_DEBUG)				\
	ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG,		\
		APLOG_STATUS r, a, b, c, d, e, f)
extern struct tms	starttms, endtms;
extern struct timeval	starttv, endtv;
#define	START_TIME							\
	do {								\
		times(&starttms);					\
		gettimeofday(&starttv, NULL);				\
	} while (0)
#define	END_TIME(a)							\
	do {								\
		times(&endtms);						\
		gettimeofday(&endtv, NULL);				\
		AP_LOG_RERROR(APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG,	\
			APLOG_STATUS r,					\
			"%s[%d]: elapsed time: %.0fms, cpu time: %.0fms",\
			a, (int)getpid(),				\
			((endtv.tv_sec - starttv.tv_sec) * 1.0e6	\
			+ (endtv.tv_usec - starttv.tv_usec)) / 1000.,	\
			10. * (endtms.tms_utime - starttms.tms_utime	\
			+ endtms.tms_stime - starttms.tms_stime));	\
	} while (0)
#else /* AUTHZ_LDAP_DEBUG */
#define	START_TIME
#define	END_TIME(a)
#define	AUTHZ_DEBUG1(a)
#define	AUTHZ_DEBUG2(a, b)
#define	AUTHZ_DEBUG3(a, b, c)
#define	AUTHZ_DEBUG4(a, b, c, d)
#define	AUTHZ_DEBUG5(a, b, c, d, e)
#define	AUTHZ_DEBUG6(a, b, c, d, e, f)
#endif /* AUTHZ_LDAP_DEBUG */

#define	AUTHZ_DECLINED							\
	(sec->authoritative) ? HTTP_UNAUTHORIZED : DECLINED
#define	AUTHZZ_DECLINED							\
	(sec->authoritative) ? HTTP_FORBIDDEN : DECLINED

extern const command_rec	authz_ldap_cmds[];
#ifndef AP_SERVER_MAJORVERSION
extern const handler_rec	authz_ldap_handlers[];
#endif /* AP_SERVER_MAJORVERSION */

/*************************************************************************
** declarations from modconf.c						**
*************************************************************************/

#ifdef HAVE_LDAP_ENABLE_CACHE
/* read the cache timeout from the configuration			*/
extern const char	*authz_ldap_set_timeout_slot(cmd_parms *parms,
	void *mconfig, const char *arg);
/* read the cache size from the configuration				*/
extern const char	*authz_ldap_set_cachesize_slot(cmd_parms *parms,
	void *mconfig, const char *arg);
#endif /* HAVE_LDAP_ENABLE_CACHE */

/* initialize a directory configuration record				*/
extern void	*authz_ldap_create_dir_config(apr_pool_t *p, char *d);
extern void	*authz_ldap_merge_dir_config(apr_pool_t *p, void *pp, void *cp);

/*************************************************************************
** declarations for utilities.c						**
*************************************************************************/

/*
 * Utility functions to handle the connection to the LDAP server
 *
 * authz_ldap_init	initialize the connection, but don't connect yet
 * authz_ldap_unbind	free the connection to the directory
 * authz_ldap_connect	connect to the directory, without binding
 * authz_ldap_reconnect	reestablish the connection to the directory
 * authz_ldap_search	actually perform a search
 */

/* utility function: connect to the ldap server when required		*/
extern LDAP	*authz_ldap_init(request_rec *r);
extern int	authz_ldap_unbind(LDAP *l);
extern int	authz_ldap_connect(request_rec *r);
extern int	authz_ldap_reconnect(request_rec *r);
extern int	authz_ldap_search(request_rec *r, char *base, int scope,
		const char *filter, char *attrs[], int attrsonly,
		LDAPMessage **res);

/*
 * utility functions to work with users
 *
 * authz_ldap_set_user_to_dn	set the authorization header to the user dn
 * authz_ldap_get_userdn	get the user's distinguished name
 * authz_ldap_get_username	get the user's short name
 * authz_ldap_set_userdn	save the user's distinguished name
 * authz_ldap_set_username	save the user's short name (the cn usually)
 */
extern void	authz_ldap_setauth(request_rec *r);
extern const char	*authz_ldap_get_username(request_rec *r);
extern const char	*authz_ldap_get_userdn(request_rec *r);
extern const char	*authz_ldap_get_mapped(request_rec *r);
extern const char	*authz_ldap_get_subject(request_rec *r);
extern const char	*authz_ldap_get_serial(request_rec *r);
extern const char	*authz_ldap_get_authorized(request_rec *r);
extern void	authz_ldap_set_username(request_rec *r, char *username);
extern void	authz_ldap_set_userdn(request_rec *r, char *userdn);
extern void	authz_ldap_set_mapped(request_rec *r, char *mapped);
extern void	authz_ldap_set_subject(request_rec *r, char *subject);
extern void	authz_ldap_set_serial(request_rec *r, char *serial);
extern void	authz_ldap_set_authorized(request_rec *r, char *authorized);
extern void	authz_ldap_copynotes(request_rec *r);
extern const char	*authz_ldap_get_user(request_rec *r, int nametype);

/*************************************************************************
** declarations for auth.c						**
*************************************************************************/

extern int	authz_ldap_authenticate(request_rec *r, const char *userdn);
extern int	authz_ldap_auth(request_rec *r);

/*************************************************************************
** declarations for authz.c						**
*************************************************************************/

extern int	authz_ldap_check_filter(request_rec *r, int scope,
		const char *filter);
extern int	authz_ldap_is_user(request_rec *r, const char *username);
extern int	authz_ldap_is_member(request_rec *r, const char *groupname);
extern int	authz_ldap_has_allroles(request_rec *r, const char **line);
extern int	authz_ldap_filter(request_rec *r, const char **line);
extern int	authz_ldap_owner(request_rec *r);
extern int	authz_ldap_groupowner(request_rec *r);
extern int	authz_ldap_authz(request_rec *r);

/*************************************************************************
** declarations for filterexpand.c					**
*************************************************************************/
extern char	*authz_ldap_filter_expand(request_rec *r, char *outbuffer,
			size_t buffersize, const char *filter);

/*************************************************************************
** declarations for age.c						**
*************************************************************************/
extern int	authz_ldap_age(request_rec *r, double age);

/*************************************************************************
** declarations for certmap.c						**
*************************************************************************/
extern int	authz_ldap_map_user(request_rec *r);
extern char	*authz_ldap_get_ms_user_principal_name(request_rec *r);
extern char	*authz_ldap_get_ms_x500_alt_security_identity(request_rec *r);

#endif /* _MOD_AUTHZ_LDAP_H */
