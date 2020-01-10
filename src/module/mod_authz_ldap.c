/* 
**  mod_authz_ldap.c -- Apache LDAP authorization module
**
**  Read the files README and mod_authz_ldap.html for instructions on
**  configuring the module. Details of the license can be found in the
**  HTML documentation.
**
**  (c) 2000 Dr. Andreas Mueller
**
**  $Id: mod_authz_ldap.c,v 1.3 2002/10/10 08:36:05 afm Exp $
*/ 

/*
 * MODULE-DEFINITION-START
 * Name: authz_ldap_module
 * ConfigStart
   LDAP_LIBS="-lldap -llber"
   LIBS="$LIBS $LDAP_LIBS"
   echo "      + using LDAP libraries for authz_ldap module"
 * ConfigEnd
 * MODULE-DEFINITION-END
 */
#include "mod_authz_ldap.h"

/*************************************************************************
** Module Record							**
*************************************************************************/

/* Dispatch list for API hooks */
#ifndef STANDARD20_MODULE_STUFF
module MODULE_VAR_EXPORT authz_ldap_module = {
    STANDARD_MODULE_STUFF, 
    NULL,                  /* module initializer                  */
    authz_ldap_create_dir_config,
                           /* create per-dir    config structures */
    authz_ldap_merge_dir_config,
			   /* merge  per-dir    config structures */
    NULL,                  /* create per-server config structures */
    NULL,                  /* merge  per-server config structures */
    authz_ldap_cmds,       /* table of config file commands       */
    authz_ldap_handlers,   /* [#8] MIME-typed-dispatched handlers */
    NULL,                  /* [#1] URI to filename translation    */
    authz_ldap_auth,       /* [#4] validate user id from request  */
    authz_ldap_authz,      /* [#5] check if the user is ok _here_ */
    NULL,                  /* [#3] check access by host address   */
    NULL,                  /* [#6] determine MIME type            */
    NULL,                  /* [#7] pre-run fixups                 */
    NULL,                  /* [#9] log a transaction              */
    NULL,                  /* [#2] header parser                  */
    NULL,                  /* child_init                          */
    NULL,                  /* child_exit                          */
    NULL                   /* [#0] post read-request              */
#ifdef EAPI
   ,NULL,                  /* EAPI: add_module                    */
    NULL,                  /* EAPI: remove_module                 */
    NULL,                  /* EAPI: rewrite_command               */
    NULL                   /* EAPI: new_connection                */
#endif
};
#else /* STANDARD20_MODULE_STUFF */
static void	authz_ldap_register_hooks(apr_pool_t *p) {
	static const char	*aszPre[] = { "mod_ssl.c", NULL };
	static const char	*aszSucc[] = { "mod_auth.c", NULL };
	ap_hook_check_user_id(authz_ldap_auth, aszPre, aszSucc,
		APR_HOOK_MIDDLE);
	ap_hook_auth_checker(authz_ldap_authz, aszPre, aszSucc,
		APR_HOOK_MIDDLE);
}

module AP_MODULE_DECLARE_DATA authz_ldap_module = {
    STANDARD20_MODULE_STUFF, 
    authz_ldap_create_dir_config,
                           /* create per-dir    config structures */
    authz_ldap_merge_dir_config,
			   /* merge  per-dir    config structures */
    NULL,                  /* create per-server config structures */
    NULL,                  /* merge  per-server config structures */
    authz_ldap_cmds,       /* table of config file commands       */
    authz_ldap_register_hooks	   /* register hooks for auth and authz	  */
};
#endif /* STANDARD20_MODULE_STUFF */

