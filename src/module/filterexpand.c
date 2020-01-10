/*
 * filterexpand.c -- replace certain strings in the filter by information
 *                   retrieved from the system
 *
 * templates replaced:
 *  %t	current time in the form YYYYMMDDhhmmss
 *  %f	name of the requested file
 *  %r	remote ip address or name (as it appears in the apache log)
 *  %s	server name (so that we can define in LDAP which users have
 *	access to which hosts)
 *  %m  request method (GET, POST, PUT, HEAD, ...)
 *
 * (c) 2002 Dr. Andreas Mueller, Beratung und Entwicklung
 *
 * $Id: filterexpand.c,v 1.3 2002/10/06 19:01:16 afm Exp $
 */
#include <sys/types.h>
#include <stdlib.h>
#include <stdio.h>
#include "mod_authz_ldap.h"

char	*authz_ldap_filter_expand(request_rec *r, char *outbuffer,
		size_t buffersize, const char *filter) {
	time_t			now;
	char			workarea[1024];
	const char		*inp;
	int			outi;
	struct tm		*tp;
	authz_ldap_config_rec	*sec;

	/* get the configuration record from the request		*/
	sec = (authz_ldap_config_rec *)ap_get_module_config(r->per_dir_config,
		&authz_ldap_module);

#define	addstring(w)							\
	outi += snprintf(&outbuffer[outi], buffersize - outi, "%s", w)

	/* make sure our filter is defined                              */
	if (filter == NULL) {
		AUTHZ_DEBUG1("no filter defined");
		return NULL;
	}

	/* if the target buffer is no set, we cannot do anything either */
	if (outbuffer == NULL) {
		AUTHZ_DEBUG1("no output buffer");
		return NULL;
	}
	AUTHZ_DEBUG2("performing substitutions in filter '%s'",
		(filter) ? filter : "(null)");

	/* scan the the filter string, and for each occurence of %, 	*/
	/* add a replacement string					*/
	memset(outbuffer, 0, buffersize);
	outi = 0; inp = filter;

	while ((*inp) && (outi < (buffersize - 1))) {
		if (*inp != '%') {
			outbuffer[outi++] = *inp++;
		} else {
			inp++;
			AUTHZ_DEBUG2("found template %%%c", *inp);
			switch (*inp) {
			case '%':
				/* add a literal %			*/
				addstring("%");
				break;
			case 't':
				time(&now);
				tp = localtime(&now);
				strftime(workarea, sizeof(workarea),
					"%Y%m%d%H%M%S", tp);
				addstring(workarea);
				break;
			case 's':
				if (r->hostname)
					addstring(r->hostname);
				else
					addstring("unknown");
				break;
			case 'm':
				addstring(r->method);
				break;
			case 'r':
				addstring(AP_GET_REMOTE_HOST(r->connection,
					r->per_dir_config, REMOTE_NAME, NULL));
				break;
			case 'f':
				if (r->filename)
					addstring(r->filename);
				else
					addstring("unknown");
				break;
			default:
				AUTHZ_DEBUG2("unknown template: %c, "
					"replaced by empty string",  *inp);
				break;
			}
			inp++;
		}
	}
	AUTHZ_DEBUG2("filter substitutions give new filter '%s'", outbuffer);
	return outbuffer;
}

