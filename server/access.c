/* This file is part of the Project Athena Zephyr Notification System.
 * It contains functions for dealing with acl's.
 *
 *	Created by:	John T. Kohl
 *
 *	$Source$
 *	$Author$
 *
 *	Copyright (c) 1987 by the Massachusetts Institute of Technology.
 *	For copying and distribution information, see the file
 *	"mit-copyright.h". 
 */

#include <zephyr/mit-copyright.h>

#if !defined (lint) && !defined (SABER)
static const char rcsid_access_c[] =
    "$Header$";
#endif

/*
 *
 * External routines:
 *
 * ZAcl_t::ok (ZString sender, ZAccess_t accesstype)
 *
 * void access_init();
 *
 * void access_reinit();
 */

/*
 * Each restricted class has four ACL's associated with it,
 * governing subscriptions, transmission, and instance restrictions.
 * This module provides the 'glue' between the standard Athena ACL
 * routines and the support needed by the Zephyr server.
 */

#include <sys/param.h>

#include "zserver.h"

/*
 * Our private types for the acl_types field in the ZAcl_t structure.
 * 	-TYT 8/14/90
 */
#define ACL_XMT		1
#define ACL_SUB		2
#define ACL_IWS		4
#define ACL_IUI		8

/*
 * check access.  return 1 if ok, 0 if not ok.
 */

int
ZAcl_t::ok (ZString sender, ZAccess_t accesstype)
{
	char buf[MAXPATHLEN];		/* holds the real acl name */
	char *prefix;
	int	flag;

	switch (accesstype) {
	case TRANSMIT:
		prefix = "xmt";
		flag = ACL_XMT;
		break;
	case SUBSCRIBE:
		prefix = "sub";
		flag = ACL_SUB;
		break;
	case INSTWILD:
		prefix = "iws";
		flag = ACL_IWS;
		break;
	case INSTUID:
		prefix = "iui";
		flag = ACL_IUI;
		break;
	default:
		syslog(LOG_ERR, "unknown access type %d", (int) accesstype);
		return(0);
	}
	if (!acl_types & flag) /* no acl ==> no restriction
				        ==> thumbs up */
		return (1);
	(void) sprintf(buf, "%s%s-%s.acl", 
		       ZEPHYR_ACL_DIR,
		       prefix,
		       acl_filename);
	/*
	 * If we can't load it (because it probably doesn't exist),
	 * we grant access by default.  Dangerous!
	 */
#if 0
	zdbug ((LOG_DEBUG, "checking %s for %s", buf, sender.value ()));
#endif
	return (acl_load (buf) < 0
		|| acl_check(buf, sender.value ()));
}

void ZAcl_t::check_acl_type (ZAccess_t accesstype, int typeflag)
{
	char 	buf[MAXPATHLEN];		/* holds the real acl name */
	char	*prefix;

	switch (accesstype) {
	case TRANSMIT:
		prefix = "xmt";
		break;
	case SUBSCRIBE:
		prefix = "sub";
		break;
	case INSTWILD:
		prefix = "iws";
		break;
	case INSTUID:
		prefix = "iui";
		break;
	default:
		syslog(LOG_ERR, "unknown access type %d", (int) accesstype);
		return;
	}
	(void) sprintf(buf, "%s%s-%s.acl", 
		       ZEPHYR_ACL_DIR,
		       prefix,
		       acl_filename);
	if (!access(buf, F_OK))
		acl_types |= typeflag;
}

void ZAcl_t::check () {
    acl_types = 0;
    check_acl_type (TRANSMIT, ACL_XMT);
    check_acl_type (SUBSCRIBE, ACL_SUB);
    check_acl_type (INSTWILD, ACL_IWS);
    check_acl_type (INSTUID, ACL_IUI);
}

/*
 * Re-init code written by TYT, 8/14/90.
 *
 * General plan of action; we reread the registry list, and add any
 * new restricted classes.  If any restricted classes disappear (this
 * should be rarely) the ZAcl_t structure is not deallocated; rather,
 * the acl_types field will be left at zero, since there will be no
 * acl files for the (non-)restricted class.
 */

static void
access_setup (int first)
{
	char buf[MAXPATHLEN];
	char class_name[512];		/* assume class names <= 511 bytes */
	FILE *registry;
	ZAcl_t *acl;
	register int len;
	register char *colon_idx;
	Code_t retval = 0;

	(void) sprintf(buf, "%s%s", ZEPHYR_ACL_DIR, ZEPHYR_CLASS_REGISTRY);
	
	if ((registry = fopen(buf, "r")) == (FILE *) NULL) {
		syslog(LOG_ERR, "no registry available, all classes are free");
		return;
	}
	while (fgets(class_name, 512, registry) != NULL) {
		if (colon_idx = index(class_name, ':'))
		    *colon_idx = '\0';
		else if (len = strlen(class_name))
		    class_name[len - 1] = '\0';
		acl = 0;
		if (!first)
		    acl = class_get_acl (ZString (class_name, 1));
		if (!acl) {
		    acl = new ZAcl_t (class_name);
		    if (!acl) {
			syslog(LOG_ERR, "no mem acl alloc");
			abort();
		    }
		    if (!first) {
			/* Try to restrict already existing class */
			retval = class_restrict (class_name, acl);
			if (retval == ZSRV_NOCLASS)
			    retval = class_setup_restricted (class_name, acl);
		    }
		    else
			retval = class_setup_restricted (class_name, acl);
		}
		if (retval) {
		    syslog(LOG_ERR, "can't restrict %s: %s",
			   class_name, error_message(retval));
		    continue;
		}
#if 1
		else if (zdebug)
		    syslog(LOG_DEBUG, "restricted %s", class_name);
#endif
	}
	(void) fclose(registry);

	return;
}

void
access_init (void)
{
    access_setup (1);
}

void
access_reinit (void)
{
    acl_cache_reset ();
    access_setup (0);
}
