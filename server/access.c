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

#ifndef lint
#ifndef SABER
static char rcsid_acl_s_c[] = "$Header$";
#endif SABER
#endif lint

/*
 *
 * External routines:
 *
 * int access_check(notice, acl, accesstype)
 *	ZNotice_t *notice;
 *	ZAcl_t *acl;
 *	ZAccess_t accesstype;
 *
 * void access_init();
 */

/*
 * Each restricted class has four ACL's associated with it,
 * governing subscriptions, transmission, and instance restrictions.
 * This module provides the 'glue' between the standard Athena ACL
 * routines and the support needed by the Zephyr server.
 */

#include "zserver.h"			/* includes <sys/file.h>,
					 <strings.h> */
#include <sys/param.h>

/*
 * check access.  return 1 if ok, 0 if not ok.
 */

int
access_check(notice, acl, accesstype)
ZNotice_t *notice;
ZAcl_t *acl;
ZAccess_t accesstype;
{
	char buf[MAXPATHLEN];		/* holds the real acl name */
	char *prefix;

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
		return(0);
	}
	(void) sprintf(buf, "%s%s-%s.acl", 
		       ZEPHYR_ACL_DIR,
		       prefix,
		       acl->acl_filename);
	if (access(buf, F_OK))		/* no acl ==> no restriction
					   ==> thumbs up */
		return(1);
	return(acl_check(buf, notice->z_sender));
}

int
access_init()
{
	char buf[MAXPATHLEN];
	char class[512];		/* assume class names <= 511 bytes */
	FILE *registry;
	ZAcl_t *acl;
	register int len;
	register char *colon_idx;

	(void) sprintf(buf, "%s%s", ZEPHYR_ACL_DIR, ZEPHYR_CLASS_REGISTRY);
	
	if ((registry = fopen(buf, "r")) == (FILE *) NULL) {
		syslog(LOG_ERR, "no registry available, all classes are free");
		return;
	}
	while (fgets(class, 512, registry) != NULL) {
		if (colon_idx = index(class, ':'))
			*colon_idx = '\0';
		else if (len = strlen(class))
			class[len - 1] = '\0';
		acl = (ZAcl_t *) xmalloc(sizeof(ZAcl_t));
		if (!acl) {
			syslog(LOG_ERR, "no mem acl alloc");
			abort();
		}
		acl->acl_filename = strsave(class);
		(void) class_setup_restricted(class, acl);
		zdbug((LOG_DEBUG, "restricted %s by %s",
		       class, acl->acl_filename));
	}
	(void) fclose(registry);

	return;
}
