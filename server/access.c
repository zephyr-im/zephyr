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
 */

/*
 * Each restricted class has two ACL's associated with it, one
 * governing subscriptions and one governing transmission.
 * This module provides the 'glue' between the standard Athena ACL
 * routines and the support needed by the Zephyr server.
 */

#include "zserver.h"			/* includes <sys/file.h> */
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
	(void) sprintf(buf, "%s%s-%s", 
		       ZEPHYR_ACL_DIR,
		       prefix,
		       acl->acl_filename);
	if (access(buf, F_OK))		/* no acl ==> no restriction
					   ==> thumbs up */
		return(1);
	return(acl_check(buf, notice->z_sender));
}
