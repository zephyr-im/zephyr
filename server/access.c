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
static char rcsid_acl_s_c[] = "$Header$";
#endif lint

/*
 *
 * External routines:
 *
 * int access_check(notice, acltype)
 *	ZNotice_t *notice;
 *	ZAclType acltype;
 */

#include "zserver.h"

/*
 * check access.  return 1 if ok, 0 if not ok.
 */

int
access_check(notice, acltype)
ZNotice_t *notice;
ZAclType acltype;
{
	return(1);
}
