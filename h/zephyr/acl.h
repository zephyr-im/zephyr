/* This file is part of the Project Athena Zephyr Notification System.
 * It contains definitions for the ACL library
 *
 *	Created by:	John T. Kohl
 *
 *	$Source$
 *	$Author$
 *	$Header$
 *
 *	Copyright (c) 1987 by the Massachusetts Institute of Technology.
 *	For copying and distribution information, see the file
 *	"mit-copyright.h". 
 */

#include <zephyr/mit-copyright.h>

#ifndef	__ACL__
#define	__ACL__
#if defined(__STDC_)
    extern int acl_add ( char *,  char *);
    extern int acl_check ( char *,  char *);
    extern int acl_delete ( char *,  char *);
    extern int acl_initialize ( char *, int);
#else /* not STDC */
extern int acl_check(), acl_add(), acl_delete(), acl_initialize();
#endif
#endif /* __ACL__ */
