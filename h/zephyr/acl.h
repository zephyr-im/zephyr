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
#if defined(__STDC__) || defined(__cplusplus)
#ifdef __cplusplus
extern "C" {
#endif
    extern int acl_add (const char *, const char *);
    extern int acl_check (const char *, const char *);
    extern int acl_delete (const char *, const char *);
    extern int acl_initialize (const char *, int);
#ifdef __cplusplus
}
#endif
#else /* not STDC or C++ */
extern int acl_check(), acl_add(), acl_delete(), acl_initialize();
#endif
#endif /* __ACL__ */
