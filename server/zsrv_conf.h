/* This file is part of the Project Athena Zephyr Notification System.
 * It contains site-specific definitions for use in the server.
 *
 *	Created by:	John T. Kohl
 *
 *	$Source$
 *	$Author$
 *	$Header$
 *
 *	Copyright (c) 1988 by the Massachusetts Institute of Technology.
 *	For copying and distribution information, see the file
 *	"mit-copyright.h". 
 */

#ifndef __ZSRV_CONF_H__
#define	__ZSRV_CONF_H__
#include <zephyr/mit-copyright.h>

/* Magic path names */
#ifndef HESIOD
#define SERVER_LIST_FILE	Z_LIBDIR "/server.list"
#endif /* !HESIOD */

/* ACL's for pre-registered classes */
/* Directory containing acls and other info */
#define	ZEPHYR_ACL_DIR		Z_LIBDIR "/"
/* name of the class registry */
#define	ZEPHYR_CLASS_REGISTRY	"class-registry.acl"

#ifdef KERBEROS
/* name of file to hold the tickets for keys to exchange with other servers */
#define	ZEPHYR_TKFILE		Z_LIBDIR "/ztkts"

/* pathname of Kerberos srvtab file */
#define SERVER_SRVTAB		Z_LIBDIR "/srvtab"
#endif

/* default subscription file */
#define	DEFAULT_SUBS_FILE	Z_LIBDIR "/default.subscriptions"

/* client defines */
#define	REXMIT_SECS	((long) 20)	/* rexmit delay on normal notices */
#define	NUM_REXMITS	(9)		/* number of rexmits */

/* hostmanager defines */
#define	LOSE_TIMO	(60)		/* time during which a losing host
					   must respond to a ping */

/* server-server defines */
#define	TIMO_UP		((long) 60)	/* timeout between up and tardy */
#define	TIMO_TARDY	((long) 120)	/* timeout btw tardy hellos */
#define	TIMO_DEAD	((long)(15*60))	/* timeout between hello's for dead */

#define	H_NUM_TARDY	5		/* num hello's before going dead
					   when tardy */
#define	H_NUM_STARTING	2		/* num hello's before going dead
					   when starting */
#endif /* __ZSRV_CONF_H__ */
