/* This file is part of the Project Athena Zephyr Notification System.
 * It contains site-specific definitions for use in the server.
 *
 *	Created by:	John T. Kohl
 *
 *	$Id$
 *
 *	Copyright (c) 1988 by the Massachusetts Institute of Technology.
 *	For copying and distribution information, see the file
 *	"mit-copyright.h". 
 */

#ifndef __ZSRV_CONF_H__
#define	__ZSRV_CONF_H__
#include <zephyr/mit-copyright.h>

/* Path names are relative to CONFDIR, except for the class registry. */

#define SERVER_LIST_FILE	"server.list"
#define REALM_LIST_FILE		"realm.list"
#ifdef HAVE_KRB4
#define ZEPHYR_SRVTAB		"srvtab"
#define ZEPHYR_TKFILE		"ztkts"
#endif
#define	ZEPHYR_ACL_DIR		"acl/"
#define	ZEPHYR_CLASS_REGISTRY	"class-registry.acl"
#define	DEFAULT_SUBS_FILE	"default.subscriptions"

#define REXMIT_TIMES { 2, 2, 4, 4, 8, 8, 16, 32, 64, 128, 256, 512, -1 }
#define NUM_REXMIT_TIMES 12
#define CLIENT_GIVEUP_MIN 512

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

#define SWEEP_INTERVAL  3600		/* Time between sweeps of the ticket
					   hash table */

#endif /* __ZSRV_CONF_H__ */
