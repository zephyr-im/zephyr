/* This file is part of the Project Athena Zephyr Notification System.
 * It contains configuration definitions.
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

#ifndef __ZEPHYR_CONF_H__
#define __ZEPHYR_CONF_H__

#include <zephyr/mit-copyright.h>

/* Kerberos information */
/* If you are not using Kerberos, comment out the following three lines.
   These provide default definitions so that users compiling Zephyr
   programs don't need to put -DKERBEROS on their compile lines. */
#ifndef KERBEROS
#define KERBEROS
#endif

#define SERVER_SERVICE		"zephyr"
#define SERVER_INSTANCE		"zephyr"
#define SERVER_SRVTAB		"/usr/athena/lib/zephyr/srvtab"

/* General filenames */
#define DEFAULT_VARS_FILE	"/etc/athena/zephyr.vars"

/* Service names */
#define	HM_SVCNAME	"zephyr-hm"
#define	SERVER_SVCNAME	"zephyr-clt"

#ifdef ultrix
/* If you are using Ultrix versions prior to 3.0, uncomment the following
   three lines  so that users don't need to specify -DULTRIX22 on their
   compile lines. */
/* #ifndef ULTRIX22 */
/* #define ULTRIX22 */
/* #endif */
#endif /* ultrix */

#if defined(ultrix) && defined(ULTRIX22)
/* Ultrix 3.0 and beyond have these defined in standard places */
/* Ultrix 2.2 and previous don't have these defined */
#define	MAXHOSTNAMELEN	64
typedef int uid_t;
typedef int gid_t;
#ifndef KERBEROS
#define FD_ZERO(p)  ((p)->fds_bits[0] = 0)
#define FD_SET(n, p)   ((p)->fds_bits[0] |= (1 << (n)))
#define FD_ISSET(n, p)   ((p)->fds_bits[0] & (1 << (n)))
#endif /* KERBEROS */
#define	FD_CLR(n, p)	((p)->fds_bits[0] &= ~(1 << (n)))
#endif /* ultrix */

#ifndef KERBEROS
#define	REALM_SZ	MAXHOSTNAMELEN
#define	INST_SZ		0		/* no instances w/o Kerberos */
#define	ANAME_SZ	9		/* size of a username + null */
#define	KRB_REALM	"ATHENA.MIT.EDU" /* your local "realm" */
#endif /* !KERBEROS */

#endif /* __ZEPHYR_CONF_H__ */
