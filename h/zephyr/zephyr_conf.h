/* This file is part of the Project Athena Zephyr Notification System.
 * It contains configuration definitions.
 *
 *	Created by:	John T. Kohl
 *
 *	$Source$
 *	$Author$
 *	$Zephyr: /mit/zephyr/src/include/zephyr/RCS/zephyr_conf.h,v 1.8 90/12/21 17:40:40 raeburn Exp $
 *
 *	Copyright (c) 1988,1991 by the Massachusetts Institute of Technology.
 *	For copying and distribution information, see the file
 *	"mit-copyright.h". 
 */

#ifndef __ZEPHYR_CONF_H__
#define __ZEPHYR_CONF_H__

#include <zephyr/mit-copyright.h>
#include <zephyr/zephyr_paths.h>

#ifdef Z_HaveKerberos
#define SERVER_SERVICE		"zephyr"
#define SERVER_INSTANCE		"zephyr"
#define SERVER_SRVTAB		"/etc/athena/zephyr/srvtab"
#endif

/* General filenames */
#define DEFAULT_VARS_FILE	"/etc/athena/zephyr.vars"

/* Service names */
#define	HM_SVCNAME		"zephyr-hm"
#define	SERVER_SVCNAME		"zephyr-clt"

#if defined(vax) || defined(ibm032)
#define memset(a,b,c) bzero(a,c)
#define memmove(a,b,c) bcopy(b,a,c)
#define memcmp(a,b,c) bcmp(a,b,c)
#define strchr index
#define strrchr rindex
#endif

#ifdef SUNOS
extern char *sys_errlist[];

#ifndef memmove
#define memmove(a,b,c) bcopy(b,a,c)
#endif

#ifndef memmove
#define strerror(e) (sys_errlist[e])
#endif
#endif

#ifdef ultrix
/* If you are using Ultrix versions prior to 3.0, uncomment the following
 * three lines  so that users don't need to specify -DULTRIX22 on their
 * compile lines. */

/* #ifndef ULTRIX22 */
/* #define ULTRIX22 */
/* #endif */

#ifdef ULTRIX22
#define	MAXHOSTNAMELEN	64
typedef int uid_t;
typedef int gid_t;
#endif
#endif

#if defined(macII) || defined(ULTRIX22)
#define FD_ZERO(p)  ((p)->fds_bits[0] = 0)
#define FD_SET(n, p)   ((p)->fds_bits[0] |= (1 << (n)))
#define FD_ISSET(n, p)   ((p)->fds_bits[0] & (1 << (n)))
#define	FD_CLR(n, p)	((p)->fds_bits[0] &= ~(1 << (n)))
#endif

#ifndef Z_HaveKerberos
#define	REALM_SZ	MAXHOSTNAMELEN
#define	INST_SZ		0		/* no instances w/o Kerberos */
#define	ANAME_SZ	9		/* size of a username + null */
#endif

#endif /* __ZEPHYR_CONF_H__ */
