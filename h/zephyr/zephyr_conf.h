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
#endif

/* General filenames */
#define DEFAULT_VARS_FILE	"/etc/athena/zephyr.vars"

/* Service names */
#define	HM_SVCNAME	"zephyr-hm"
#define	SERVER_SVCNAME	"zephyr-clt"

#if defined(vax) && !defined(ultrix)
#define _BCOPY bcopy
#define _BZERO bzero
#define _BCMP  bcmp
#else
#define _BCOPY(a,b,n) memmove(b,a,n)
#define _BZERO(a,n)   memset(a,0,n)
#define _BCMP(a,b,n)  memcmp(a,b,n)
#endif

#if defined(vax) || defined(ibm032)
#define strchr index
#define strrchr rindex
#endif

#ifdef ultrix
/* If you are using Ultrix versions prior to 3.0, uncomment the following
   three lines  so that users don't need to specify -DULTRIX22 on their
   compile lines. */
/* #ifndef ULTRIX22 */
/* #define ULTRIX22 */
/* #endif */
#endif /* ultrix */

#if (defined(ultrix) && defined(ULTRIX22))
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

#ifdef macII
#define FD_ZERO(p)  ((p)->fds_bits[0] = 0)
#define FD_SET(n, p)   ((p)->fds_bits[0] |= (1 << (n)))
#define FD_ISSET(n, p)   ((p)->fds_bits[0] & (1 << (n)))
#define	FD_CLR(n, p)	((p)->fds_bits[0] &= ~(1 << (n)))
#endif

#ifndef Z_HaveKerberos
#define	REALM_SZ	MAXHOSTNAMELEN
#define	INST_SZ		0		/* no instances w/o Kerberos */
#define	ANAME_SZ	9		/* size of a username + null */
#endif /* !KERBEROS */

#endif /* __ZEPHYR_CONF_H__ */
