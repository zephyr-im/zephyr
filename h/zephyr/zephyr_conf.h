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
#define SERVER_SERVICE		"zephyr"
#define SERVER_INSTANCE		"zephyr"
#define SERVER_SRVTAB		"/usr/athena/lib/zephyr/srvtab"

/* General filenames */
#define DEFAULT_VARS_FILE	"/etc/athena/zephyr.vars"

/* Service names */
#define	HM_SVCNAME	"zephyr-hm"
#define	SERVER_SVCNAME	"zephyr-clt"

#if defined(ultrix) && !defined(ULTRIX30)
/* Ultrix 3.0 has these defined in standard places */
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
#endif /* !KERBEROS */

#endif /* __ZEPHYR_CONF_H__ */
