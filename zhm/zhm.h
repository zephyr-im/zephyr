#ifndef __HM_H__
#define __HM_H__
/* This file is part of the Project Athena Zephyr Notification System.
 * It contains the hostmanager header file.
 *
 *      Created by:     David C. Jedlinsky
 *
 *      $Source$
 *      $Author$
 *      $Header$
 *
 *      Copyright (c) 1987 by the Massachusetts Institute of Technology.
 *      For copying and distribution information, see the file
 *      "mit-copyright.h". 
 */

#include <zephyr/mit-copyright.h>
#include <zephyr/zephyr.h>
#include <zephyr/zsyslog.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <netdb.h>
#ifdef lint
#include <sys/uio.h>			/* make lint shut up */
#endif /* lint */

#ifdef DEBUG
#define DPR(a) fprintf(stderr, a); fflush(stderr)
#define DPR2(a,b) fprintf(stderr, a, b); fflush(stderr)
#define Zperr(e) fprintf(stderr, "Error = %d\n", e)
#else
#define DPR(a)
#define DPR2(a,b)
#define Zperr(e)
#endif

#define ever (;;)

#define SERV_TIMEOUT 20
#define NOTICE_TIMEOUT 25
#define BOOTING 1
#define NOTICES 2

#define MAXRETRIES 2

extern char *malloc();
extern Code_t send_outgoing();
extern void init_queue(), retransmit_queue();

#ifdef vax
#define MACHINE "vax"
#define ok
#endif /* vax */

#ifdef ibm032
#define MACHINE "rt"
#define ok
#endif /* ibm032 */

#ifdef NeXT
#define MACHINE "NeXT"
#define ok
#endif /* NeXT */

#ifdef SUN2_ARCH
#define MACHINE "sun2"
#define ok
#endif /* SUN2_ARCH */

#ifdef SUN3_ARCH
#define MACHINE "sun3"
#define ok
#endif /* SUN3_ARCH */

#ifdef SUN4_ARCH
#define MACHINE "sun4"
#define ok
#endif /* SUN4_ARCH */

#if defined(ultrix) && defined(mips)
#define MACHINE "decmips"
#define ok
#endif /* ultrix && mips */

#if defined(AIX) && defined(i386)
#define	MACHINE	"ps2"
#define ok
#endif

#ifndef ok
#define MACHINE "unknown"
#endif
#undef ok

#endif !__HM_H__
