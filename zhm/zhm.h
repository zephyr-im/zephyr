#ifndef __HM_H__
#define __HM_H__
/* This file is part of the Project Athena Zephyr Notification System.
 * It contains the hostmanager header file.
 *
 *      Created by:     David C. Jedlinsky
 *
 *      $Source$
 *      $Author$
 *      $Zephyr: /mit/zephyr/src.rw/zhm/RCS/zhm.h,v 1.13 90/10/19 07:11:48 raeburn Exp $
 *
 *      Copyright (c) 1987, 1991 by the Massachusetts Institute of Technology.
 *      For copying and distribution information, see the file
 *      "mit-copyright.h". 
 */

#include <zephyr/mit-copyright.h>
#include <internal.h>
#include <sys/socket.h>

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

#define SERV_TIMEOUT 5
#define BOOTING 1
#define NOTICES 2

/* main.c */
void die_gracefully __P((void));

/* zhm_client.c */
void transmission_tower __P((ZNotice_t *, char *, int));
Code_t send_outgoing __P((ZNotice_t *));

/* queue.c */
void init_queue __P((void));
Code_t add_notice_to_queue __P((ZNotice_t *, char *, struct sockaddr_in *,
				int));
Code_t remove_notice_from_queue __P((ZNotice_t *, ZNotice_Kind_t *,
				     struct sockaddr_in *));
void retransmit_queue __P((struct sockaddr_in *));
int queue_len __P((void));
void resend_notices __P((struct sockaddr_in *));

extern int rexmit_times[];

#ifdef vax
#define MACHINE_TYPE "vax"
#define use_etext
#define ok
#endif /* vax */

#ifdef ibm032
#define MACHINE_TYPE "rt"
#define adjust_size(size)	size -= 0x10000000
#define ok
#endif /* ibm032 */

#ifdef NeXT
#define MACHINE_TYPE "NeXT"
#define ok
#endif /* NeXT */

#ifdef sun
#ifdef SUN2_ARCH
#define MACHINE_TYPE "sun2"
#define ok
#endif /* SUN2_ARCH */

#ifdef SUN3_ARCH
#define MACHINE_TYPE "sun3"
#define ok
#endif /* SUN3_ARCH */

#if defined (SUN4_ARCH) || defined (sparc)
#define MACHINE_TYPE "sun4"
#define use_etext
#define ok
#endif /* SUN4_ARCH */

#ifndef ok
#if defined (m68k)
#define MACHINE_TYPE "sun (unknown 68k)"
#else
#define MACHINE_TYPE "sun (unknown)"
#endif
#define ok
#endif /* ! ok */
#endif /* sun */

#ifdef _AIX
#ifdef i386
#define	MACHINE_TYPE	"ps2"
#define adjust_size(size)	size -= 0x400000
#endif
#ifdef _IBMR2
#define	MACHINE_TYPE "IBM RISC/6000"
#define	adjust_size(size)	size -= 0x20000000
#endif
#define	ok
#endif

#if defined(ultrix) && defined(mips)
#define MACHINE_TYPE "decmips"
#define adjust_size(size)	size -= 0x10000000
#define ok
#endif /* ultrix && mips */

#if defined(__alpha)
#define MACHINE_TYPE "alpha"
#define adjust_size(size)	size -= 0x140000000
#define ok
#endif /* alpha */


#ifdef use_etext
extern int etext;
#define adjust_size(size)	size -= (unsigned int) &etext;
#undef use_etext
#endif

#ifndef ok
#define MACHINE_TYPE "unknown"
#endif
#undef ok

#endif
