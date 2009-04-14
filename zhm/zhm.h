#ifndef __HM_H__
#define __HM_H__
/* This file is part of the Project Athena Zephyr Notification System.
 * It contains the hostmanager header file.
 *
 *      Created by:     David C. Jedlinsky
 *
 *      $Id$
 *
 *      Copyright (c) 1987, 1991 by the Massachusetts Institute of Technology.
 *      For copying and distribution information, see the file
 *      "mit-copyright.h". 
 */

#include <zephyr/mit-copyright.h>
#include <internal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include "timer.h"

/* These macros are for insertion into and deletion from a singly-linked list
 * with back pointers to the previous element's next pointer.  In order to
 * make these macros act like expressions, they use the comma operator for
 * sequenced evaluations of assignment, and "a && b" for "evaluate assignment
 * b if expression a is true". */
#define LIST_INSERT(head, elem) \
	((elem)->next = *(head), \
	 (*head) && ((*(head))->prev_p = &(elem)->next), \
	 (*head) = (elem), (elem)->prev_p = (head))
#define LIST_DELETE(elem) \
	(*(elem)->prev_p = (elem)->next, \
	 (elem)->next && ((elem)->next->prev_p = (elem)->prev_p))

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
void disable_queue_retransmits __P((void));
int queue_len __P((void));

struct sockaddr_in serv_sin;
extern int rexmit_times[];

#ifdef vax
#define use_etext
#endif /* vax */

#ifdef ibm032
#define adjust_size(size)	size -= 0x10000000
#endif /* ibm032 */

#if defined(sun) && (defined (SUN4_ARCH) || defined (sparc))
#define use_etext
#endif

#ifdef _AIX
#ifdef i386
#define adjust_size(size)	size -= 0x400000
#endif
#ifdef _IBMR2
#define	adjust_size(size)	size -= 0x20000000
#endif
#endif

#if (defined(ultrix) || defined(sgi)) && defined(mips)
#define adjust_size(size)	size -= 0x10000000
#endif /* (ultrix || sgi) && mips */

#if defined(__alpha)
#define adjust_size(size)	size -= 0x140000000
#endif /* alpha */

#ifdef use_etext
extern int etext;
#define adjust_size(size)	size -= (unsigned int) &etext;
#undef use_etext
#endif

#endif
