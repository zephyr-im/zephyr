/* This file is part of the Project Athena Zephyr Notification System.
 * It contains declarations for many standard UNIX library functions,
 * and macros for aiding in interfacing to them.
 *
 * Created by Ken Raeburn.
 *
 * $Source$
 * $Author$
 * $Zephyr: unix.h,v 1.3 91/01/28 15:12:57 raeburn Exp $
 *
 * Copyright (c) 1990,1991 by the Massachusetts Institute of Technology.
 * For copying and distribution information, see the file
 * "mit-copyright.h".
 */

#include <zephyr/mit-copyright.h>

#ifndef ZSERVER_UNIX_H__

#include <stdio.h>
#if defined(__STDC__) && !defined(__HIGHC__) && !defined(SABER)
/* Brain-dead High-C claims to be ANSI but doesn't have the include files.. */
#include <stdlib.h>
#endif

#ifdef __STDC__
# define        P(s) s
#else
# define P(s) ()
#endif

/*
 * Queue-handling functions.  This structure is basically a dummy;
 * as long as the start of another structure looks like this,
 * we're okay.
 */
struct qelem {
  struct qelem *q_forw;
  struct qelem *q_back;
  char *q_data;
};
void insque P((struct qelem*, struct qelem*));
void remque P((struct qelem *));

/* From the Error table library */
char *error_message P((long));

#ifdef KERBEROS
/* Kerberos */
extern int krb_get_lrealm P((char *, int));
extern int dest_tkt P((void));
extern int krb_get_svc_in_tkt P((char *, char *, char *, char *, char *, int,
			       char *));
#ifdef KRB_DEFS		/* have we actually got krb.h? */
extern int krb_mk_req P((KTEXT, char *, char *, char *, unsigned long));
extern int krb_get_cred P((char *, char *, char *, CREDENTIALS *));
#endif
#else
extern int rresvport P((int *));
#endif

#ifdef HESIOD
    /* Hesiod */
extern char ** hes_resolve P((Zconst char *, Zconst char *));
#endif

    /* hacked acl code */
extern void acl_cache_reset P((void));

#undef P

#ifdef vax
#define HAVE_ALLOCA
#endif

#if defined (__GNUC__)

/* GCC/G++ has a built-in function for allocating automatic storage.  */
#define LOCAL_ALLOC(X)	__builtin_alloca(X)
#define LOCAL_FREE(X)

#else /* not gcc or g++ */

#ifdef HAVE_ALLOCA
#define LOCAL_ALLOC(X)	alloca(X)
#define LOCAL_FREE(X)
#endif
#endif

#ifndef LOCAL_ALLOC
#define LOCAL_ALLOC(X)	malloc(X)
#define LOCAL_FREE(X)	free(X)
#endif

/*
 * Miscellaneous casts, so we don't have to insert these all over the
 * source files...
 */

#define	xfree(foo)	free((caddr_t) (foo))
#define	xinsque(a,b)	insque((struct qelem *)(a), (struct qelem *)(b))
#define xremque(a)	remque((struct qelem *)(a))
#define	xmalloc(a)	malloc((unsigned)(a))
#define	xrealloc(foo,a) realloc((caddr_t) (foo), (unsigned) (a))

#define ZSERVER_UNIX_H__
#endif
