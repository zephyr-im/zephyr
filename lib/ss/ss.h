/*
 * Copyright 1987, 1988 by MIT Student Information Processing Board
 *
 * For copyright information, see mit-sipb-copyright.h.
 */

#ifndef _ss_h
#define _ss_h __FILE__

#include <ss/mit-sipb-copyright.h>
#include <ss/ss_err.h>

/* Don't use <sysdep.h> for this; the broken Ultrix yacc produces
 * "char *malloc()", which conflicts with <stdlib.h>. */
#ifdef __STDC__
# include <stdarg.h>
# define VA_START(ap, last) va_start(ap, last)
# ifndef __P
#  define __P(x) x
# endif
#else
# include <varargs.h>
# define VA_START(ap, last) va_start(ap)
# define const
# ifndef __P
#  define __P(x) ()
# endif
#endif

typedef const struct _ss_request_entry {
    const char *const *command_names;
    void (*const function) __P((int, const char *const *, int, void *));
    const char * const info_string;
    int flags;
} ss_request_entry;

typedef const struct _ss_request_table {
    int version;
    ss_request_entry *requests;
} ss_request_table;

#define SS_RQT_TBL_V2	2

typedef struct _ss_rp_options {
    int version;
    void (*unknown) __P((int, const char *const *, int, void *));
    int allow_suspend;
    int catch_int;
} ss_rp_options;

#define SS_RP_V1 1

#define SS_OPT_DONT_LIST	0x0001
#define SS_OPT_DONT_SUMMARIZE	0x0002

void ss_help __P((int, const char *const *, int, void *));
char *ss_name __P((int));
void ss_error __P((int, long, char const *, ...));
void ss_perror __P((int, long, char const *));
void ss_abort_subsystem __P((int));
extern ss_request_table ss_std_requests;
#endif /* _ss_h */
