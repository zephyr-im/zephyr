/* This file is part of the Project Athena Zephyr Notification System.
 * It contains definitions used by timer.c
 *
 *      Created by:     John T. Kohl
 *      Derived from timer_manager_.h by Ken Raeburn
 *
 *      $Source$
 *      $Author$
 *      $Header: /mit/zephyr/src/server/RCS/timer.h,v 1.9 94/03/15 12:44:40 prob
e Exp $
 *
 */

/*
 * timer_manager_ -- routines for handling timers in login_shell
 * (and elsewhere)
 *
 * Copyright 1986 Student Information Processing Board,
 * Massachusetts Institute of Technology
 *
 * written by Ken Raeburn

Permission to use, copy, modify, and distribute this
software and its documentation for any purpose and without
fee is hereby granted, provided that the above copyright
notice appear in all copies and that both that copyright
notice and this permission notice appear in supporting
documentation, and that the name of M.I.T. and the Student
Information Processing Board not be used in
advertising or publicity pertaining to distribution of the
software without specific, written prior permission.
M.I.T. and the Student Information Processing Board
make no representations about the suitability of
this software for any purpose.  It is provided "as is"
without express or implied warranty.

 */

#ifdef __STDC__
# define        P(s) s
#else
# define P(s) ()
#endif

typedef struct _timer {
        int heap_pos;
        /* time for timer to go off, absolute time */
        long    time;
        /* procedure to call when timer goes off */
        void    (*func)P((void*));
        /* argument for that procedure */
        void *  arg;
} *timer;

#define NOW t_local.tv_sec
typedef void (*timer_proc) P((void *));
extern timer timer_set_rel P((long, timer_proc, void*));
extern timer timer_set_abs P((long, timer_proc, void*));
extern void timer_reset P((timer)), timer_process P((void));

#undef P

#define timer_when(x)   ALARM_TIME(x)

extern struct timeval t_local;
extern long nexttimo;                   /* Unix time of next timout */
