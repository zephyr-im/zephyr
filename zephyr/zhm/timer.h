/* This file is part of the Project Athena Zephyr Notification System.
 * It contains definitions used by timer.c
 *
 *      Created by:     John T. Kohl
 *      Derived from timer_manager_.h by Ken Raeburn
 *
 *      $Id$
 *
 */

#ifndef __TIMER_H

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

typedef void (*timer_proc) __P((void *));

typedef struct _Timer {
        int		heap_pos;	/* Position in timer heap */
        long    	abstime;
        timer_proc	func;
        void		*arg;
} Timer;

Timer *timer_set_rel __P((long, timer_proc, void *));
Timer *timer_set_abs __P((long, timer_proc, void *));
void timer_reset __P((Timer *));
void timer_process __P((void));
struct timeval *timer_timeout __P((struct timeval *tvbuf));

#endif /* __TIMER_H */

