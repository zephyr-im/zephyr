/* This file is part of the Project Athena Zephyr Notification System.
 * It contains functions for managing multiple timeouts.
 *
 *	Created by:	John T. Kohl
 *	Derived from timer_manager_ by Ken Raeburn
 *
 *	$Source$
 *	$Author$
 *
 */

static char rcsid[] =
    "$Header$";

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


/*
 * External functions:
 *
 * timer timer_set_rel (time_rel, proc, arg)
 *	long time_rel;
 *	void (*proc)();
 *	caddr_t arg;
 * timer timer_set_abs (time_abs, proc, arg)
 *	long time_abs;
 *	void (*proc)();
 *	caddr_t arg;
 *
 * void timer_reset(tmr)
 *	timer tmr;
 *
 * void timer_process()
 *
 */

#include <stdio.h>
#include "zserver.h"

long nexttimo = 0L;			/* the Unix time of the next
					   alarm */
static timer timers = NULL;
static long right_now;

static void timer_botch(void*), insert_timer(timer), add_timer(timer);

/*
 * timer_set_rel(time_rel, proc)
 *   time_rel: alarm time relative to now, in seconds
 *   proc: subroutine to be called (no args, returns void)
 *
 * creates a "timer" and adds it to the current list, returns "timer"
 */

timer timer_set_rel (long time_rel, void (*proc)(void*), void *arg) {
	timer new_t;
	right_now = NOW;
	new_t = (timer) xmalloc(TIMER_SIZE);
	if (new_t == NULL) return(NULL);
	ALARM_TIME(new_t) = time_rel + right_now;
	ALARM_FUNC(new_t) = proc;
	ALARM_NEXT(new_t) = NULL;
	ALARM_PREV(new_t) = NULL;
	ALARM_ARG(new_t)  = arg;
	add_timer(new_t);
	return new_t;
}

#ifdef notdef
/* currently unused */

/*
 * timer_set_abs (time_abs, proc, arg)
 *   time_abs: alarm time, absolute
 *   proc: routine to call when timer expires
 *   arg:  argument to routine
 *
 * functions like timer_set_rel
 */

timer timer_set_abs (time_abs, proc, arg)
     long time_abs;
     void (*proc)();
     caddr_t arg;
{
	timer new_t;

	new_t = (timer)xmalloc(TIMER_SIZE);
	if (new_t == NULL) return(NULL);
	ALARM_TIME(new_t) = time_abs;
	ALARM_FUNC(new_t) = proc;
	ALARM_NEXT(new_t) = NULL;
	ALARM_PREV(new_t) = NULL;
	ALARM_ARG(new_t)  = arg;
	add_timer(new_t);
	return new_t;
}
#endif notdef

/*
 * timer_reset
 *
 * args:
 *   tmr: timer to be removed from the list
 *
 * removes any timers matching tmr and reallocates list
 *
 */

void
timer_reset(timer tmr) {
	if (!ALARM_PREV(tmr) || !ALARM_NEXT(tmr)) {
		syslog (LOG_ERR, "timer_reset() of unscheduled timer\n");
		abort();
	}
	if (tmr == timers) {
		syslog (LOG_ERR,"timer_reset of timer head\n");
		abort();
	}
	xremque(tmr);
	ALARM_PREV(tmr) = NULL;
	ALARM_NEXT(tmr) = NULL;
	xfree(tmr);
	if (timers == NULL) {
		syslog (LOG_ERR,"reset with no timers\n");
		abort();
	}
	nexttimo = ALARM_TIME(ALARM_NEXT(timers));
}


#define set_timeval(t,s) ((t).tv_sec=(s),(t).tv_usec=0,(t))

/* add_timer(t:timer)
 *
 * args:
 *   t: new "timer" to be added
 *
 * returns:
 *   0 if successful
 *   -1 if error (errno set) -- old time table may have been destroyed
 *
 */
static void
add_timer(timer new_t) {
	if (ALARM_PREV(new_t) || ALARM_NEXT(new_t)) {
		syslog (LOG_ERR,"add_timer of enqueued timer\n");
		abort();
	}
	insert_timer(new_t);
}

/*
 * insert_timer(t:timer)
 *
 * inserts a timer into the current timer table.
 *
 */

static void
insert_timer(timer new_t) {
	register timer t;

	if (timers == NULL) {
		timers = (timer) xmalloc(TIMER_SIZE);
		ALARM_NEXT(timers) = timers;
		ALARM_PREV(timers) = timers;
		ALARM_TIME(timers) = 0L;
		ALARM_FUNC(timers) = timer_botch;
	}
	for (t = ALARM_NEXT(timers); t != timers; t = ALARM_NEXT(t)) {
		if (ALARM_TIME(t) > ALARM_TIME(new_t)) {
			xinsque(new_t, ALARM_PREV(t));
			nexttimo = ALARM_TIME(ALARM_NEXT(timers));
			return;
		}
	}
	xinsque(new_t, ALARM_PREV(timers));
	nexttimo = ALARM_TIME(ALARM_NEXT(timers));
}

/*
 * timer_process -- checks for next timer execution time
 * and execute 
 *
 */

void
timer_process(void) {
	register timer t;
	timer_proc queue;
	void * queue_arg;
	int valid = 0;

	right_now = NOW;
	t=ALARM_NEXT(timers);
	/* note that in the case that there are no timers, the ALARM_TIME
	   is set to 0L, which is what the main loop expects as the
	   nexttimo when we have no timout work to do */
	nexttimo = ALARM_TIME(t);
	if (t != timers && right_now >= ALARM_TIME(t)) {
		/*
		 * This one goes off NOW..
		 * Enqueue the function, and delete the timer.
		 */
		valid = 1;
		queue_arg = ALARM_ARG(t);
		queue = ALARM_FUNC(t);
		xremque(t); 
	        ALARM_PREV(t) = NULL;
		ALARM_NEXT(t) = NULL;
		ALARM_FUNC(t) = timer_botch;
		ALARM_ARG(t)  = (caddr_t) NULL;
		xfree(t);	
	}
	
	if (valid) {
		(queue)(queue_arg);
	}
}

static void
timer_botch(void *arg) {
	syslog(LOG_CRIT, "Timer botch\n");
	abort();
}
