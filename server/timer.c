/* This file is part of the Project Athena Zephyr Notification System.
 * It contains functions for managing multiple timeouts.
 *
 *      Created by:     John T. Kohl
 *      Derived from timer_manager_ by Ken Raeburn
 *
 *      $Source$
 *      $Author$
 *
 */

#ifndef SABER
#ifndef lint
static char rcsid[] =
    "$Id$";
#endif /* lint */
#endif /* SABER */

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
 *      long time_rel;
 *      void (*proc)();
 *      caddr_t arg;
 * timer timer_set_abs (time_abs, proc, arg)
 *      long time_abs;
 *      void (*proc)();
 *      caddr_t arg;
 *
 * void timer_reset(tmr)
 *      timer tmr;
 *
 * void timer_process()
 *
 */

#include <stdio.h>
#include "zserver.h"

/* DELTA is just an offset to keep the size a bit less than a power 
 * of two.  It's measured in pointers, so it's 32 bytes on most
 * systems. */
#define DELTA 8
#define INITIAL_HEAP_SIZE (1024 - DELTA)

/* We have three operations which we need to be able to perform
 * quickly: adding a timer, deleting a timer given a pointer to
 * it, and determining which timer will be the next to go off.  A
 * heap is an ideal data structure for these purposes, so we use
 * one.  The heap is an array of pointers to timers, and each timer
 * knows the position of its pointer in the heap.
 *
 * Okay, what is the heap, exactly?  It's a data structure,
 * represented as an array, with the invariant condition that
 * the timeout of heap[i] is less than or equal to the timeout of
 * heap[i * 2 + 1] and heap[i * 2 + 2] (assuming i * 2 + 1 and
 * i * 2 + 2 are valid * indices).  An obvious consequence of this
 * is that heap[0] has the lowest timer value, so finding the first
 * timer to go off is easy.  We say that an index i has "children"
 * i * 2 + 1 and i * 2 + 1, and the "parent" (i - 1) / 2.
 *
 * To add a timer to the heap, we start by adding it to the end, and
 * then keep swapping it with its parent until it has a parent with
 * a timer value less than its value.  With a little bit of thought,
 * you can see that this preserves the heap property on all indices
 * of the array.
 *
 * To delete a timer at position i from the heap, we discard it and
 * fill in its position with the last timer in the heap.  In order
 * to restore the heap, we have to consider two cases: the timer
 * value at i is less than that of its parent, or the timer value at
 * i is greater than that of one of its children.  In the first case,
 * we propagate the timer at i up the tree, swapping it with its
 * parent, until the heap is restored; in the second case, we
 * propagate the timer down the tree, swapping it with its least
 * child, until the heap is restored. */

/* In order to ensure that the back pointers from timers are consistent
 * with the heap pointers, all heap assignments should be done with the
 * HEAP_ASSIGN() macro, which sets the back pointer and updates the
 * heap at the same time. */
#define PARENT(i) (((i) - 1) / 2)
#define CHILD1(i) ((i) * 2 + 1)
#define CHILD2(i) ((i) * 2 + 2)
#define TIME(i) (heap[i]->time)
#define HEAP_ASSIGN(pos, tmr) ((heap[pos] = (tmr))->heap_pos = (pos))

long nexttimo = 0L;                     /* the Unix time of the next
                                           alarm */
static timer *heap;
static int num_timers = 0;
static int heap_size = 0;

#ifdef __STDC__
# define        P(s) s
#else
# define P(s) ()
#endif

static void timer_botch P((void*));
static timer add_timer P((timer));

/*
 * timer_set_rel(time_rel, proc)
 *   time_rel: alarm time relative to now, in seconds
 *   proc: subroutine to be called (no args, returns void)
 *
 * creates a "timer" and adds it to the current list, returns "timer"
 */

timer timer_set_rel (time_rel, proc, arg)
     long time_rel;
     void (*proc) P((void *));
     void *arg;
{
        timer new_t;
        new_t = (timer) xmalloc(sizeof(*new_t));
        if (new_t == NULL)
                return(NULL);
        new_t->time = time_rel + NOW;
        new_t->func = proc;
        new_t->arg = arg;
        return add_timer(new_t);
}

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
timer_reset(tmr)
     timer tmr;
{
        int pos, min;

        /* Free the timer, saving its heap position. */
        pos = tmr->heap_pos;
        xfree(tmr);

	if (pos != num_timers - 1) {
	    /* Replace the timer with the last timer in the heap and
	     * restore the heap, propagating the timer either up or
	     * down, depending on which way it violates the heap
	     * property to insert the last timer in place of the
	     * deleted timer. */
	    if (pos > 0 && TIME(num_timers - 1) < TIME(PARENT(pos))) {
                do {
		    HEAP_ASSIGN(pos, heap[PARENT(pos)]);
		    pos = PARENT(pos);
                } while (pos > 0 && TIME(num_timers - 1) < TIME(PARENT(pos)));
                HEAP_ASSIGN(pos, heap[num_timers - 1]);
	    } else {
                while (CHILD2(pos) < num_timers) {
		    min = num_timers - 1;
		    if (TIME(CHILD1(pos)) < TIME(min))
			min = CHILD1(pos);
		    if (TIME(CHILD2(pos)) < TIME(min))
			min = CHILD2(pos);
		    HEAP_ASSIGN(pos, heap[min]);
		    pos = min;
                }
		if (pos != num_timers - 1)
		    HEAP_ASSIGN(pos, heap[num_timers - 1]);
	    }
	}
        num_timers--;

        /* Fix up the next timeout. */
        nexttimo = (num_timers == 0) ? 0 : heap[0]->time;
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
static timer
add_timer(new)
     timer new;
{
        int pos;

        /* Create or resize the heap as necessary. */
        if (heap_size == 0) {
                heap_size = INITIAL_HEAP_SIZE;
                heap = (timer *) xmalloc(heap_size * sizeof(timer));
        } else if (num_timers >= heap_size) {
                heap_size = heap_size * 2 + DELTA;
                heap = (timer *) xrealloc(heap, heap_size * sizeof(timer));
        }
        if (!heap) {
                xfree(new);
                return NULL;
        }

        /* Insert the timer into the heap. */
        pos = num_timers;
        while (pos > 0 && new->time < TIME(PARENT(pos))) {
                HEAP_ASSIGN(pos, heap[PARENT(pos)]);
                pos = PARENT(pos);
        }
        HEAP_ASSIGN(pos, new);
        num_timers++;

        /* Fix up the next timeout. */
        nexttimo = heap[0]->time;
        return new;
}

/*
 * timer_process -- checks for next timer execution time
 * and execute 
 *
 */

void
timer_process()
{
        register timer t;
        timer_proc func;
        void *arg;
        int valid = 0;

        if (num_timers == 0 || heap[0]->time > NOW)
                return;

        /* Remove the first timer from the heap, remembering it's 
         * function and argument.  timer_reset() updates nexttimo. */
        t = heap[0];
        func = t->func;
        arg = t->arg;
        t->func = timer_botch;
        t->arg = NULL;
        timer_reset(t);

        /* Run the function. */
        (func)(arg);
}

static void
timer_botch(arg)
     void *arg;
{
        syslog(LOG_CRIT, "Timer botch\n");
        abort();
}

