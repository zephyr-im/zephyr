/* This file is part of the Project Athena Zephyr Notification System.
 * It contains functions for managing multiple timeouts.
 *
 *      Created by:     John T. Kohl
 *      Derived from timer_manager_ by Ken Raeburn
 *
 *      $Id$
 *
 */

#include "internal.h"
#include "timer.h"

#ifndef SABER
#ifndef lint
static const char rcsid[] =
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
 * Timer *timer_set_rel (time_rel, proc, arg)
 *      long time_rel;
 *      void (*proc)();
 *      caddr_t arg;
 * Timer *timer_set_abs (time_abs, proc, arg)
 *      long time_abs;
 *      void (*proc)();
 *      caddr_t arg;
 *
 * void timer_reset(tmr)
 *      Timer *tmr;
 *
 * void timer_process()
 *
 */

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
#define TIME(i) (heap[i]->abstime)
#define HEAP_ASSIGN(pos, tmr) ((heap[pos] = (tmr))->heap_pos = (pos))

static Timer **heap;
static int num_timers = 0;
static int heap_size = 0;

static void timer_botch __P((void*));
static Timer *add_timer __P((Timer *));

Timer *timer_set_rel(time_rel, proc, arg)
    long time_rel;
    void (*proc) __P((void *));
    void *arg;
{
    Timer *new_t;

    new_t = (Timer *) malloc(sizeof(*new_t));
    if (new_t == NULL)
	return(NULL);
    new_t->abstime = time_rel + time(NULL);
    new_t->func = proc;
    new_t->arg = arg;
    return add_timer(new_t);
}

void
timer_reset(tmr)
    Timer *tmr;
{
    int pos, min;

    /* Free the timer, saving its heap position. */
    pos = tmr->heap_pos;
    free(tmr);

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
}


#define set_timeval(t,s) ((t).tv_sec=(s),(t).tv_usec=0,(t))

static Timer *
add_timer(new)
    Timer *new;
{
    int pos;

    /* Create or resize the heap as necessary. */
    if (heap_size == 0) {
	heap_size = INITIAL_HEAP_SIZE;
	heap = (Timer **) malloc(heap_size * sizeof(Timer *));
    } else if (num_timers >= heap_size) {
	heap_size = heap_size * 2 + DELTA;
	heap = (Timer **) realloc(heap, heap_size * sizeof(Timer *));
    }
    if (!heap) {
	free(new);
	return NULL;
    }

    /* Insert the Timer *into the heap. */
    pos = num_timers;
    while (pos > 0 && new->abstime < TIME(PARENT(pos))) {
	HEAP_ASSIGN(pos, heap[PARENT(pos)]);
	pos = PARENT(pos);
    }
    HEAP_ASSIGN(pos, new);
    num_timers++;

    return new;
}

void
timer_process()
{
    Timer *t;
    timer_proc func;
    void *arg;
    int valid = 0;

    if (num_timers == 0 || heap[0]->abstime > time(NULL))
	return;

    /* Remove the first timer from the heap, remembering its
     * function and argument. */
    t = heap[0];
    func = t->func;
    arg = t->arg;
    t->func = timer_botch;
    t->arg = NULL;
    timer_reset(t);

    /* Run the function. */
    func(arg);
}

struct timeval *
timer_timeout(tvbuf)
    struct timeval *tvbuf;
{
    if (num_timers > 0) {
	tvbuf->tv_sec = heap[0]->abstime - time(NULL);
	if (tvbuf->tv_sec < 0)
	    tvbuf->tv_sec = 0;
	tvbuf->tv_usec = 0;
	return tvbuf;
    } else {
	return NULL;
    }
}

static void
timer_botch(arg)
    void *arg;
{
    syslog(LOG_CRIT, "timer botch\n");
    abort();
}

