/*
 * timer_manager_ -- routines for handling timers in login_shell
 * (and elsewhere)
 *
 * Copyright 1986 Student Information Processing Board,
 * Massachusetts Institute of Technology
 *
 * written by Ken Raeburn
 */

#include <stdio.h>
#include <sys/types.h>
#include <sys/time.h>
#include <signal.h>
#include "timer_manager_.h"

#define NOW (time((time_t *)NULL))
/* Maximum simultaneous triggers.. */
#define MAXSIMUL (16)

static timer timers = NULL;
static long right_now;

char *calloc(), *malloc(), *realloc();
static int timer_handler();
static void timer_botch();
static void insert_timer();

/*
 * timer_set_rel(time_rel, proc)
 *   time_rel: alarm time relative to now, in seconds
 *   proc: subroutine to be called (no args, returns void)
 *
 * creates a "timer" and adds it to the current list, returns "timer"
 */

timer timer_set_rel (time_rel, proc)
     long time_rel;
     void (*proc)();
{
	timer new_t;
	right_now = NOW;
	new_t = (timer) malloc(TIMER_SIZE);
	if (new_t == NULL) return(NULL);
	ALARM_TIME(new_t) = time_rel + right_now;
	ALARM_FUNC(new_t) = proc;
	ALARM_NEXT(new_t) = NULL;
	ALARM_PREV(new_t) = NULL;
	if (add_timer(new_t) != 0) {
		free((char *)new_t);
		return(NULL);
	}
	return(new_t);
}

/*
 * timer_set_abs (time_abs, proc)
 *   time_abs: alarm time, absolute
 *   proc: routine to call when timer expires
 *
 * functions like timer_set_rel
 */

timer timer_set_abs (time_abs, proc)
     long time_abs;
     void (*proc)();
{
	timer new_t;

	new_t = (timer)malloc(TIMER_SIZE);
	if (new_t == NULL) return(NULL);
	ALARM_TIME(new_t) = time_abs;
	ALARM_FUNC(new_t) = proc;
	ALARM_NEXT(new_t) = NULL;
	ALARM_PREV(new_t) = NULL;
	if (add_timer(new_t) != 0) {
		free((char *)new_t);
		return(NULL);
	}
	return(new_t);
}

/*
 * reset_timer
 *
 * args:
 *   tmr: timer to be removed from the list
 *
 * removes any timers matching tmr and reallocates list
 *
 */

reset_timer(tmr)
     timer tmr;
{
	if (!ALARM_PREV(tmr) || !ALARM_NEXT(tmr)) {
#ifdef DEBUG
		fprintf(stderr, "reset_timer() of unscheduled timer\n");
#endif
		return(-1);
	}
	if (tmr == timers) {
#ifdef DEBUG
		fprintf(stderr, "reset_timer of timer head\n");
#endif
		return(-1);
	}
	right_now = NOW;
	remque(tmr);
	ALARM_PREV(tmr) = NULL;
	ALARM_NEXT(tmr) = NULL;
	return(reschedule_timer());
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
int
add_timer(new_t)
     timer new_t;
{
	if (ALARM_PREV(new_t) || ALARM_NEXT(new_t)) {
#ifdef DEBUG
	        fprintf(stderr, "add_timer of enqueued timer\n");
#endif
		return(-1);
	}
	right_now = NOW;
	insert_timer(new_t);
	return(reschedule_timer());
}

int
add_timer_rel(tm, new_t)
     long tm;
     timer new_t;
{
	ALARM_TIME(new_t) = tm + NOW;
	return(add_timer(new_t));
}

/*
 * insert_timer(t:timer)
 *
 * inserts a timer into the current timer table.
 *
 */

static void
insert_timer(new_t)
     timer new_t;
{
	register timer t;

	if (timers == NULL) {
		timers = (timer) malloc(TIMER_SIZE);
		ALARM_NEXT(timers) = timers;
		ALARM_PREV(timers) = timers;
		ALARM_TIME(timers) = (long) 0;
		ALARM_FUNC(timers) = timer_botch;
	}
	for (t = ALARM_NEXT(timers); t != timers; t = ALARM_NEXT(t)) {
		if (ALARM_TIME(t) > ALARM_TIME(new_t)) {
			insque(new_t, ALARM_PREV(t));
			return;
		}
	}
	insque(new_t, ALARM_PREV(timers));
}

/*
 * reschedule_timer -- checks for next timer execution time
 * and schedules itimer alarm for that time
 *
 * returns 0 on success, -1 on error
 *
 */

static int
reschedule_timer()
{
	register int i;
	register struct _timer *t;
	struct itimerval it;
	void (*queue[MAXSIMUL])();
	int nqueue=0;

	if ((int)signal(SIGALRM, timer_handler) == -1) return(-1);

	for (t=ALARM_NEXT(timers); t != timers && right_now >= ALARM_TIME(t); 
	     t=ALARM_NEXT(t)) {
		/*
		 * This one goes off NOW..
		 * Enqueue the function, and delete the timer.
		 */
		register timer s;
     
		if (nqueue>MAXSIMUL) break;
		queue[nqueue++]=ALARM_FUNC(t);
		remque(t); 
		s = t;
		t = ALARM_PREV(t);
	        ALARM_PREV(s) = NULL;
		ALARM_NEXT(s) = NULL;
	}
	set_timeval(it.it_interval, (long)0);
	set_timeval(it.it_value, 
		    ALARM_TIME(t)?(long)(ALARM_TIME(t) - right_now) : (long) 0
		    );
	setitimer(ITIMER_REAL, &it, (struct itimerval *)NULL);
	for (i=0; i < nqueue; i++)
		(queue[i])();
	return(0);
}

static
timer_handler()
{
	right_now = NOW;
	return(reschedule_timer());
}

suspend_timers()
{
	struct itimerval it;
	set_timeval(it.it_value, 0);
	setitimer(ITIMER_REAL, &it, (struct itimerval *)NULL);
}

restart_timers()
{
	reschedule_timer();
}


/* sleep routine to replace library sleep routine, which steals SIGALRM */

static int stay_asleep;

static void
wake_up()
{
	stay_asleep = 0;
}

sleep(n_sec)
     unsigned n_sec;
{
	stay_asleep = 1;
	if (timer_set_rel((long)n_sec, wake_up) == NULL) return;
	while(stay_asleep) sigpause(0);
}

static void
timer_botch()
{
	fprintf(stderr, "Timer botch\n");
	exit(42);
}

print_timers()
{
	register timer t;

	printf("\nIt's currently %d\n", NOW);
	for (t=ALARM_NEXT(timers); t != timers; t = ALARM_NEXT(t)) {
		printf("Timer %x: time %d\n", t, ALARM_TIME(t));
	}
}
