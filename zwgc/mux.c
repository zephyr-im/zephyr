/* This file is part of the Project Athena Zephyr Notification System.
 * It is one of the source files comprising zwgc, the Zephyr WindowGram
 * client.
 *
 *      Created by:     Marc Horowitz <marc@athena.mit.edu>
 *
 *      $Source$
 *      $Author$
 *
 *      Copyright (c) 1989 by the Massachusetts Institute of Technology.
 *      For copying and distribution information, see the file
 *      "mit-copyright.h".
 */

#if (!defined(lint) && !defined(SABER))
static char rcsid_mux_c[] = "$Id$";
#endif

/****************************************************************************/
/*                                                                          */
/*        Module containing code to wait on multiple file descriptors:      */
/*                                                                          */
/****************************************************************************/

#include <sys/types.h>
#include <sys/time.h>
#include <sys/file.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <zephyr/zephyr.h>
#include "mux.h"
#include "error.h"
#include "zwgc.h"
#include "pointer.h"

#ifdef _AIX
#include <sys/select.h>
#endif

/*
 * mux_end_loop_p - Setting this to true during a mux_loop causes the mux_loop
 *                  to be exited.
 */

int mux_end_loop_p;

/*
 * have_tty - is defined to be true if there is a controlling tty for this
 * 	      process.  When we can no longer access the controlling tty,
 * 	      the process will die.
 */

static int have_tty = 0;

/*
 * max_source - the maximum file descriptor that a handler was ever
 *              registered for:
 */

static int max_source = -1;

/*
 * Which file descriptors we're waiting on for input & the accompanying
 * input handlers & their arguments:
 */

static fd_set input_sources;
static void (*input_handler[MAX_SOURCES])();
static pointer input_handler_arg[MAX_SOURCES];

static int check_tty();

/*
 *    void mux_init()
 *        Requires: mux_init has never been called before
 *        Effects: Initializes the mux module.  Must be called before
 *                 any other mux call.
 */

void mux_init()
{
    int i;

    FD_ZERO(&input_sources);
    
    for (i=0; i<MAX_SOURCES; i++)
      input_handler[i] = NULL;

    have_tty = check_tty();
}

/*
 *    void mux_add_input_source(int descriptor; void (*handler)(); pointer arg)
 *        Requires: 0<=descriptor<MAX_SOURCES, mux_init has been called
 *        Modifies: Removes the previous input handler if any for descriptor
 *        Effects: Registers handler as the input handler for file descriptor
 *                 descriptor.  When mux_loop() is running and input is
 *                 available on descriptor, handler will be called with
 *                 argument arg.
 */

void mux_add_input_source(descriptor, handler, arg)
     int descriptor;
     void (*handler)();
     pointer arg;
{
#ifdef DEBUG
    if(descriptor < 0 || descriptor >= MAX_SOURCES)
      abort(); /* <<<>>> */
#endif
    
    input_handler[descriptor] = handler;
    input_handler_arg[descriptor] = arg;
    FD_SET(descriptor, &input_sources);
    if(descriptor > max_source)
      max_source = descriptor;
}

/*
 *    void mux_loop()
 *        Requires: mux_init has been called.
 *        Effects: Loops until mux_end_loop_p becomes true.  (Sets
 *                 mux_end_loop_p false to start).  Whenever input is
 *                 available on an input source which has a registered
 *                 handler (see mux_add_input_source), that handler is
 *                 called with its argument.  It is guaranteed that if
 *                 input is available on a source, its respective input
 *                 handler, if any, will eventually be called.  No other
 *                 ordering guarantees are made.  When some signal handler
 *                 or input handler eventually sets mux_end_loop_p to
 *                 true, we return.
 */

void mux_loop()
{
    int i;
    fd_set input_sources_copy;
    struct timeval tv;

    mux_end_loop_p = 0;

    for (;;) {
	/*
	 * Exit if mux_end_loop_p has been set to true by a handler:
	 */
	if (mux_end_loop_p)
	  break;

	if (have_tty) {
	    tv.tv_sec = 10;
	    tv.tv_usec = 0;
	} else {
	    tv.tv_sec = tv.tv_usec = 0;
	}

	/*
	 * Do a select on all the file descriptors we care about to
	 * wait until at least one of them has input available:
	 */
	input_sources_copy = input_sources;

	i = select(max_source+1, &input_sources_copy, (fd_set *)0,
		   (fd_set *)NULL, have_tty ? &tv : (struct timeval *)0);

	if (i == -1) {
	    if (errno == EINTR)
		continue;    /* on a signal restart checking mux_loop_end_p */
	    else
		FATAL_TRAP( errno, "while selecting" );
	}
	else if (i == 0) {
	    if (have_tty && !check_tty()) {
		mux_end_loop_p = 1;
		continue;
	    }
	}

	/*
	 * Call all input handlers whose corresponding file descriptors have
	 * input:
	 */
	for(i=0; i<=max_source; i++)
	  if (FD_ISSET(i, &input_sources_copy) && input_handler[i]) {
#ifdef DEBUG
	      if (zwgc_debug)
		fprintf(stderr,
			"mux_loop...activity on fd %d, calling %x(%x)\n",
			i,input_handler[i],input_handler_arg[i]);
#endif
	      input_handler[i](input_handler_arg[i]);
	  }
    }
}

static int check_tty()
{
    register int result;
    int pgrp;
    int tty = open("/dev/tty", O_RDONLY|O_NDELAY);

    if (tty < 0) return 0;

#if defined(POSIX) || defined(SUNOS)
    result = ( ((pgrp = tcgetpgrp(tty)) < 0)      ? 0 : 1 );
#else
    result = ( (ioctl(tty, TIOCGPGRP, &pgrp) < 0) ? 0 : 1 );
#endif

    close(tty);
    return(result);
}
