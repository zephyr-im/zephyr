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
static char rcsid_xerror_c[] = "$Id$";
#endif

#include <zephyr/mit-copyright.h>

#include <X11/Xlib.h>
#include <stdio.h>
#include "mux.h"

int xerror_happened;

/*ARGSUSED*/
static int xerrortrap(dpy,xerrev)
     Display *dpy;
     XErrorEvent *xerrev;
{
   xerror_happened = 1;
}

/*ARGSUSED*/
void begin_xerror_trap(dpy)
     Display *dpy;
{
   xerror_happened = 0;
   XSetErrorHandler(xerrortrap);
}

void end_xerror_trap(dpy)
     Display *dpy;
{
   XSync(dpy,False);
   XSetErrorHandler(NULL);
}
