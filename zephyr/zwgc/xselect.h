/* This file is part of the Project Athena Zephyr Notification System.
 * It is one of the source files comprising zwgc, the Zephyr WindowGram
 * client.
 *
 *      Created by:     Marc Horowitz <marc@athena.mit.edu>
 *
 *      $Id$
 *
 *      Copyright (c) 1989 by the Massachusetts Institute of Technology.
 *      For copying and distribution information, see the file
 *      "mit-copyright.h".
 */


#include <zephyr/mit-copyright.h>

#ifndef _XSELECT_H_
#define _XSELECT_H_

extern void xicccmInitAtoms(Display *);
extern int xselGetOwnership(Display *, Window, Time);
extern int xselProcessSelection(Display *, Window, XEvent *);
extern void xselOwnershipLost(Time);
extern void xselGiveUpOwnership(Display *, Window);

extern Atom XA_WM_PROTOCOLS, XA_WM_DELETE_WINDOW;

#endif
