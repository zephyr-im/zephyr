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
static char rcsid_xcut_c[] = "$Id$";
#endif

#include <zephyr/mit-copyright.h>

/****************************************************************************/
/*                                                                          */
/*                    Code to deal with handling X events:                  */
/*                                                                          */
/****************************************************************************/

#include <X11/Xlib.h>
#include <X11/Xutil.h>
#include "new_memory.h"
#include "new_string.h"
#include "X_gram.h"
#include <stdio.h>
#include "zwgc.h"
#include "xselect.h"
#include "xmark.h"
#include "error.h"
#include "xrevstack.h"

/*
 *
 */

extern char *xmarkGetText();

static char *selected_text=NULL;
static Window selecting_in = 0;

char *getSelectedText()
{
   return(selected_text);
}

static string x_gram_to_string(gram)
     x_gram *gram;
{
    int i, index, len;
    int last_y = -1;
    string temp;
    string text_so_far = string_Copy("");
    char *text;

    text = gram->text;
    for (i=0; i<gram->numblocks; i++) {
	if (last_y != -1 && last_y != gram->blocks[i].y)
	  text_so_far = string_Concat2(text_so_far, "\n");
	index = gram->blocks[i].strindex;
	len = gram->blocks[i].strlen;
	temp = string_CreateFromData(text+index, len);
	text_so_far = string_Concat2(text_so_far, temp);
	free(temp);
	last_y = gram->blocks[i].y;
    }

    text_so_far = string_Concat2(text_so_far, "\n");
    return(text_so_far);
}

/*
 *
 */

/*ARGSUSED*/
Bool isShiftButton1(dpy,event,arg)
     Display *dpy;
     XEvent *event;
     char *arg;
{
   return(event->xbutton.state & (ShiftMask|Button1Mask));
}

/*ARGSUSED*/
Bool isShiftButton3(dpy,event,arg)
     Display *dpy;
     XEvent *event;
     char *arg;
{
   return(event->xbutton.state & (ShiftMask|Button3Mask));
}

void getLastEvent(dpy,state,event)
     Display *dpy;
     unsigned int state;
     XEvent *event;
{
   XEvent xev;

   if (state & Button1Mask) {
      while(XCheckIfEvent(dpy,&xev,isShiftButton1,NULL))
	 *event=xev;
   } else if (state & Button3Mask) {
      while(XCheckIfEvent(dpy,&xev,isShiftButton3,NULL))
	 *event=xev;
   }
}

void xunmark(dpy,w,gram,desc_context)
     Display *dpy;
     Window w;
     x_gram *gram;
     XContext desc_context;
{
   if (gram == NULL)
     if (XFindContext(dpy, w, desc_context, (caddr_t *) &gram))
       return;

   xmarkClear();
   xmarkRedraw(dpy,w,gram,XMARK_REDRAW_OLD);
}
     

void xcut(dpy,event,desc_context)
     Display *dpy;
     XEvent *event;
     XContext desc_context;
{
    x_gram *gram;
    Window w = event->xany.window;
    static int current_window_in = -1;
    int changedbound;

    /*
     * If event is for a window that's not ours anymore (say we're
     * in the process of deleting it...), ignore it:
     */
    if (XFindContext(dpy, w, desc_context, (caddr_t *) &gram))
      return;

    /*
     * Dispatch on the event type:
     */
    switch(event->type) {
     case EnterNotify:
       current_window_in = w;
       break;

     case LeaveNotify:
       current_window_in = -1;
       break;

     case MotionNotify:
       if (w == selecting_in) {
	  if (event->xmotion.state==(ShiftMask|Button1Mask)) {
	     /*	  getLastEvent(dpy,Button1Mask,event); */
	     changedbound=xmarkExtendFromFirst(gram,event->xmotion.x,
					       event->xmotion.y);
	     xmarkRedraw(dpy,w,gram,changedbound);
	  } else if (event->xmotion.state==(ShiftMask|Button3Mask)) {
	     /*	  getLastEvent(dpy,Button3Mask,event); */
	     changedbound=xmarkExtendFromNearest(gram,event->xmotion.x,
						 event->xmotion.y);
	     xmarkRedraw(dpy,w,gram,changedbound);
	  } 
       }
       break;

      case ButtonPress:
	if ( (event->xbutton.state)&ShiftMask ) {
	   if (event->xbutton.button==Button1) {
	      xunmark(dpy,selecting_in,NULL,desc_context);
	      if (selected_text) free(selected_text);
	      selected_text = NULL;
	      if (! xselGetOwnership(dpy,w,event->xbutton.time)) {
		 XBell(dpy,0);
		 ERROR("Unable to get ownership of PRIMARY selection.\n");
		 selecting_in = 0;
	      } else {
		 selecting_in = w;
		 xmarkStart(gram,event->xbutton.x,event->xbutton.y);
	      }
	   }
	   if ((event->xbutton.button==Button3) && (w == selecting_in)) {
	      if (selected_text) free(selected_text);
	      selected_text = NULL;
	      changedbound=xmarkExtendFromNearest(gram,event->xbutton.x,
						  event->xbutton.y);
	      xmarkRedraw(dpy,w,gram,changedbound);
	      selected_text = xmarkGetText();
	   }
	} else {
	   current_window_in = w;
	}
	break;

      case ButtonRelease:
	if (w == current_window_in && !((event->xbutton.state)&ShiftMask)) {
	   if (w == selecting_in) {
	      selecting_in = 0;
	      xmarkClear();
	   }
	   if (reverse_stack && (gram == bottom_gram))
	      bottom_gram = gram;
	   XDeleteContext(dpy, w, desc_context);
	   XDestroyWindow(dpy, w);
	   if (reverse_stack)
	     delete_gram(gram);
	   free(gram->text);
	   free(gram->blocks);
	   free(gram);
	} else if (w == selecting_in) {
	   if (selected_text) free(selected_text);
	   selected_text = xmarkGetText();
	}
	break;

     case SelectionRequest:
       xselProcessSelection(dpy,w,event);
       break;

     case SelectionClear:
       xselOwnershipLost(event->xselectionclear.time);
       if (w == selecting_in) {
	  selecting_in = 0;
	  xunmark(dpy,w,gram,desc_context);
	  if (selected_text) free(selected_text);
	  selected_text = NULL;
       }
       break;

#ifdef notdef
      case ConfigureNotify:
#ifdef DEBUG
	if (zwgc_debug)
	  printf("ConfigureNotify received for wid %lx above wid %lx\n",
		 (long) w,(long) event->xconfigure.above);
#endif
	if (gram->above==gram) {
	   /* a new zgram.  Straight to the bottom! */
	   add_to_bottom(gram);
	} else if (event->xconfigure.above)  {
	   /* some zgram was pulled to the top */
	   pull_to_top(gram);
	} else {
	   /* Some zgram was pushed to the bottom */
	   push_to_bottom(gram);
	}
	/* Note that there is no option to configure a zgram to the middle */
	break;
#endif
    }

    XFlush(dpy);
}
