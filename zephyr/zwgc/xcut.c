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

#include <sysdep.h>

#if (!defined(lint) && !defined(SABER))
static const char rcsid_xcut_c[] = "$Id$";
#endif

#include <zephyr/mit-copyright.h>

/****************************************************************************/
/*                                                                          */
/*                    Code to deal with handling X events:                  */
/*                                                                          */
/****************************************************************************/

#ifndef X_DISPLAY_MISSING

#include <X11/Xlib.h>
#include <X11/Xutil.h>
#include <zephyr/zephyr.h>
#include "new_memory.h"
#include "new_string.h"
#include "X_gram.h"
#include "zwgc.h"
#include "xselect.h"
#include "xmark.h"
#include "error.h"
#include "xrevstack.h"
#include "X_driver.h"
#include "xcut.h"
#ifdef CMU_ZWGCPLUS
#include "plus.h"
#include "variables.h"
#endif

/*
 *
 */

extern long ttl;

static char *selected_text=NULL;
static Window selecting_in = 0;

char *
getSelectedText(void)
{
   return(selected_text);
}

#ifdef notdef
static string
x_gram_to_string(x_gram *gram)
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
#endif

/*
 *
 */

/*ARGSUSED*/
Bool
isShiftButton1(Display *dpy,
	       XEvent *event,
	       char *arg)
{
   return(event->xbutton.state & (ShiftMask|Button1Mask));
}

/*ARGSUSED*/
Bool
isShiftButton3(Display *dpy,
	       XEvent *event,
	       char *arg)
{
   return(event->xbutton.state & (ShiftMask|Button3Mask));
}

void
getLastEvent(Display *dpy,
	     unsigned int state,
	     XEvent *event)
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

void
xunmark(Display *dpy,
	Window w,
	x_gram *gram,
	XContext desc_context)
{
   if (gram == NULL)
     if (XFindContext(dpy, w, desc_context, (caddr_t *) &gram))
       return;

   xmarkClear();
   xmarkRedraw(dpy,w,gram,XMARK_REDRAW_OLD);
}

/* This is out here so xdestroygram can get at it */

#define PRESSOP_NONE 0	/* nothing */
#define PRESSOP_KILL 1	/* normal click */
#define PRESSOP_SEL  2	/* shift left */
#define PRESSOP_EXT  3  /* shift right */
#define PRESSOP_NUKE 4 /* ctrl */
#define PRESSOP_STOP 5  /* pressop cancelled by moving out of window */

static int current_pressop = PRESSOP_NONE;

void
xdestroygram(Display *dpy,
	     Window w,
	     XContext desc_context,
	     x_gram *gram)
{
    struct timeval now;

    gettimeofday(&now,NULL);
    if ((gram->can_die.tv_sec == 0) ||
	(gram->can_die.tv_sec > now.tv_sec) ||
	((gram->can_die.tv_sec == now.tv_sec) &&
	 (gram->can_die.tv_usec > now.tv_usec)))
	return;

    if (w == selecting_in) {
	selecting_in = 0;
	xmarkClear();
    }
    current_pressop = PRESSOP_NONE;
    XDeleteContext(dpy, w, desc_context);
    XDestroyWindow(dpy, w);
    delete_gram(gram);
    free(gram->text);
    free(gram->blocks);
#ifdef CMU_ZWGCPLUS
    if (gram->notice)
      list_del_notice(gram->notice);
#endif
    free(gram);

#ifdef CMU_ZWGCPLUS
    XFlush(dpy);
#endif

    if (bottom_gram == NULL && unlinked == NULL) {
       /* flush colormap here */
    }
}

void
xcut(Display *dpy,
     XEvent *event,
     XContext desc_context)
{
    x_gram *gram;
    Window w = event->xany.window;
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
#ifdef CMU_ZWGCPLUS
    case KeyPress:
      {
        char c;
        char *plusvar;
        int res, metaflag;
        res = XLookupString(&(event->xkey), &c, 1, NULL, NULL);
        metaflag = event->xkey.state & Mod1Mask;

        /* Recheck if zwgcplus is turned on;
         *  Zephyr variables override zwgc variables
         */

        zwgcplus = 1;
        plusvar = ZGetVariable("zwgcplus") ? ZGetVariable("zwgcplus") : (char *)var_get_variable("zwgcplus");

        if ((plusvar[0]=='\0') || (strcmp(plusvar,"no") == 0))
          zwgcplus = 0;
        else {
          if (strcmp(plusvar,"no") == 0)
            zwgcplus = 0;
          if (strcmp(plusvar,"new") == 0)
            zwgcplus = 2;
        }

        if (res != 0 && zwgcplus != 0)
          plus_retry_notice(gram->notice, c, metaflag);
      }
      break;
#endif
      case ClientMessage:
	if ((event->xclient.message_type == XA_WM_PROTOCOLS) &&
	    (event->xclient.format == 32) &&
	    (event->xclient.data.l[0] == XA_WM_DELETE_WINDOW))
	    xdestroygram(dpy,w,desc_context,gram);
	break;

      case MapNotify:
	/* I don't like using the local time, but MapNotify events don't
	 * come with a timestamp, and there's no way to query the server
	 */

	if (gram->can_die.tv_sec == 0) {
	    gettimeofday(&(gram->can_die),NULL);
	    gram->can_die.tv_sec += (int) (ttl/1000);
	    gram->can_die.tv_usec += (ttl%1000)*1000;
	}
	break;

      case UnmapNotify:
	unlink_gram(gram);
	break;

      case LeaveNotify:
	if (current_pressop == PRESSOP_KILL ||
	    current_pressop == PRESSOP_NUKE)
	   current_pressop = PRESSOP_STOP;
	break;

      case MotionNotify:
	if (current_pressop == PRESSOP_SEL) {
	   /*	  getLastEvent(dpy,Button1Mask,event); */
	   changedbound=xmarkExtendFromFirst(gram,event->xmotion.x,
					     event->xmotion.y);
	   xmarkRedraw(dpy,w,gram,changedbound);
	} else if (current_pressop == PRESSOP_EXT) {
	   /*	  getLastEvent(dpy,Button3Mask,event); */
	   changedbound=xmarkExtendFromNearest(gram,event->xmotion.x,
					       event->xmotion.y);
	   xmarkRedraw(dpy,w,gram,changedbound);
	} 
	break;

      case ButtonPress:
	if (current_pressop != PRESSOP_NONE) {
	   current_pressop = PRESSOP_STOP;
	} else if ((event->xbutton.button==Button4 ||
		    event->xbutton.button==Button5) &&
		   !get_bool_resource("scrollDelete","ScrollDelete",0)) {
	   /* Ignore scroll wheel movement. */
	   break;
	} else if ( (event->xbutton.state)&ShiftMask ) {
	   if (event->xbutton.button==Button1) {
	      if (selecting_in)
		 xunmark(dpy,selecting_in,NULL,desc_context);
	      if (selected_text) free(selected_text);
	      selected_text = NULL;
	      if (! xselGetOwnership(dpy,w,event->xbutton.time)) {
		 XBell(dpy,0);
		 ERROR("Unable to get ownership of PRIMARY selection.\n");
		 selecting_in = 0;
		 current_pressop = PRESSOP_STOP;
	      } else {
		 selecting_in = w;
		 xmarkStart(gram,event->xbutton.x,event->xbutton.y);
		 current_pressop = PRESSOP_SEL;
	      }
	   } else if ((event->xbutton.button==Button3) &&
		      (w == selecting_in)) {
	      if (selected_text) free(selected_text);
	      selected_text = NULL;
	      changedbound=xmarkExtendFromNearest(gram,event->xbutton.x,
						  event->xbutton.y);
	      xmarkRedraw(dpy,w,gram,changedbound);
	      selected_text = xmarkGetText();
	      /* this is ok, since to get here, the selection must be owned */
	      current_pressop = PRESSOP_EXT;
#ifdef CMU_ZWGCPLUS
              if (selected_text)
                XStoreBytes(dpy, selected_text, strlen(selected_text)+1);
#endif
	   }
	} else if ( (event->xbutton.state)&ControlMask ) {
	   current_pressop = PRESSOP_NUKE;
	} else {
	   current_pressop = PRESSOP_KILL;
	}
	break;

      case ButtonRelease:
	if (current_pressop == PRESSOP_KILL) {
	   xdestroygram(dpy,w,desc_context,gram);
	} else if (current_pressop == PRESSOP_SEL ||
		   current_pressop == PRESSOP_EXT) {
	   if (selected_text) free(selected_text);
	   selected_text = xmarkGetText();
#ifdef CMU_ZWGCPLUS
	   if (selected_text)
	     XStoreBytes(dpy, selected_text, strlen(selected_text)+1);
#endif
	} else if (current_pressop == PRESSOP_NUKE) {
	   XWindowAttributes wa;
	   int gx,gy;
	   Window temp;
	   x_gram *next;

	   for (gram = bottom_gram ; gram ; gram = next) {
	      XGetWindowAttributes(dpy,gram->w,&wa);
	      XTranslateCoordinates(dpy,gram->w,wa.root,0,0,&gx,&gy,
				    &temp);

	      next = gram->above;

	      if ((wa.map_state == IsViewable) &&
		  (gx <= event->xbutton.x_root) &&
		  (event->xbutton.x_root < gx+wa.width) &&
		  (gy <= event->xbutton.y_root) &&
		  (event->xbutton.y_root < gy+wa.height)) {
		 xdestroygram(dpy,gram->w,desc_context,gram);
	      }
	   }
	   for (gram = unlinked ; gram ; gram = next) {
	      XGetWindowAttributes(dpy,gram->w,&wa);
	      XTranslateCoordinates(dpy,gram->w,wa.root,0,0,&gx,&gy,
				    &temp);

	      next = gram->above;

	      if ((wa.map_state == IsViewable) &&
		  (gx <= event->xbutton.x_root) &&
		  (event->xbutton.x_root < gx+wa.width) &&
		  (gy <= event->xbutton.y_root) &&
		  (event->xbutton.y_root < gy+wa.height)) {
		 xdestroygram(dpy,gram->w,desc_context,gram);
	      }
	   }
	}
	current_pressop = PRESSOP_NONE;
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
      default:
	break;
    }

    XFlush(dpy);
}

#endif

