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
static char rcsid_X_gram_c[] = "$Id$";
#endif

#include <zephyr/mit-copyright.h>

#include "X_gram.h"
#include "xmark.h"
#include <X11/Xutil.h>
#include <X11/cursorfont.h>
#include "zwgc.h"
#include "X_driver.h"
#include "X_fonts.h"
#include "error.h"
#include "new_string.h"
#include "xrevstack.h"
#include "xerror.h"

extern XContext desc_context;
extern char *app_instance;
extern unsigned long x_string_to_color();
extern char *getenv();

/*
 *
 */

int internal_border_width = 2;

unsigned long default_fgcolor;
unsigned long default_bgcolor;
unsigned long default_bordercolor;
static int reset_saver;
static int border_width = 1;
static int cursor_code = XC_sailboat;
static int set_transient = 0;
static char *title_name,*icon_name;
static Cursor cursor;
static Window group_leader; /* In order to have transient windows,
			     * I need a top-level window to always exist
			     */
static XClassHint classhint;

/* ICCCM note:
 *
 * the following properties must be set on all top-level windows:
 *
 * WM_NAME                  XStoreName(dpy,w,name);
 * WM_ICON_NAME             XSetIconName(dpy,w,name);
 * WM_NORMAL_HINTS          XSetNormalHints(dpy,w,sizehints);
 * WM_HINTS                 XSetWMHints(dpy,w,wmhints);
 * WM_CLASS                 XSetClassHint(dpy,w,classhint);
 *
 * and for individual zgrams:
 *
 * WM_TRANSIENT_FOR         XSetTransientForHint(dpy,w,main_window);
 */

/* set all properties defined in ICCCM.  If main_window == 0,
 * XSetTransientForHint is not called.
 */

/*ARGSUSED*/
void x_set_icccm_hints(dpy,w,name,icon_name,psizehints,pwmhints,main_window)
     Display *dpy;
     Window w;
     char *name;
     char *icon_name;
     XSizeHints *psizehints;
     XWMHints *pwmhints;
     Window main_window;
{
   XStoreName(dpy,w,name);
   XSetIconName(dpy,w,icon_name);
   XSetNormalHints(dpy,w,psizehints);
   XSetWMHints(dpy,w,pwmhints);
   XSetClassHint(dpy,w,&classhint);
   /* in order for some wm's to iconify, the window shouldn't be transient.
      e.g. Motif wm */
   if (set_transient && main_window)
     XSetTransientForHint(dpy,w,main_window);
}

void x_gram_init(dpy)
     Display *dpy;
{
    char *temp;
    XSizeHints sizehints;
    XWMHints wmhints;
    unsigned long rv,tc;

    default_fgcolor = BlackPixelOfScreen(DefaultScreenOfDisplay(dpy));
    default_bgcolor = WhitePixelOfScreen(DefaultScreenOfDisplay(dpy));
    rv = get_bool_resource("reverseVideo", "ReverseVideo", 0);
    if (rv) {
       tc = default_fgcolor;
       default_fgcolor = default_bgcolor;
       default_bgcolor = tc;
    }
    if (temp = get_string_resource("foreground","Foreground"))
      default_fgcolor = x_string_to_color(temp,default_fgcolor);
    if (temp = get_string_resource("background","Background"))
      default_bgcolor = x_string_to_color(temp,default_bgcolor);
    default_bordercolor = default_fgcolor;
    if (temp = get_string_resource("borderColor","BorderColor"))
      default_bordercolor = x_string_to_color(temp,default_bordercolor);

    reverse_stack = get_bool_resource("reverseStack", "ReverseStack", 0);
    reset_saver =  get_bool_resource("resetSaver", "ResetSaver", 1);
    /* The default here should be 1, but mwm sucks */
    set_transient = get_bool_resource("transient", "Transient", 0);

    temp = get_string_resource("borderWidth", "BorderWidth");
    /* <<<>>> */
    if (temp && atoi(temp)>=0)
      border_width = atoi(temp);

    temp = get_string_resource("internalBorder", "InternalBorder");
    /* <<<>>> */
    if (temp && atoi(temp)>=0)
      internal_border_width = atoi(temp);

    temp = get_string_resource("cursorCode", "CursorCode");
    /* <<<>>> */
    if (temp && atoi(temp))
      cursor_code = atoi(temp);

    cursor = XCreateFontCursor(dpy, cursor_code);
    if (!cursor)
      cursor = XCreateFontCursor(dpy, XC_sailboat);

    temp = get_string_resource("pointerColor", "Foreground");
    if (temp) {
	char *temp2;
	XColor cursor_fore, cursor_back;
	/* XXX need to do our own parsing here, since the RecolorCursor
	   routine requires an XColor, not an unsigned long (pixel) */
	if (!(temp2 = get_string_resource("background","Background"))) {
	    if (default_bgcolor == WhitePixelOfScreen(DefaultScreenOfDisplay(dpy)))
		temp2 = "white";
	    else
		temp2 = "black";
	}
	if (XParseColor(dpy,
			DefaultColormapOfScreen(DefaultScreenOfDisplay(dpy)),
			temp, &cursor_fore) &&
	    XParseColor(dpy,
			DefaultColormapOfScreen(DefaultScreenOfDisplay(dpy)),
			temp2, &cursor_back)) {
	      XRecolorCursor(dpy, cursor, &cursor_fore, &cursor_back);
	  }
    }
    if (!(title_name=get_string_resource("title","Title")))
      if (!(title_name=get_string_resource("name","Name")))
	title_name=app_instance;

    if (!(icon_name=get_string_resource("iconName","IconName")))
      if (!(icon_name=get_string_resource("name","Name")))
	icon_name=app_instance;

    if (!(temp=get_string_resource("name","Name")))
      if (!(temp=(char *) getenv("RESOURCE_NAME")))
	temp=app_instance;
    classhint.res_name=string_Copy(temp);
    classhint.res_class="Zwgc";

    group_leader=XCreateSimpleWindow(dpy,DefaultRootWindow(dpy),0,0,100,100,0,
				     default_bordercolor,default_bgcolor);
    sizehints.x = 0;
    sizehints.y = 0;
    sizehints.width = 100;
    sizehints.height = 100;
    sizehints.flags = PPosition | PSize;

    wmhints.input = False;
    wmhints.initial_state = DontCareState;
    wmhints.flags = InputHint | StateHint;

    x_set_icccm_hints(dpy,group_leader,"ZwgcGroup","ZwgcGroup",&sizehints,
		      &wmhints,0);
}

void x_gram_create(dpy, gram, xalign, yalign, xpos, ypos, xsize, ysize,
		   beepcount)
     Display *dpy;
     x_gram *gram;
     int xalign, yalign;
     int xpos, ypos;
     int xsize, ysize;
     int beepcount;
{
    Window w;
    XSizeHints sizehints;
    XWMHints wmhints;
    extern void x_get_input();

    /*
     * Adjust xpos, ypos based on the alignments xalign, yalign and the sizes:
     */
    if (xalign<0)
      xpos = WidthOfScreen(DefaultScreenOfDisplay(dpy)) - xpos - xsize
	- 2*border_width;
    else if (xalign == 0)
      xpos = (WidthOfScreen(DefaultScreenOfDisplay(dpy)) - xsize
	      - 2*border_width)>>1 + xpos;

    if (yalign<0)
      ypos = HeightOfScreen(DefaultScreenOfDisplay(dpy)) - ypos - ysize
	- 2*border_width;
    else if (yalign == 0)
      ypos = (HeightOfScreen(DefaultScreenOfDisplay(dpy)) - ysize
	      - 2*border_width)>>1 + ypos;

    /*
     * Create the window:
     */
    w = XCreateSimpleWindow(dpy,DefaultRootWindow(dpy),xpos,ypos,xsize,
			    ysize,border_width,default_bordercolor,
			    gram->bgcolor);
    gram->w=w;

    XDefineCursor(dpy, w, cursor);
    
    sizehints.x = xpos;
    sizehints.y = ypos;
    sizehints.width = xsize;
    sizehints.height = ysize;
    sizehints.flags = USPosition|USSize;

    wmhints.input = True;
    wmhints.initial_state = NormalState;
    wmhints.window_group = group_leader;
    wmhints.flags = InputHint | StateHint | WindowGroupHint;

    x_set_icccm_hints(dpy,w,title_name,icon_name,&sizehints,&wmhints,
		      group_leader);

    XSaveContext(dpy, w, desc_context, (caddr_t)gram);
    XSelectInput(dpy, w, ExposureMask|ButtonReleaseMask|ButtonPressMask
		 |LeaveWindowMask|Button1MotionMask|
		 Button3MotionMask
#ifdef notdef
		 |StructureNotifyMask
#endif
		 );

    XMapWindow(dpy, w);

    while (beepcount--)
	XBell(dpy, 0);

   if (reset_saver)
       XResetScreenSaver(dpy);

   if (reverse_stack) {
      if (bottom_gram) {
	 XWindowChanges winchanges;
	 
	 winchanges.sibling=bottom_gram->w;
	 winchanges.stack_mode=Below;
	 begin_xerror_trap(dpy);
	 XConfigureWindow(dpy,w,CWSibling|CWStackMode,&winchanges);
	 end_xerror_trap(dpy);

	 /* ICCCM compliance code:  This will happen under reparenting
	    window managers.  This is the compliant code: */
	 if (xerror_happened) {
	    XEvent ev;
	    
	    ev.type=ConfigureRequest;
	    ev.xconfigurerequest.parent=DefaultRootWindow(dpy);
	    ev.xconfigurerequest.window=w;
	    ev.xconfigurerequest.above=bottom_gram->w;
	    ev.xconfigurerequest.detail=Below;
	    ev.xconfigurerequest.value_mask=CWSibling|CWStackMode;
	    begin_xerror_trap(dpy);
	    XSendEvent(dpy,RootWindow(dpy,DefaultScreen(dpy)),
		       False,SubstructureRedirectMask|
		       SubstructureNotifyMask,&ev);
	    end_xerror_trap(dpy);
	    if (xerror_happened) {
	       /* the event didn't go.  Print error, continue */
	       ERROR("error configuring window to the bottom of the stack\n");
	    }
	 } else {
	    xerror_happened = 0;
	 }
      }
      add_to_bottom(gram);
      if (xerror_happened)
	pull_to_top(gram);
   }

   XFlush(dpy);
   /* Because the flushing/syncing/etc with the error trapping can cause
      events to be read into the Xlib queue, we need to go through the queue
      here before exiting so that any pending events get processed.
      */
   x_get_input(dpy);
}

void x_gram_draw(dpy, w, gram, region)
     Display *dpy;
     Window w;
     x_gram *gram;
     Region region;
{
   int i;
   GC gc;
   XGCValues gcvals;
   xblock *xb;
   XTextItem text;
   int startblock,endblock,startpixel,endpixel;
   
#define SetFG(fg) \
   gcvals.foreground=fg; \
   XChangeGC(dpy,gc,GCForeground,&gcvals)

   gc = XCreateGC(dpy, w, 0, &gcvals);
   XSetRegion(dpy,gc,region);
 
   if ((markgram == gram) && (STARTBLOCK != -1) && (ENDBLOCK != -1)) {
      if (xmarkSecond() == XMARK_END_BOUND) {
	 startblock=STARTBLOCK;
	 endblock=ENDBLOCK;
	 startpixel=STARTPIXEL;
	 endpixel=ENDPIXEL;
      } else {
	 startblock=ENDBLOCK;
	 endblock=STARTBLOCK;
	 startpixel=ENDPIXEL;
	 endpixel=STARTPIXEL;
      }
   } else {
      startblock = -1;
      endblock = -1;
   }

   for (i=0,xb=gram->blocks ; i<gram->numblocks ; i++,xb++) {
      if (XRectInRegion(region,xb->x1,xb->y1,xb->x2-xb->x1,
			xb->y2-xb->y1) != RectangleOut) {
	 if (i==startblock) {
	    if (i==endblock) {
	       SetFG(gram->bgcolor);
	       XFillRectangle(dpy,w,gc,xb->x1,xb->y1,startpixel,
			      (xb->y2-xb->y1));
	       SetFG(xb->fgcolor);
	       XFillRectangle(dpy,w,gc,xb->x1+startpixel,xb->y1,
			      (endpixel-startpixel),(xb->y2-xb->y1));
	       SetFG(gram->bgcolor);
	       XFillRectangle(dpy,w,gc,xb->x1+endpixel,xb->y1,
			      (xb->x2-xb->x1-endpixel),(xb->y2-xb->y1));
	    } else {
	       SetFG(gram->bgcolor);
	       XFillRectangle(dpy,w,gc,xb->x1,xb->y1,startpixel,
			      (xb->y2-xb->y1));
	       SetFG(xb->fgcolor);
	       XFillRectangle(dpy,w,gc,xb->x1+startpixel,xb->y1,
			      (xb->x2-xb->x1-startpixel),(xb->y2-xb->y1));
	    }
	 } else if (i==endblock) {
	    SetFG(xb->fgcolor);
	    XFillRectangle(dpy,w,gc,xb->x1,xb->y1,endpixel,
			   (xb->y2-xb->y1));
	    SetFG(gram->bgcolor);
	    XFillRectangle(dpy,w,gc,xb->x1+endpixel,xb->y1,
			   (xb->x2-xb->x1-endpixel),(xb->y2-xb->y1));
	 } else {
	    if ((startblock < i) && (i < endblock)) {
	       SetFG(xb->fgcolor);
	    } else {
	       SetFG(gram->bgcolor);
	    }
	    XFillRectangle(dpy,w,gc,xb->x1,xb->y1,(xb->x2-xb->x1),
			   (xb->y2-xb->y1));
	 }
      }
   }

   gcvals.function=GXxor;
   XChangeGC(dpy,gc,GCFunction,&gcvals);

   for (i=0,xb=gram->blocks ; i<gram->numblocks ; i++,xb++) {
      if (XRectInRegion(region,xb->x1,xb->y1,xb->x2-xb->x1,
			xb->y2-xb->y1) != RectangleOut) {
	 SetFG(gram->bgcolor^xb->fgcolor);
	 text.chars=gram->text+xb->strindex;
	 text.nchars=xb->strlen;
	 text.delta=0;
	 text.font=xb->fid;
	 XDrawText(dpy,w,gc,xb->x,xb->y,&text,1);
      }
   }

   XFreeGC(dpy,gc);
}

void x_gram_expose(dpy,w,gram,event)
     Display *dpy;
     Window w;
     x_gram *gram;
     XExposeEvent *event;
{
   static Region region;
   static int partregion=0;
   XRectangle rect;

   rect.x = (short) event->x;
   rect.y = (short) event->y;
   rect.width = (unsigned short) event->width;
   rect.height = (unsigned short) event->height;

#ifdef MARK_DEBUG
   printf("----- xeventExpose:\nx=%d y=%d w=%d h=%d\n-----",
	  event->x,event->y,event->width,event->height);
#endif

   if (! partregion) {
      region=XCreateRegion();
      partregion = 1;
   }

   if (rect.width && rect.height) XUnionRectWithRegion(&rect,region,region);

   if (event->count == 0) {
      x_gram_draw(dpy,w,gram,region);
      partregion = 0;
      XDestroyRegion(region);
   }
}
