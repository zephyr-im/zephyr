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

/*
 *
 */

int internal_border_width = 2;

static int reverse_video = 0;
static int border_width = 1;
static int cursor_code = XC_sailboat;
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
   if (main_window) XSetTransientForHint(dpy,w,main_window);
}

void x_gram_init(dpy)
     Display *dpy;
{
    char *temp;
    XSizeHints sizehints;
    XWMHints wmhints;

    reverse_video = get_bool_resource("reverseVideo", "ReverseVideo", 0);
    reverse_stack = get_bool_resource("reverseStack", "ReverseStack", 0);

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
				     BlackPixel(dpy,DefaultScreen(dpy)),
				     WhitePixel(dpy,DefaultScreen(dpy)));
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

void x_gram_create(dpy, gram, xalign, yalign, xpos, ypos, xsize, ysize)
     Display *dpy;
     x_gram *gram;
     int xalign, yalign;
     int xpos, ypos;
     int xsize, ysize;
{
    int i;
    Window w;
    XSizeHints sizehints;
    XWMHints wmhints;
    int foreground_color = BlackPixel(dpy, DefaultScreen(dpy));
    int background_color = WhitePixel(dpy, DefaultScreen(dpy));

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
     * Deal with reverse video:
     */
    if (reverse_video) {
	int temp;
	temp = foreground_color;
	foreground_color = background_color;
	background_color = temp;
    }

    /*
     * Create the window:
     */
    w = XCreateSimpleWindow(dpy,DefaultRootWindow(dpy),xpos,ypos,xsize,
			    ysize,border_width,foreground_color,
			    background_color);
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
		 |EnterWindowMask|LeaveWindowMask|Button1MotionMask|
		 Button3MotionMask
#ifdef notdef
		 |StructureNotifyMask
#endif
		 );

    XMapWindow(dpy, w);

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
}

void x_gram_draw(dpy, w, gram, region)
     Display *dpy;
     Window w;
     x_gram *gram;
     Region region;
{
   int i,bcsize,ecsize;
   GC gc;
   XGCValues gcvals;
   xblock *xb;
   XTextItem text;
   unsigned long fg,bg;
   int startblock,endblock,startchar,endchar,startpixel,endpixel;
   
#define SetFG(fg) \
   gcvals.foreground=fg; \
   XChangeGC(dpy,gc,GCForeground,&gcvals)

   if (!reverse_video) {
      fg = BlackPixel(dpy, DefaultScreen(dpy));
      bg = WhitePixel(dpy, DefaultScreen(dpy));
   } else {
      fg = WhitePixel(dpy, DefaultScreen(dpy));
      bg = BlackPixel(dpy, DefaultScreen(dpy));
   }
   gc = XCreateGC(dpy, w, 0, &gcvals);
   XSetRegion(dpy,gc,region);
 
   if (markgram == gram) {
      if (xmarkSecond() == XMARK_END_BOUND) {
	 startblock=STARTBLOCK;
	 endblock=ENDBLOCK;
	 startchar=STARTCHAR;
	 endchar=ENDCHAR;
	 startpixel=STARTPIXEL;
	 endpixel=ENDPIXEL;
      } else {
	 startblock=ENDBLOCK;
	 endblock=STARTBLOCK;
	 startchar=ENDCHAR;
	 endchar=STARTCHAR;
	 startpixel=ENDPIXEL;
	 endpixel=STARTPIXEL;
      }
   } else {
      startblock=-1;
      endblock=-1;
   }

   SetFG(bg);
   for (i=0,xb=gram->blocks ; i<gram->numblocks ; i++,xb++) {
      if (XRectInRegion(region,xb->x1,xb->y1,xb->x2-xb->x1,
			xb->y2-xb->y1) != RectangleOut) {
	 if (i==startblock) {
	    if (i==endblock) {
	       XFillRectangle(dpy,w,gc,xb->x1,xb->y1,startpixel,
			      (xb->y2-xb->y1));
	       SetFG(fg);
	       XFillRectangle(dpy,w,gc,xb->x1+startpixel,xb->y1,
			      (endpixel-startpixel),(xb->y2-xb->y1));
	       SetFG(bg);
	       XFillRectangle(dpy,w,gc,xb->x1+endpixel,xb->y1,
			      (xb->x2-xb->x1-endpixel),(xb->y2-xb->y1));
	    } else {
	       XFillRectangle(dpy,w,gc,xb->x1,xb->y1,startpixel,
			      (xb->y2-xb->y1));
	       SetFG(fg);
	       XFillRectangle(dpy,w,gc,xb->x1+startpixel,xb->y1,
			      (xb->x2-xb->x1-startpixel),(xb->y2-xb->y1));
	    }
	 } else if (i==endblock) {
	    XFillRectangle(dpy,w,gc,xb->x1,xb->y1,endpixel,
			   (xb->y2-xb->y1));
	    SetFG(bg);
	    XFillRectangle(dpy,w,gc,xb->x1+endpixel,xb->y1,
			   (xb->x2-xb->x1-endpixel),(xb->y2-xb->y1));
	 } else {
	    XFillRectangle(dpy,w,gc,xb->x1,xb->y1,(xb->x2-xb->x1),
			   (xb->y2-xb->y1));
	 }
      } else {
	 if (i==startblock) {
	    if (i != endblock) SetFG(fg);
	 } else if (i==endblock) {
	    SetFG(bg);
	 }
      }
   }

   gcvals.function=GXxor;
   XChangeGC(dpy,gc,GCFunction,&gcvals);

   for (i=0,xb=gram->blocks ; i<gram->numblocks ; i++,xb++) {
      if (XRectInRegion(region,xb->x1,xb->y1,xb->x2-xb->x1,
			xb->y2-xb->y1) != RectangleOut) {
	 SetFG(fg^bg);
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
