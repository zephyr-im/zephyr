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
static char rcsid_xselect_c[] = "$Id$";
#endif

#include <zephyr/mit-copyright.h>

/* xselect.c - ICCCM compliant cut-and-paste */

#include <stdio.h>
#include <X11/Xlib.h>
#include <X11/Xproto.h>
#include <X11/Xatom.h>
#include "new_string.h"
#include "xselect.h"

extern char *getSelectedText();

static Time ownership_start = CurrentTime;
static Time ownership_end = CurrentTime;
static Atom ZA_TARGETS,ZA_MULTIPLE,ZA_TIMESTAMP,ZA_ATOM_PAIR;

static struct _ZAtom {
   Atom *patom;
   char *name;
} ZAtom[] = {
   {&ZA_TARGETS,"TARGETS"},
   {&ZA_MULTIPLE,"MULTIPLE"},
   {&ZA_TIMESTAMP,"TIMESTAMP"},
   {&ZA_ATOM_PAIR,"ATOM_PAIR"}
};
#define NumZAtoms (sizeof(ZAtom)/sizeof(struct _ZAtom))

/* internal static functions */

static void xselNotify(dpy,selreq,property)
     Display *dpy;
     XSelectionRequestEvent *selreq;
     Atom property;
{
   XSelectionEvent ev;

   ev.type=SelectionNotify;
   ev.requestor=selreq->requestor;
   ev.selection=selreq->selection;
   ev.target=selreq->target;
   ev.property=property;
   ev.time=selreq->time;

   XSendEvent(dpy,ev.requestor,False,0,(XEvent *) &ev);
}

/* pRequestAtoms and RequestAtoms should have the same size. */
static Atom *pRequestAtoms[] = {
   &ZA_TARGETS,&ZA_MULTIPLE,&ZA_TIMESTAMP,NULL
};
static Atom RequestAtoms[] = {
   None,None,None,XA_STRING
};
#define NumRequestAtoms (sizeof(RequestAtoms)/sizeof(Atom))
#define PROP(prop,targ) ((prop)!=None?(prop):(targ))
#define ChangeProp(type,format,data,size) \
  XChangeProperty(dpy,w,PROP(property,target),(type),(format), \
		  PropModeReplace, (unsigned char *) (data),(size))

static void xselSetProperties(dpy,w,property,target,selreq)
     Display *dpy;
     Window w;
     Atom property,target;
     XSelectionRequestEvent *selreq;
{
   if (target==ZA_TARGETS) {

      ChangeProp(XA_ATOM,32,RequestAtoms,NumRequestAtoms);
      XSync(dpy,0);
   } else if (target==ZA_MULTIPLE) {
      Atom atype;
      int aformat;
      Atom *alist;
      unsigned long alistsize,i;

      XGetWindowProperty(dpy,w,property,0L,0L,False,ZA_ATOM_PAIR,&atype,
			 &aformat,&i,&alistsize,(unsigned char **) &alist);

      if (alistsize)
	XGetWindowProperty(dpy,w,property,0L,alistsize/sizeof(Atom),False,
			   ZA_ATOM_PAIR,&atype,&aformat,&alistsize,&i,
			   (unsigned char **) &alist);

      alistsize/=(sizeof(Atom)/4);
      for (i=0;i<alistsize;i+=2)
	xselSetProperties(dpy,w,alist[i+1],alist[i],selreq);

      XFree(alist);
   } else if (target==ZA_TIMESTAMP) {
      ChangeProp(XA_INTEGER,32,&ownership_start,1);
      XSync(dpy,0);
   } else if (target==XA_STRING) {
      char *selected;

      selected=getSelectedText();

      ChangeProp(XA_STRING,8,selected,string_Length(selected));
      XSync(dpy,0);
   }

   xselNotify(dpy,selreq,property);
}

/* global functions */

void xselInitAtoms(dpy)
     Display *dpy;
{
   int i;

   for (i=0;i<NumZAtoms;i++)
     *(ZAtom[i].patom)=XInternAtom(dpy,ZAtom[i].name,False);
   for (i=0;i<NumRequestAtoms;i++)
     if (pRequestAtoms[i]) 
       RequestAtoms[i]=*(pRequestAtoms[i]);
}

int xselGetOwnership(dpy,w,time)
     Display *dpy;
     Window w;
     Time time;
{
   int temp;

   XSetSelectionOwner(dpy,XA_PRIMARY,w,time);
   temp=(w == XGetSelectionOwner(dpy,XA_PRIMARY));

   if (temp)
     ownership_start = time;

   return(temp);
}

/* Get the selection.  Return !0 if success, 0 if fail */
int xselProcessSelection(dpy,w,event)
     Display *dpy;
     Window w;
     XEvent *event;
{
   XSelectionRequestEvent *selreq = &(event->xselectionrequest);
   int (*syncfunc)();
   Atom targetprop;
   char *selvalue;

#ifdef DEBUG
   if ((selreq->owner != w) || (selreq->selection != XA_PRIMARY))
      fprintf(stderr,"SelectionRequest event has bogus field values\n");
#endif

   if ((ownership_start == CurrentTime) ||
       (selreq->time < ownership_start) ||
       ((ownership_end != CurrentTime) &&
	(ownership_end > ownership_start) &&
	(selreq->time > ownership_end)))
     xselNotify(dpy,event,None);

   xselSetProperties(dpy,selreq->requestor,selreq->property,selreq->target,
		     selreq);

   return(1);
}

void xselOwnershipLost(time)
     Time time;
{
   ownership_end = time;
}

void xselGiveUpOwnership(dpy,w)
     Display *dpy;
     Window w;
{
   XSetSelectionOwner(dpy,XA_PRIMARY,None,ownership_start);

   ownership_end=ownership_start;  /* Is this right?  what should I use? */
}
