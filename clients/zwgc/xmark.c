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
static char rcsid_xmark_c[] = "$Id$";
#endif

#include <zephyr/mit-copyright.h>

#include <X11/X.h>
#include <X11/Xlib.h>
#include "X_gram.h"
#include "X_fonts.h"
#include "xmark.h"
#include "new_string.h"
#include <stdio.h>

int markblock[3] = { -1 , -1 , -1 };
int markchar[3] = { -1 , -1 , -1 };
int markpixel[3] = { -1 , -1 , -1 };
x_gram *markgram = NULL;

int oldblock[2] = { -1 , -1 };
int oldpixel[2] = { -1 , -1 };
x_gram *oldgram = NULL;

#define xmarkValid() \
   ((markgram) && \
   (STARTBLOCK != -1) && (ENDBLOCK != -1) && \
   (STARTCHAR != -1) && (ENDCHAR != -1) && \
   (STARTPIXEL != -1) && (ENDPIXEL != -1))

void xmarkSetBound(gram,x,y,which)
     x_gram *gram;
     int x,y;
     int which;
{
   int i,xofs,yofs;
   XFontStruct *font;
   xblock *xb;
   char *s;

#ifdef MARK_DEBUG
#define RETURN \
   if ((oldblock[which] != markblock[which]) || \
       (oldpixel[which] != markpixel[which])) { \
      printf("----- SetBound:\noldblock[%d]=%d,   oldpixel[%d]=%d\nmarkblock[%d]=%d, markpixel[%d]=%d\n-----", \
	     which,oldblock[which],which,oldpixel[which], \
	     which,markblock[which],which,markpixel[which]); \
   } \
   return
#else
#define RETURN return
#endif

   if (markgram != gram) {
      xmarkClear();
      markgram = gram;
   } else if (which < XMARK_TEMP_BOUND) {
      oldblock[which]=markblock[which];
      oldpixel[which]=markpixel[which];
   }

   /* Start at the top, fastforward to first span not too high. */
   for (i=0,xb=gram->blocks ;
	(i<gram->numblocks) && (xb->y2 < y) ;
	i++,xb++) ;

   /* the point is after the end */
   if (i==gram->numblocks) {
      markblock[which]=i;
      markchar[which]=0;
      markpixel[which]=0;
      RETURN;
   }

   /* is the point before the beginning of the line? */
   if (x <= xb->x1) {
      markblock[which]=i;
      markchar[which]=0;
      markpixel[which]=0;
      RETURN;
   }

   /* is the point in the nether space between this line and the last? */
   if (y < xb->y1) {
      markblock[which]=i;
      markchar[which]=0;
      markpixel[which]=0;
      RETURN;
   }

   for (yofs=xb->y1;(i<gram->numblocks) && (xb->y1 == yofs);i++,xb++) {

      if (x <= xb->x2) {
	 markblock[which]=i;

	 xofs=xb->x1;
	 if ((x < xofs) || (y < xb->y1)) {
	    markchar[which]=0;
	    RETURN;
	 }
	 font=get_fontst_from_fid(xb->fid);
	 for (i=0,s=((gram->text)+(xb->strindex));
	      xofs<x && i<xb->strlen;
	      i++,s++)
	   if (x<=(xofs+=font->per_char[*s - font->min_char_or_byte2].width)) {
	      markchar[which]=i;
	      markpixel[which]=xofs-xb->x1-
		font->per_char[*s - font->min_char_or_byte2].width;
	      RETURN;
	   }
      }
   }

   /* The endpoint is after the end of the block if the loop ends */
   markblock[which]=i;
   markchar[which]=0;
   markpixel[which]=0;
   RETURN;
}

/* needs both bounds to be valid (!= -1) */
static int xmarkNearest(x,y)
     int x,y;
{
   int middle;

   xmarkSetBound(markgram,x,y,XMARK_TEMP_BOUND);
   middle=(ENDBLOCK+STARTBLOCK)/2;

   if (markblock[XMARK_TEMP_BOUND] < middle)
     return(XMARK_START_BOUND);
   else if (markblock[XMARK_TEMP_BOUND] > middle)
     return(XMARK_END_BOUND);
   else {
      middle=(ENDCHAR+STARTCHAR)/2;
      if (markchar[XMARK_TEMP_BOUND] < middle)
	return(XMARK_START_BOUND);
      else
	return(XMARK_END_BOUND);
   }
}

void xmarkExpose(dpy,w,gram,b1,p1,b2,p2)
     Display *dpy;
     Window w;
     x_gram *gram;
     unsigned int b1,p1,b2,p2;
{
#define swap(x,y) temp=(x); (x)=(y); (y)=temp
   int i,temp;
   XEvent event;
#define expose (event.xexpose)

   if ((b1==-1) || (p1==-1) || (b2==-1) || (p2==-1)) return;

   if ((b1 > b2) || ((b1 == b2) && (p1 > p2))) {
      swap(b1,b2);
      swap(p1,p2);
   }

   expose.type=Expose;
   expose.display=dpy;
   expose.window=w;

   for (i=b1;i<=b2;i++) {
      if (b1==b2) {
	 expose.x=gram->blocks[i].x1+p1;
	 expose.y=gram->blocks[i].y1;
	 expose.width=p2-p1;
	 expose.height=gram->blocks[i].y2-gram->blocks[i].y1;
	 expose.count=0;
      } else if (i==b1) {
	 expose.x=gram->blocks[i].x1+p1;
	 expose.y=gram->blocks[i].y1;
	 expose.width=gram->blocks[i].x2-p1;
	 expose.height=gram->blocks[i].y2-gram->blocks[i].y1;
	 expose.count=b2-i;
      } else if (i==b2) {
	 expose.x=gram->blocks[i].x1;
	 expose.y=gram->blocks[i].y1;
	 expose.width=p2;
	 expose.height=gram->blocks[i].y2-gram->blocks[i].y1;
	 expose.count=b2-i;
      } else {
	 expose.x=gram->blocks[i].x1;
	 expose.y=gram->blocks[i].y1;
	 expose.width=gram->blocks[i].x2-gram->blocks[i].x1;
	 expose.height=gram->blocks[i].y2-gram->blocks[i].y1;
	 expose.count=b2-i;
      }

#ifdef MARK_DEBUG
   if (expose.width && expose.height) {
      printf("---- markExpose:\nb1=%d p1=%d b2=%d p2=%d\n",b1,p1,b2,p2);
      printf("x=%d y=%d w=%d h=%d\n-----",
	     expose.x,expose.y,expose.width,expose.height);
   }
#endif
      if ((expose.width && expose.height) || (expose.count == 0))
	XSendEvent(dpy,w,True,ExposureMask,&event);
   }
}

/* Public functions: */

void xmarkRedraw(dpy,w,gram,range)
     Display *dpy;
     Window w;
     x_gram *gram;
     int range;
{
#define ob1 ((unsigned int) oldblock[XMARK_START_BOUND])
#define ob2 ((unsigned int) oldblock[XMARK_END_BOUND])
#define nb1 ((unsigned int) markblock[XMARK_START_BOUND])
#define nb2 ((unsigned int) markblock[XMARK_END_BOUND])
#define op1 ((unsigned int) oldpixel[XMARK_START_BOUND])
#define op2 ((unsigned int) oldpixel[XMARK_END_BOUND])
#define np1 ((unsigned int) markpixel[XMARK_START_BOUND])
#define np2 ((unsigned int) markpixel[XMARK_END_BOUND])

   if (range==XMARK_REDRAW_CURRENT) {
      if (!markgram) return;
      xmarkExpose(dpy,w,gram,nb1,np1,nb2,np2);
   } else if (range==XMARK_REDRAW_OLD) {
      if (!oldgram) return;
      xmarkExpose(dpy,w,gram,ob1,op1,ob2,op2);
   } else if (range==XMARK_REDRAW_START) {
      if (!markgram) return;
      xmarkExpose(dpy,w,gram,ob1,op1,nb1,np1);
   } else if (range==XMARK_REDRAW_END) {
      if (!markgram) return;
      xmarkExpose(dpy,w,gram,ob2,op2,nb2,np2);
   }
#ifdef DEBUG
     else {
	printf("xmarkRedraw:  This shouldn't happen!\n");
     }
#endif
}

/* needs both bounds to be valid (!= -1) */
int xmarkSecond()
{
   if (STARTBLOCK > ENDBLOCK)
     return(XMARK_START_BOUND);
   else if (STARTBLOCK < ENDBLOCK)
     return(XMARK_END_BOUND);
   else {
      if (STARTCHAR > ENDCHAR)
	return(XMARK_START_BOUND);
      else if (STARTCHAR < ENDCHAR)
	return(XMARK_END_BOUND);
      else
	return(XMARK_END_BOUND);
   }
}

void xmarkClear()
{
   oldblock[0]=markblock[0];
   oldblock[1]=markblock[1];
   oldpixel[0]=markpixel[0];
   oldpixel[1]=markpixel[1];
   oldgram=markgram;

   markblock[0] = -1;
   markblock[1] = -1;
   markchar[0] = -1;
   markchar[1] = -1;
   markpixel[0] = -1;
   markpixel[1] = -1;
   markgram=NULL;
}

int xmarkExtendFromFirst(gram,x,y)
     x_gram *gram;
     int x,y;
{
   if (markgram != gram) {
      xmarkClear();
      markgram = gram;
   }

   if (STARTBLOCK == -1) {
      xmarkStart(gram,x,y);
      xmarkEnd(gram,x,y);
      return(XMARK_REDRAW_CURRENT);
   } else if (ENDBLOCK == -1) {
      xmarkEnd(gram,x,y);
      return(XMARK_REDRAW_CURRENT);
   } else {
      xmarkSetBound(gram,x,y,XMARK_END_BOUND);
      return(XMARK_REDRAW_END);
   }
}

int xmarkExtendFromNearest(gram,x,y)
     x_gram *gram;
     int x,y;
{
   int bound;

   if (markgram != gram) {
      xmarkClear();
      markgram = gram;
   }

   if (STARTBLOCK == -1) {
      xmarkStart(gram,x,y);
      xmarkEnd(gram,x,y);
      return(XMARK_REDRAW_CURRENT);
   } else if (ENDBLOCK == -1) {
      xmarkEnd(gram,x,y);
      return(XMARK_REDRAW_CURRENT);
   } else {
      xmarkSetBound(gram,x,y,bound=xmarkNearest(x,y));
      return(bound==XMARK_START_BOUND?XMARK_REDRAW_START:XMARK_REDRAW_END);
   }
}

char *xmarkGetText()
{
    int i, index, len;
    int last_y = -1;
    string temp;
    string text_so_far = string_Copy("");
    char *text = markgram->text;
    int startblock,endblock,startchar,endchar;

    if (xmarkValid()) {
       if (xmarkSecond() == XMARK_END_BOUND) {
	  startblock=STARTBLOCK;
	  endblock=ENDBLOCK;
	  startchar=STARTCHAR;
	  endchar=ENDCHAR;
       } else {
	  startblock=ENDBLOCK;
	  endblock=STARTBLOCK;
	  startchar=ENDCHAR;
	  endchar=STARTCHAR;
       }

       for (i=startblock; i<=endblock; i++) {
	  if (last_y != -1 && last_y != markgram->blocks[i].y)
	    text_so_far = string_Concat2(text_so_far, "\n");
	  index = markgram->blocks[i].strindex;
	  len = markgram->blocks[i].strlen;
	  if (startblock == endblock)
	    temp = string_CreateFromData(text+index+startchar,
					 endchar-startchar);
	  else if (i==startblock)
	    temp = string_CreateFromData(text+index+startchar,len-startchar);
	  else if (i==endblock)
	    temp = string_CreateFromData(text+index,endchar);
	  else
	    temp = string_CreateFromData(text+index,len);
	  text_so_far = string_Concat2(text_so_far, temp);
	  free(temp);
	  last_y = markgram->blocks[i].y;
       }
    }

    return(text_so_far);
}
