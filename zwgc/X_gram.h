/* This file is part of the Project Athena Zephyr Notification System.
 * It is one of the source files comprising zwgc, the Zephyr WindowGram
 * client.
 *
 *      Created by:     Marc Horowitz <marc@athena.mit.edu>
 *
 *      $Source$
 *      $Author$
 *	$Id$
 *
 *      Copyright (c) 1989 by the Massachusetts Institute of Technology.
 *      For copying and distribution information, see the file
 *      "mit-copyright.h".
 */


#include <zephyr/mit-copyright.h>

#ifndef x_gram_TYPE
#define x_gram_TYPE

#include <X11/Xlib.h>

typedef struct _xblock {
   unsigned long fgcolor;
   Font fid;
   int x,y;
   int x1,y1,x2,y2; /* bounds of block.  used for cut and paste. */
   int strindex;
   int strlen;
} xblock;

typedef struct _x_gram {
   unsigned long bgcolor;
#ifdef REVSTACK
   struct _x_gram *below,*above;
   Window w;
#endif
   int numblocks;
   xblock *blocks;
   char *text;
} x_gram;

typedef struct _xauxblock {
   int align;
   XFontStruct *font;
   char *str;
   int len;
   int width;
} xauxblock;

typedef struct _xmode {
   int bold;
   int italic;
   int size;
   int align;
   char *substyle;
} xmode;

typedef struct _xlinedesc {
   int startblock;
   int numblock;
   int lsize;
   int csize;
   int rsize;
   int ascent;
   int descent;
} xlinedesc;

/* alignment values: */
#define LEFTALIGN   0
#define CENTERALIGN 1
#define RIGHTALIGN  2

extern void x_gram_init();
extern void x_gram_create();
extern void x_gram_expose();
extern void xshow();
extern void xcut();

#endif
