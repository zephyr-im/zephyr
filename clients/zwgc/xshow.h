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

#ifndef _ZWGC_XSHOW_H_
#define _ZWGC_XSHOW_H_

#include <X11/Xlib.h>

typedef struct _xblock {
   unsigned long fgcolor;
   Font fid;
   int x,y;
   int x1,y1,x2,y2; /* bounds of block.  used for cut and paste. */
   int strindex;
   int strlen;
} xblock;

typedef struct _xwin {
   unsigned long bgcolor;
   int xpos,ypos,xsize,ysize;
   int numblocks;
   xblock *blocks;
   char *text;
} xwin;

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

#endif /* _ZWGC_XSHOW_H_ */
