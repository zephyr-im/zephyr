/*
 * This file is part of libdyn.a, the C Dynamic Object library.  It
 * contains the private header file.
 *
 * There are no restrictions on this code; however, if you make any
 * changes, I request that you document them so that I do not get
 * credit or blame for your modifications.
 *
 * Written by Barr3y Jaspan, Student Information Processing Board (SIPB)
 * and MIT-Project Athena, 1989.
 */


/*
 * dynP.h -- private header file included by source files for libdyn.a.
 */

#ifndef _DynP_h
#define _DynP_h

#include "dyn.h"

/*
 * Rep invariant:
 * 1) el_size is the number of bytes per element in the object
 * 2) num_el is the number of elements currently in the object.  It is
 * one higher than the highest index at which an element lives.
 * 3) size is the number of elements the object can hold without
 * resizing.  num_el <= index.
 * 4) inc is a multiple of the number of elements the object grows by
 * each time it is reallocated.
 */

typedef struct _DynObject {
     DynPtr	array;
     int	el_size, num_el, size, inc;
     char	debug, paranoid;
} DynObjectRecP, *DynObjectP;

/* Internal functions */
int _DynRealloc();

#define _DynResize(obj, req) \
     ((obj)->size > (req) ? DYN_OK : \
     (_DynRealloc((obj), (((req) - (obj)->size) / (obj)->inc) + 1)))

/* external (C library) functions */
#include <stdio.h>
#ifdef POSIX
#include <stdlib.h>
#endif

#endif /* _DynP_h */
/* DON'T ADD STUFF AFTER THIS #endif */
