/*
 * This file is part of libdyn.a, the C Dynamic Object library.  It
 * contains the source code for the internal function _DynRealloc().
 *
 * There are no restrictions on this code; however, if you make any
 * changes, I request that you document them so that I do not get
 * credit or blame for your modifications.
 *
 * Written by Barr3y Jaspan, Student Information Processing Board (SIPB)
 * and MIT-Project Athena, 1989.
 */

#include <stdio.h>

#include "dynP.h"

/*
 * Ideally, this function should not be called from outside the
 * library.  However, nothing will break if it is.
 */
int _DynRealloc(obj, num_incs)
   DynObjectP obj;
   int num_incs;
{
     DynPtr temp;
     int new_size_in_bytes;
     
     new_size_in_bytes = obj->el_size*(obj->size + obj->inc*num_incs);

     if (obj->debug)
	  fprintf(stderr,
		  "dyn: alloc: Increasing object by %d bytes (%d incs).\n",
		  obj->el_size*obj->inc*num_incs, num_incs);
     
     temp = (DynPtr) realloc(obj->array, new_size_in_bytes);
     if (temp == NULL) {
	  if (obj->debug)
	       fprintf(stderr, "dyn: alloc: Out of memory.\n");
	  return DYN_NOMEM;
     }
     else {
	  obj->array = temp;
	  obj->size += obj->inc*num_incs;
     }

     if (obj->debug)
	  fprintf(stderr, "dyn: alloc: done.\n");
	  
     return DYN_OK;
}
