/*
 * This file is part of libdyn.a, the C Dynamic Object library.  It
 * contains the source code for the function DynAppend().
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

int DynAppend(obj, els, num)
   DynObjectP obj;
   DynPtr els;
   int num;
{
     if (obj->debug)
	  fprintf(stderr, "dyn: append: Writing %d bytes from %d to %d + %d\n",
		  obj->el_size*num, els, obj->array, obj->num_el*obj->el_size);

     if (obj->size < obj->num_el + num) {
	  int num_incs, ret;

	  num_incs = ((obj->num_el + num - obj->size) / obj->inc) + 1;
	  if ((ret = _DynRealloc(obj, num_incs)) != DYN_OK)
	       return ret;
     }

     (void) memmove(obj->array + obj->num_el*obj->el_size, els,
		    obj->el_size*num);

     obj->num_el += num;

     if (obj->debug)
	  fprintf(stderr, "dyn: append: done.\n");

     return DYN_OK;
}

