/*
 * This file is part of libdyn.a, the C Dynamic Object library.  It
 * contains the source code for the function DynDelete().
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
 * Checkers!  Get away from that "hard disk erase" button!
 *    (Stupid dog.  He almost did it to me again ...)
 */                                 
int DynDelete(obj, index)
   DynObjectP obj;
   int index;
{
     if (index < 0) {
	  if (obj->debug)
	       fprintf(stderr, "dyn: delete: bad index %d\n", index);
	  return DYN_BADINDEX;
     }
     
     if (index >= obj->num_el) {
	  if (obj->debug)
	       fprintf(stderr, "dyn: delete: Highest index is %d.\n",
		       obj->num_el);
	  return DYN_BADINDEX;
     }

     if (index == obj->num_el-1) {
	  if (obj->paranoid) {
	       if (obj->debug)
		    fprintf(stderr, "dyn: delete: last element, zeroing.\n");
	       bzero(obj->array + index*obj->el_size, obj->el_size);
	  }
	  else {
	       if (obj->debug)
		    fprintf(stderr, "dyn: delete: last element, punting.\n");
	  }
     }	  
     else {
	  if (obj->debug)
	       fprintf(stderr,
		       "dyn: delete: copying %d bytes from %d + %d to + %d.\n",
		       obj->el_size*(obj->num_el - index), obj->array,
		       (index+1)*obj->el_size, index*obj->el_size);
	  
	  bcopy(obj->array + (index+1)*obj->el_size,
		obj->array + index*obj->el_size,
		obj->el_size*(obj->num_el - index));

	  if (obj->paranoid) {
	       if (obj->debug)
		    fprintf(stderr,
			    "dyn: delete: zeroing %d bytes from %d + %d\n",
			    obj->el_size, obj->array,
			    obj->el_size*(obj->num_el - 1));
	       bzero(obj->array + obj->el_size*(obj->num_el - 1),
		     obj->el_size);
	  }
     }
     
     --obj->num_el;
     
     if (obj->debug)
	  fprintf(stderr, "dyn: delete: done.\n");

     return DYN_OK;
}
