/*
 * This file is part of libdyn.a, the C Dynamic Object library.  It
 * contains the source code for the functions DynGet() and DynAdd().
 *
 * There are no restrictions on this code; however, if you make any
 * changes, I request that you document them so that I do not get
 * credit or blame for your modifications.
 *
 * Written by Barr3y Jaspan, Student Information Processing Board (SIPB)
 * and MIT-Project Athena, 1989.
 */

#include "dynP.h"

static int DynPut __P((DynObject obj, DynPtr el, int index));

DynPtr DynGet(obj, num)
   DynObject obj;
   int num;
{
     if (num < 0) {
	  if (obj->debug)
	       fprintf(stderr, "dyn: get: bad index %d\n", num);
	  return NULL;
     }
     
     if (num >= obj->num_el) {
	  if (obj->debug)
	       fprintf(stderr, "dyn: get: highest element is %d.\n",
		       obj->num_el);
	  return NULL;
     }
     
     if (obj->debug)
	  fprintf(stderr, "dyn: get: Returning address %p + %d.\n",
		  obj->array, obj->el_size*num);
     
     return (DynPtr) obj->array + obj->el_size*num;
}

int DynAdd(obj, el)
   DynObject obj;
   DynPtr el;
{
     int	ret;

     ret = DynPut(obj, el, obj->num_el);
     if (ret != DYN_OK)
	  return ret;

     ++obj->num_el;
     return ret;
}

/*
 * WARNING!  There is a reason this function is not documented in the
 * man page.  If DynPut used to mutate already existing elements,
 * everything will go fine.  If it is used to add new elements
 * directly, however, the state within the object (such as
 * obj->num_el) will not be updated properly and many other functions
 * in the library will lose.  Have a nice day.
 */
static int DynPut(obj, el, index)
   DynObject obj;
   DynPtr el;
   int index;
{
     int ret;
     
     if (obj->debug)
	  fprintf(stderr, "dyn: put: Writing %d bytes from %p to %p + %d\n",
		  obj->el_size, el, obj->array, index*obj->el_size);

     if ((ret = _DynResize(obj, index)) != DYN_OK)
	  return ret;
     
     (void) memmove(obj->array + index*obj->el_size, el, obj->el_size);

     if (obj->debug)
	  fprintf(stderr, "dyn: put: done.\n");
     
     return DYN_OK;
}
