/*
 * This file is part of libdyn.a, the C Dynamic Object library.  It
 * contains the source code for the functions DynCreate() and
 * DynDestroy().
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

#ifndef DEFAULT_INC
#define DEFAULT_INC	100
#endif

static int default_increment = DEFAULT_INC;

DynObjectP DynCreate(el_size, inc)
   int	el_size, inc;
{
     DynObjectP obj;

     obj = (DynObjectP) malloc(sizeof(DynObjectRecP));
     if (obj == NULL)
	  return NULL;

     obj->array = (DynPtr) malloc(0);
     obj->el_size = el_size;
     obj->num_el = obj->size = 0;
     obj->debug = obj->paranoid = 0;
     obj->inc = (!! inc) ? inc : default_increment;

     return obj;
}

int DynDestroy(obj)
   DynObjectP obj;
{
     free(obj->array);
     free(obj);
     return DYN_OK;
}
