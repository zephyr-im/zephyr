/*
 * This is a string-associative array abstraction with really lousy
 * semantics.  But it does what I need at the moment.
 */

#include "associate.h"

AArray AACreate()
{
     return (DynCreate(sizeof(AElementRec), 0));
}

void AADestroy(array)
   AArray array;
{
     DynDestroy(array);
}

int AAInsert(array, index, value)
   AArray array;
   char *index, *value;
{
     AElementRec temp;
     int ret;

     temp.index = index;
     temp.value = value;

     ret = DynAdd(array, &temp);
     if (ret != DYN_OK)
	  return AA_FAILED;
     else
	  return AA_OK;
}

char *AALookup(array, index)
   AArray array;
   char *index;
{
     AElementRec *a;
     int i;

     a = DynGet((char *) array, 0);
     for (i=0; i < DynSize(array); i++)
	  if (strcmp(a[i].index, index) == 0)
	       return (a[i].value);

     return NULL;
}

     
