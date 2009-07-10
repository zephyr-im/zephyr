#ifndef _Associate_h
#define _Associate_h

#include <stdio.h>
#include <dyn.h>

#define AA_OK		-1000
#define AA_FAILED	-1001
#define AA_NOTFOUND	-1002

typedef struct _array_elements {
     char *index;
     char *value;
} AElementRec, *AElement;

typedef DynObject AArray;

#endif /* _Associate_h */
