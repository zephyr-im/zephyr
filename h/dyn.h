/*
 * This file is part of libdyn.a, the C Dynamic Object library.  It
 * contains the public header file.
 *
 * There are no restrictions on this code; however, if you make any
 * changes, I request that you document them so that I do not get
 * credit or blame for your modifications.
 *
 * Written by Barr3y Jaspan, Student Information Processing Board (SIPB)
 * and MIT-Project Athena, 1989.
 */


/*
 * dyn.h -- header file to be included by programs linking against
 * libdyn.a.
 */

#ifndef _Dyn_h
#define _Dyn_h

/* Reliance on <sysdep.h> for __P() below makes this unsuitable for use
 * outside of the Zephyr source tree. */
#include <sysdep.h>

typedef char *DynPtr;
typedef struct _DynObject *DynObject;

/* Function macros */
#define DynHigh(obj)	(DynSize(obj) - 1)
#define DynLow(obj)	(0)

#ifdef SUNOS
#define memmove(a, b, c) bcopy(b, a, c)
#endif

/* Return status codes */
#define DYN_OK		-1000
#define DYN_NOMEM	-1001
#define DYN_BADINDEX	-1002
#define DYN_BADVALUE	-1003
     
/* Function declarations */
int		DynAppend __P((DynObject obj, DynPtr els, int num));
int		DynAdd __P((DynObject obj, DynPtr el));
DynObject 	DynCreate __P((int el_size, int inc));
int		DynDebug __P((DynObject obj, int state));
int		DynDelete __P((DynObject obj, int idx));
int		DynDestroy __P((DynObject obj));
DynPtr		DynGet __P((DynObject obj, int num));
int		DynInsert __P((DynObject obj, int idx, DynPtr els, int num));
int		DynParanoid __P((DynObject obj, int state));
int		DynSize __P((DynObject obj));

#endif /* _Dyn_h */
/* DO NOT ADD ANYTHING AFTER THIS #endif */
