/* bfgets.c
 *
 * declaration:
 *   char *bfgets(s, n, iop)
 *      char *s;
 *      int  n;
 *      FILE *iop;
 *
 * Reads n-1 characters or until a newline from iop.  The terminating newline
 * is NOT RETURNED.
 *
 * Written by Barr3y Jaspan (bjaspan@athena.mit.edu)
 */

#include <stdio.h>

char *bfgets();

char *bfgets(s, n, iop)
   char *s;
   int  n;
   FILE *iop;
{
     register int c;
     register char *cs;

     cs = s;
     while ((--n > 0) && ((c = getc(iop)) !=EOF) && (c != '\n'))
	  *cs++ = c;

     *cs = '\0';
     return (c == EOF && cs == s) ? NULL : s;
}
