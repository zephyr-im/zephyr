/* This file is part of the Project Athena Zephyr Notification System.
 * It contains source for the ZMakeAscii function.
 *
 *	Created by:	Robert French
 *
 *	$Source$
 *	$Author$
 *
 *	Copyright (c) 1987 by the Massachusetts Institute of Technology.
 *	For copying and distribution information, see the file
 *	"mit-copyright.h". 
 */
/* $Header$ */

#ifndef lint
static char rcsid_ZMakeAscii_c[] = "$Header$";
#endif lint

#include <zephyr/mit-copyright.h>

#include <zephyr/zephyr_internal.h>

Code_t ZMakeAscii(ptr, len, field, num)
    char *ptr;
    int len;
    unsigned char *field;
    int num;
{
    int i;

    for (i=0;i<num;i++) {
	if (!(i%4)) {
	    if (len < 3+(i!=0))
		return (ZERR_FIELDLEN);
	    if (i) {
		*ptr++ = ' ';
		len--;
	    }
	    *ptr++ = '0';
	    *ptr++ = 'x';
	    len -= 2;
	} 
	if (len < 3)
	    return (ZERR_FIELDLEN);
	*ptr++ = cnvt_itox(field[i] >> 4);
	*ptr++ = cnvt_itox(field[i] & 15);
	len -= 2;
    }

    *ptr = '\0';
    return (ZERR_NONE);
}

cnvt_itox(i)
    int i;
{
    i += '0';
    if (i <= '9')
	return (i);
    i += 'A'-'9'-1;
    return (i);
}
