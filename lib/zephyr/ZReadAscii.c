/* This file is part of the Project Athena Zephyr Notification System.
 * It contains source for the ZReadAscii function.
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
static char rcsid_ZReadAscii_c[] = "$Header$";
#endif lint

#include <zephyr/mit-copyright.h>

#include <zephyr/zephyr_internal.h>

int ZReadAscii(ptr, len, field, num)
    char *ptr;
    int len;
    unsigned char *field;
    int num;
{
    int i;
    unsigned int hexbyte;
    char bfr[3];

    for (i=0;i<num;i++) {
	if (*ptr == ' ') {
	    ptr++;
	    if (--len < 0)
		return (ZERR_BADFIELD);
	} 
	if (ptr[0] == '0' && ptr[1] == 'x') {
	    ptr += 2;
	    len -= 2;
	    if (len < 0)
		return (ZERR_BADFIELD);
	} 
	bfr[0] = ptr[0];
	bfr[1] = ptr[1];
	bfr[2] = '\0';
	if (!bfr[0] || !bfr[1])
	    return (ZERR_BADFIELD);
	(void) sscanf(bfr, "%x", &hexbyte);
	field[i] = hexbyte;
	ptr += 2;
	len -= 2;
	if (len < 0)
	    return (ZERR_BADFIELD);
    }

    if (*ptr)
	return (ZERR_BADFIELD);

    return (ZERR_NONE);
}
