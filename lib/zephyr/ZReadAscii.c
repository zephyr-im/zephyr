/* This file is part of the Project Athena Zephyr Notification System.
 * It contains source for the ZReadAscii function.
 *
 *	Created by:	Robert French
 *
 *	$Source$
 *	$Author$
 *
 *	Copyright (c) 1987, 1990 by the Massachusetts Institute of Technology.
 *	For copying and distribution information, see the file
 *	"mit-copyright.h". 
 */
/* $Header$ */

#ifndef lint
static
#ifdef __STDC__
    const
#endif
    char rcsid_ZReadAscii_c[] =
    "$Header$";
#endif /* lint */

#include <zephyr/mit-copyright.h>

#include <zephyr/zephyr_internal.h>

#if 0
static __inline__
int
Z_cnvt_xtoi (char c)
{
    c -= '0';
    if (c < 10)
	return c;
    c -= 'A'-'9'-1;
    if (c < 16)
	return c;
    return -1;
}
#endif

#define Z_cnvt_xtoi(c)  ((temp=(c)-'0'),(temp<10)?temp:((temp-='A'-'9'-1),(temp<16)?temp:-1))

int ZReadAscii(ptr, len, field, num)
    char *ptr;
    int len;
    unsigned char *field;
    int num;
{
    int i;
    unsigned int hexbyte;
    register char c1, c2;
#ifdef Z_cnvt_xtoi
    register unsigned int temp;
#endif

    for (i=0;i<num;i++) {
	if (*ptr == ' ') {
	    ptr++;
	    if (--len < 0)
		return ZERR_BADFIELD;
	} 
	if (ptr[0] == '0' && ptr[1] == 'x') {
	    ptr += 2;
	    len -= 2;
	    if (len < 0)
		return ZERR_BADFIELD;
	} 
	c1 = Z_cnvt_xtoi(ptr[0]);
	if (c1 < 0)
		return ZERR_BADFIELD;
	c2 = Z_cnvt_xtoi(ptr[1]);
	if (c2 < 0)
		return ZERR_BADFIELD;
	hexbyte = (c1 << 4) | c2;
	field[i] = hexbyte;
	ptr += 2;
	len -= 2;
	if (len < 0)
	    return ZERR_BADFIELD;
    }

    return *ptr ? ZERR_BADFIELD : ZERR_NONE;
}
