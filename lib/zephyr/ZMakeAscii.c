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

#include <internal.h>
#include <assert.h>

#ifndef lint
static const char rcsid_ZMakeAscii_c[] = "$Id$";
#endif

Code_t ZMakeAscii(ptr, len, field, num)
    register char *ptr;
    int len;
    unsigned char *field;
    int num;
{
    int i;
    register char *itox_chars = "0123456789ABCDEF";

    for (i=0;i<num;i++) {
	/* we need to add "0x" if we are between 4 byte pieces */
	if ((i & 3) == 0) {
	    if (len < (i?4:3))
		return ZERR_FIELDLEN;
	    /* except at the beginning, put a space in before the "0x" */
	    if (i) {
		*ptr++ = ' ';
		len--;
	    }
	    *ptr++ = '0';
	    *ptr++ = 'x';
	    len -= 2;
	} 
	if (len < 3)
	    return ZERR_FIELDLEN;
	*ptr++ = itox_chars[(int) (field[i] >> 4)];
	*ptr++ = itox_chars[(int) (field[i] & 0xf)];
	len -= 2;
    }

    *ptr = '\0';
    return ZERR_NONE;
}

Code_t ZMakeAscii32(ptr, len, value)
    register char *ptr;
    int len;
    unsigned long value;
{
    /* Convert to network byte order and convert last four bytes. */
    value = htonl(value);
    return ZMakeAscii(ptr, len, ((char *)&value) + sizeof(value) - 4, 4);
}

Code_t ZMakeAscii16(ptr, len, value)
    register char *ptr;
    int len;
    unsigned int value;
{
    /* Convert to network byte order and convert last two bytes. */
    value = htons((unsigned short) value);
    return ZMakeAscii(ptr, len, ((char *)&value) + sizeof(value) - 2, 2);
}

