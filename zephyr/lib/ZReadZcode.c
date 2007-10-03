/* This file is part of the Project Athena Zephyr Notification System.
 * It contains source for the ZReadZcode function.
 *
 *	Created by:	Jeffrey Hutzelman
 *
 *	$Id$
 *
 *	Copyright (c) 1987, 1990, 2002 by the Massachusetts Institute of Technology.
 *	For copying and distribution information, see the file
 *	"mit-copyright.h". 
 */

#ifndef lint
static char rcsid_ZReadZcode_c[] = "$Id$";
#endif /* lint */

#include <internal.h>
#include <assert.h>


#if 0
Code_t
ZReadAsciiOrZcode(char *buf, int buflen, unsigned char *data, int datalen)
{
    if (buf[0] == 'Z')
        return ZReadZcode(buf, buflen, data, datalen);
    else
        return ZReadAscii(buf, buflen, data, datalen);
}

Code_t ZReadZcode32(ptr, value_ptr)
    unsigned char *ptr;
    unsigned long *value_ptr;
{
    abort();
}
#endif

Code_t ZReadZcode(ptr, field, max, len)
    unsigned char *ptr;
    unsigned char *field;
    int max;
    int *len;
{
    int n = 0;

    if (*ptr++ != 'Z')
        return ZERR_BADFIELD;

    while (*ptr && n < max) {
        if (*ptr == 0xff) {
            ptr++;
            switch (*ptr++) {
                case 0xf0: field[n++] = 0x00; continue;
                case 0xf1: field[n++] = 0xff; continue;
                default:   return ZERR_BADFIELD;
            }
        } else {
            field[n++] = *ptr++;
        }
    }
    if (*ptr)
        return (ZERR_BADFIELD);
    *len = n;
    return (ZERR_NONE);
}
