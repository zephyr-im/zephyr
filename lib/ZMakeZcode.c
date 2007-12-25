/* This file is part of the Project Athena Zephyr Notification System.
 * It contains source for the ZMakeZcode function.
 *
 *	Created by:	Jeffrey Hutzelman
 *
 *	$Id$
 *
 *	Copyright (c) 1987, 2002 by the Massachusetts Institute of Technology.
 *	For copying and distribution information, see the file
 *	"mit-copyright.h". 
 */

#include <internal.h>
#include <assert.h>

#ifndef lint
static const char rcsid_ZMakeZcode_c[] = "$Id$";
#endif

Code_t ZMakeZcode32(ptr, len, val)
    char *ptr;
    int len;
    unsigned long val;
{
    unsigned char buf[4];
    buf[0] = (val >> 24) & 0xff;
    buf[1] = (val >> 16) & 0xff;
    buf[2] = (val >>  8) & 0xff;
    buf[3] =  val        & 0xff;
    return ZMakeZcode(ptr, len, buf, 4);
}

Code_t ZMakeZcode(ptr, len, field, num)
    register char *ptr;
    int len;
    unsigned char *field;
    int num;
{
    int i;

    /*
     * This optimistic check lets us discover quickly if the buffer
     * is not even large enough to hold the field without escapes.
     * It also insures we'll have space for the leading 'Z' and the
     * trailing NUL.  Note that this does _not_ remove the need for
     * checking length as we encode.
     */
    if (len < num + 2)
      return ZERR_FIELDLEN;
    *ptr++ = 'Z';
    --len;
    for (i=0;i<num;i++) {
        switch (field[i]) {
            case 0x00:
                if (len < 3)
                    return ZERR_FIELDLEN;
                *ptr++ = 0xff;
                *ptr++ = 0xf0;
                len -= 2;
                continue;

            case 0xff:
                if (len < 3)
                    return ZERR_FIELDLEN;
                *ptr++ = 0xff;
                *ptr++ = 0xf1;
                len -= 2;
                continue;

            default:
                if (len < 2)
                    return ZERR_FIELDLEN;
                *ptr++ = field[i];
                len--;
        }
    }

    *ptr = '\0';
    return ZERR_NONE;
}
