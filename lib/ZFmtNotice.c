/* This file is part of the Project Athena Zephyr Notification System.
 * It contains source for the ZFormatNotice function.
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
static char rcsid_ZFormatNotice_c[] = "$Header$";
#endif lint

#include <zephyr/mit-copyright.h>

#include <zephyr/zephyr_internal.h>

Code_t ZFormatNotice(notice, buffer, ret_len, cert_routine)
    ZNotice_t *notice;
    char **buffer;
    int *ret_len;
    int (*cert_routine)();
{
    char header[Z_MAXHEADERLEN];
    int hdrlen;
    Code_t retval;

    if ((retval = Z_FormatHeader(notice, header, sizeof(header), &hdrlen, 
				 cert_routine)) != ZERR_NONE)
	return (retval);

    *ret_len = hdrlen+notice->z_message_len;

    if (!(*buffer = (char *)malloc((unsigned)*ret_len)))
	return (ENOMEM);

    bcopy(header, *buffer, hdrlen);
    bcopy(notice->z_message, *buffer+hdrlen, notice->z_message_len);

    return (ZERR_NONE);
}
