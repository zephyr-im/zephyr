/* This file is part of the Project Athena Zephyr Notification System.
 * It contains source for the ZFormatRawNotice function.
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
static char rcsid_ZFormatRawNotice_c[] = "$Header$";
#endif lint

#include <zephyr/mit-copyright.h>

#include <zephyr/zephyr.h>

Code_t ZFormatRawNotice(notice, buffer, ret_len, cert_routine)
    ZNotice_t *notice;
    char **buffer;
    int *ret_len;
    int (*cert_routine)();
{
    char header[Z_MAXHEADERLEN];
    char *ptr;
    int hdrlen;
    Code_t retval;

    if ((retval = Z_FormatRawHeader(notice, header, sizeof(header), &hdrlen, 
				    cert_routine)) != ZERR_NONE)
	return (retval);

    *ret_len = hdrlen+notice->z_message_len;

    if (!(*buffer = malloc(*ret_len)))
	return (ENOMEM);

    bcopy(notice->z_message, *buffer+hdrlen, notice->z_message_len);

    return (ZERR_NONE);
}
