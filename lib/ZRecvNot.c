/* This file is part of the Project Athena Zephyr Notification System.
 * It contains source for ZReceiveNotice function.
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
static char rcsid_ZReceiveNotice_c[] = "$Header$";
#endif lint

#include <zephyr/mit-copyright.h>

#include <zephyr/zephyr_internal.h>

Code_t ZReceiveNotice(notice, from)
    ZNotice_t *notice;
    struct sockaddr_in *from;
{
    char *buffer;
    int len;
    Code_t retval;

    if (!(buffer = malloc(Z_MAXPKTLEN)))
	return (ENOMEM);
    
    if ((retval = ZReceivePacket(buffer, &len, from)) != ZERR_NONE)
	return (retval);

    buffer = realloc(buffer, len); /* XXX */
    
    return (ZParseNotice(buffer, len, notice));
}
