/* This file is part of the Project Athena Zephyr Notification System.
 * It contains source for ZReceiveNotice function.
 *
 *	Created by:	Robert French
 *
 *	$Source$
 *	$Author$
 *
 *	Copyright (c) 1987,1988 by the Massachusetts Institute of Technology.
 *	For copying and distribution information, see the file
 *	"mit-copyright.h". 
 */
/* $Header$ */

#ifndef lint
static char rcsid_ZReceiveNotice_c[] = "$Header$";
#endif

#include <internal.h>

Code_t ZReceiveNotice(notice, from)
    ZNotice_t *notice;
    struct sockaddr_in *from;
{
    char *buffer;
    struct _Z_InputQ *nextq;
    int len, auth, i, j;
    Code_t retval;
    struct sockaddr_in sin;

    if ((retval = Z_WaitForComplete()) != ZERR_NONE)
	return (retval);

    nextq = Z_GetFirstComplete();

    len = nextq->packet_len;
    
    if (!(buffer = (char *) malloc((unsigned) len)))
	return (ENOMEM);

    if (!from)
	from = &sin;

    *from = nextq->from;

    (void) memcpy(buffer, nextq->packet, len);

    auth = nextq->auth;
    Z_RemQueue(nextq);
    
    if ((retval = ZParseNotice(buffer, len, notice)) != ZERR_NONE)
	return (retval);
    notice->z_checked_auth = auth;

    notice->z_dest_realm = "unknown-realm";

    for (i=0; i<__nrealms; i++)
       for (j=0; j<__realm_list[i].realm_config.nservers; j++)
	  if (from->sin_addr.s_addr ==
	      __realm_list[i].realm_config.server_list[j].addr.s_addr) {
	     notice->z_dest_realm = __realm_list[i].realm_config.realm;
	     break;
	  }

    return ZERR_NONE;
}
