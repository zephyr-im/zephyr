/* This file is part of the Project Athena Zephyr Notification System.
 * It contains source for ZReceiveNotice function.
 *
 *	Created by:	Robert French
 *
 *	$Id$
 *
 *	Copyright (c) 1987,1988 by the Massachusetts Institute of Technology.
 *	For copying and distribution information, see the file
 *	"mit-copyright.h". 
 */

#ifndef lint
static char rcsid_ZReceiveNotice_c[] = "$Id$";
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

    notice->z_dest_galaxy = "unknown-galaxy";

    if (__ngalaxies == 1) {
	/* assume everything is in the same galaxy */

	notice->z_dest_galaxy = __galaxy_list[0].galaxy_config.galaxy;
    } else {
	for (i=0; i<__ngalaxies; i++)
	    for (j=0; j<__galaxy_list[i].galaxy_config.nservers; j++)
		if (from->sin_addr.s_addr ==
		    __galaxy_list[i].galaxy_config.server_list[j].addr.s_addr) {
		    notice->z_dest_galaxy =
			__galaxy_list[i].galaxy_config.galaxy;
		    break;
		}
    }

    return ZERR_NONE;
}
