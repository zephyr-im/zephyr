/* This file is part of the Project Athena Zephyr Notification System.
 * It contains source for the ZSendNotice function.
 *
 *	Created by:	Robert French
 *
 *	$Id$
 *
 *	Copyright (c) 1987 by the Massachusetts Institute of Technology.
 *	For copying and distribution information, see the file
 *	"mit-copyright.h". 
 */

#ifndef lint
static const char rcsid_ZSendNotice_c[] = "$Id$";
#endif

#include <internal.h>

Code_t
ZSendNotice(ZNotice_t *notice,
	    Z_AuthProc cert_routine)
{
    return(ZSrvSendNotice(notice, cert_routine, Z_XmitFragment));
}

/* Despite its name, this is not used by the server */
Code_t
ZSrvSendNotice(ZNotice_t *notice,
	       Z_AuthProc cert_routine,
	       Code_t (*send_routine)(ZNotice_t *, char *, int, int))
{    
    Code_t retval;
    ZNotice_t newnotice;
    char *buffer;
    int len;

    if ((retval = ZFormatNotice(notice, &buffer, &len, 
				cert_routine)) != ZERR_NONE)
	return (retval);

    if ((retval = ZParseNotice(buffer, len, &newnotice)) != ZERR_NONE) {
	free(buffer);
	return (retval);
    }

    
    retval = Z_SendFragmentedNotice(&newnotice, len, cert_routine,
				    send_routine);

    free(buffer);

    return (retval);
}
