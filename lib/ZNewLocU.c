/* This file is part of the Project Athena Zephyr Notification System.
 * It contains source for the ZNewLocateUser function.
 *
 *	Created by:	Robert French
 *
 *	$Source$
 *	$Author$
 *
 *	Copyright (c) 1987,1988,1991 by the Massachusetts Institute of Technology.
 *	For copying and distribution information, see the file
 *	"mit-copyright.h". 
 */
/* $Header$ */

#ifndef lint
static char rcsid_ZNewLocateUser_c[] =
    "$Zephyr: /mit/zephyr/src/lib/RCS/ZNewLocateUser.c,v 1.4 90/12/20 03:10:34 raeburn Exp $";
#endif

#include <zephyr/mit-copyright.h>

#include <zephyr/zephyr_internal.h>

#ifdef _AIX
#include <sys/select.h>
#endif

Code_t ZNewLocateUser(user, nlocs, auth)
    char *user;
    int *nlocs;
    int (*auth)();
{
    register int i, retval;
    ZNotice_t notice, retnotice;
    char *ptr, *end;
    int nrecv, ack;

    retval = ZFlushLocations();

    if (retval != ZERR_NONE && retval != ZERR_NOLOCATIONS)
	return (retval);
	
    if (ZGetFD() < 0)
	    if ((retval = ZOpenPort((u_short *)0)) != ZERR_NONE)
		    return (retval);

    (void) bzero((char *)&notice, sizeof(notice));
    notice.z_kind = ACKED;
    notice.z_port = __Zephyr_port;
    notice.z_class = LOCATE_CLASS;
    notice.z_class_inst = user;
    notice.z_opcode = LOCATE_LOCATE;
    notice.z_sender = 0;
    notice.z_recipient = "";
    notice.z_default_format = "";
    notice.z_message_len = 0;

    if ((retval = ZSendNotice(&notice, auth)) != ZERR_NONE)
	return (retval);

    nrecv = ack = 0;

    while (!nrecv || !ack) {
	    retval = Z_WaitForNotice (&retnotice, ZCompareMultiUIDPred,
				      &notice.z_multiuid, SRV_TIMEOUT);
	    if (retval == ZERR_NONOTICE)
	      return ETIMEDOUT;
	    else if (retval != ZERR_NONE)
	      return retval;

	    if (retnotice.z_kind == SERVNAK) {
		    ZFreeNotice(&retnotice);
		    return (ZERR_SERVNAK);
	    }
	    /* non-matching protocol version numbers means the
	       server is probably an older version--must punt */
	    if (strcmp(notice.z_version,retnotice.z_version)) {
		    ZFreeNotice(&retnotice);
		    return(ZERR_VERS);
	    }
	    if (retnotice.z_kind == SERVACK &&
		!strcmp(retnotice.z_opcode,LOCATE_LOCATE)) {
		    ack = 1;
		    ZFreeNotice (&retnotice);
		    continue;
	    } 	

	    if (retnotice.z_kind != ACKED) {
		    ZFreeNotice(&retnotice);
		    return (ZERR_INTERNAL);
	    }
	    nrecv++;

	    end = retnotice.z_message+retnotice.z_message_len;

	    __locate_num = 0;
	
	    for (ptr=retnotice.z_message;ptr<end;ptr++)
		    if (!*ptr)
			    __locate_num++;

	    __locate_num /= 3;

	    __locate_list = (ZLocations_t *)malloc((unsigned)__locate_num*
						   sizeof(ZLocations_t));
	    if (!__locate_list) {
		    ZFreeNotice (&retnotice);
		    return (ENOMEM);
	    }
	
	    for (ptr=retnotice.z_message, i=0;i<__locate_num;i++) {
		    __locate_list[i].host = malloc((unsigned)strlen(ptr)+1);
		    if (!__locate_list[i].host) {
		    nomem:
			    ZFreeNotice (&retnotice);
			    return (ENOMEM);
		    }
		    (void) strcpy(__locate_list[i].host, ptr);
		    ptr += strlen(ptr)+1;
		    __locate_list[i].time = malloc((unsigned)strlen(ptr)+1);
		    if (!__locate_list[i].time)
			    goto nomem;
		    (void) strcpy(__locate_list[i].time, ptr);
		    ptr += strlen(ptr)+1;
		    __locate_list[i].tty = malloc((unsigned)strlen(ptr)+1);
		    if (!__locate_list[i].tty)
			    goto nomem;
		    (void) strcpy(__locate_list[i].tty, ptr);
		    ptr += strlen(ptr)+1;
	    }

	    ZFreeNotice(&retnotice);
    }

    __locate_next = 0;
    *nlocs = __locate_num;
	
    return (ZERR_NONE);
}
