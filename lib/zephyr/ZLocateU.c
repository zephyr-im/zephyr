/* This file is part of the Project Athena Zephyr Notification System.
 * It contains source for the ZLocateUser function.
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
static char rcsid_ZLocateUser_c[] = "$Header$";
#endif lint

#include <zephyr/mit-copyright.h>

#include <zephyr/zephyr_internal.h>

Code_t ZLocateUser(user, nlocs)
    char *user;
    int *nlocs;
{
    register int i, retval;
    ZNotice_t notice, retnotice;
    char *ptr, *end;
    int nrecv, ack;
    fd_set read, setup;
    int nfds;
    int gotone;
    struct timeval tv;

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

    if ((retval = ZSendNotice(&notice, ZAUTH)) != ZERR_NONE)
	return (retval);

    nrecv = ack = 0;

    FD_ZERO(&setup);
    FD_SET(ZGetFD(), &setup);
    nfds = ZGetFD() + 1;

    while (!nrecv || !ack) {
	    tv.tv_sec = 0;
	    tv.tv_usec = 500000;
	    for (i=0;i<HM_TIMEOUT*2;i++) { /* 30 secs in 1/2 sec
					      intervals */
		    gotone = 0;
		    read = setup;
		    if (select(nfds, &read, (fd_set *) 0,
			       (fd_set *) 0, &tv) < 0)
			return (errno);
		    if (FD_ISSET(ZGetFD(), &read))
			i--;		/* make sure we time out the
					   full 30 secs */
		    retval = ZCheckIfNotice(&retnotice,
					    (struct sockaddr_in *)0,
					    ZCompareMultiUIDPred,
					    (char *)&notice.z_multiuid);
		    if (retval == ZERR_NONE) {
			    gotone = 1;
			    break;
		    }
		    if (retval != ZERR_NONOTICE)
			    return(retval);
	    }
		
	    if (!gotone)
		    return(ETIMEDOUT);

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
	    if (!__locate_list)
		    return (ENOMEM);
	
	    for (ptr=retnotice.z_message, i=0;i<__locate_num;i++) {
		    __locate_list[i].host = malloc((unsigned)strlen(ptr)+1);
		    if (!__locate_list[i].host)
			    return (ENOMEM);
		    (void) strcpy(__locate_list[i].host, ptr);
		    ptr += strlen(ptr)+1;
		    __locate_list[i].time = malloc((unsigned)strlen(ptr)+1);
		    if (!__locate_list[i].time)
			    return (ENOMEM);
		    (void) strcpy(__locate_list[i].time, ptr);
		    ptr += strlen(ptr)+1;
		    __locate_list[i].tty = malloc((unsigned)strlen(ptr)+1);
		    if (!__locate_list[i].tty)
			    return (ENOMEM);
		    (void) strcpy(__locate_list[i].tty, ptr);
		    ptr += strlen(ptr)+1;
	    }

	    ZFreeNotice(&retnotice);
    }

    __locate_next = 0;
    *nlocs = __locate_num;
	
    return (ZERR_NONE);
}
