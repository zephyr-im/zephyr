/* This file is part of the Project Athena Zephyr Notification System.
 * It contains source for the ZSubscribeTo, ZUnsubscribeTo, and
 * ZCancelSubscriptions functions.
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
static char rcsid_ZSubscriptions_c[] = "$Header$";
#endif lint

#include <zephyr/mit-copyright.h>

#include <zephyr/zephyr_internal.h>

Code_t ZSubscribeTo(sublist, nitems, port)
    ZSubscription_t *sublist;
    int nitems;
    u_short port;
{
    return (Z_Subscriptions(sublist, nitems, port, CLIENT_SUBSCRIBE, 1));
}

Code_t ZUnsubscribeTo(sublist, nitems, port)
    ZSubscription_t *sublist;
    int nitems;
    u_short port;
{
    return (Z_Subscriptions(sublist, nitems, port, CLIENT_UNSUBSCRIBE, 1));
}

Code_t ZCancelSubscriptions(port)
    u_short port;
{
    return (Z_Subscriptions((ZSubscription_t *)0, 0, port,
			    CLIENT_CANCELSUB, 0));
}

Z_Subscriptions(sublist, nitems, port, opcode, authit)
    ZSubscription_t *sublist;
    int nitems;
    u_short port;
    char *opcode;
    int authit;
{
    int i, retval;
    ZNotice_t notice, retnotice;
    char **list;
	
    list = (char **)malloc((unsigned)nitems*3*sizeof(char *));
    if (!list)
	return (ENOMEM);
	
    notice.z_kind = ACKED;
    notice.z_port = port;
    notice.z_class = ZEPHYR_CTL_CLASS;
    notice.z_class_inst = ZEPHYR_CTL_CLIENT;
    notice.z_opcode = opcode;
    notice.z_sender = 0;
    notice.z_recipient = "";
    notice.z_num_other_fields = 0;
    notice.z_default_format = "";
    notice.z_message_len = 0;

    for (i=0;i<nitems;i++) {
	list[i*3] = sublist[i].class;
	list[i*3+1] = sublist[i].classinst;
	if (sublist[i].recipient && *sublist[i].recipient &&
	    *sublist[i].recipient != '*')
	    list[i*3+2] = ZGetSender();
	else
	    list[i*3+2] = "";
    }
	
    retval = ZSendList(&notice, list, nitems*3, ZAUTH);
    if (retval != ZERR_NONE && !authit)
	retval = ZSendList(&notice, list, nitems*3, ZNOAUTH);
	
    free((char *)list);

    if (retval != ZERR_NONE)
	return (retval);

    if ((retval = ZIfNotice(&retnotice, (struct sockaddr_in *)0, 
			    ZCompareUIDPred, (char *)&notice.z_uid)) !=
	ZERR_NONE)
	return (retval);

    ZFreeNotice(&retnotice);
    
    if (retnotice.z_kind == SERVNAK)
	return (ZERR_SERVNAK);
	
    if (retnotice.z_kind != SERVACK)
	return (ZERR_INTERNAL);

    return (ZERR_NONE);
}
