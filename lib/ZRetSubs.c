/* This file is part of the Project Athena Zephyr Notification System.
 * It contains source for the ZRetrieveSubscriptions and
 * ZRetrieveDefaultSubscriptions functions.
 *
 *	Created by:	Robert French
 *
 *	$Id$
 *
 *	Copyright (c) 1987,1988,1991 by the Massachusetts Institute of Technology.
 *	For copying and distribution information, see the file
 *	"mit-copyright.h". 
 */

#include <internal.h>

#ifndef lint
static const char rcsid_ZRetrieveSubscriptions_c[] =
    "$Id$";
#endif

static Code_t Z_RetSubs (register ZNotice_t *, int *, Z_AuthProc);

/* Need STDC definition when possible for unsigned short argument. */
Code_t
ZRetrieveSubscriptions(unsigned short port,
		       int *nsubs)
{
	int retval;
	ZNotice_t notice;
	char asciiport[50];
	
	if (!port)			/* use default port */
	    port = __Zephyr_port;

	retval = ZMakeAscii16(asciiport, sizeof(asciiport), ntohs(port));
	if (retval != ZERR_NONE)
		return (retval);

	(void) memset((char *)&notice, 0, sizeof(notice));
	notice.z_message = asciiport;
	notice.z_message_len = strlen(asciiport)+1;
	notice.z_opcode = CLIENT_GIMMESUBS;

	return(Z_RetSubs(&notice, nsubs, ZAUTH));
}

Code_t
ZRetrieveDefaultSubscriptions(int *nsubs)
{
	ZNotice_t notice;

	(void) memset((char *)&notice, 0, sizeof(notice));
	notice.z_message = (char *) 0;
	notice.z_message_len = 0;
	notice.z_opcode = CLIENT_GIMMEDEFS;

	return(Z_RetSubs(&notice, nsubs, ZNOAUTH));

}

static Code_t
Z_RetSubs(register ZNotice_t *notice,
	  int *nsubs,
	  Z_AuthProc auth_routine)
{
	register int i;
	int retval,nrecv,gimmeack;
	ZNotice_t retnotice;
	char *ptr,*end,*ptr2;
	ZSubscription_t *list = __subscriptions_list;

	retval = ZFlushSubscriptions();

	if (retval != ZERR_NONE && retval != ZERR_NOSUBSCRIPTIONS)
		return (retval);

	if (ZGetFD() < 0)
		if ((retval = ZOpenPort((u_short *)0)) != ZERR_NONE)
			return (retval);

	Z_InitUPnP();

	notice->z_kind = ACKED;
	notice->z_port = __Zephyr_port;
	notice->z_class = ZEPHYR_CTL_CLASS;
	notice->z_class_inst = ZEPHYR_CTL_CLIENT;
	notice->z_sender = 0;
	notice->z_recipient = "";
	notice->z_default_format = "";

	if ((retval = ZSendNotice(notice,auth_routine)) != ZERR_NONE)
		return (retval);

	nrecv = 0;
	gimmeack = 0;
	list = (ZSubscription_t *) 0;

	while (!nrecv || !gimmeack) {
		retval = Z_WaitForNotice (&retnotice, ZCompareMultiUIDPred,
					  &notice->z_multiuid, SRV_TIMEOUT);
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
		if (strcmp(notice->z_version,retnotice.z_version)) {
			ZFreeNotice(&retnotice);
			return(ZERR_VERS);
		}
		if (retnotice.z_kind == SERVACK &&
		    !strcmp(retnotice.z_opcode,notice->z_opcode)) {
			ZFreeNotice(&retnotice);
			gimmeack = 1;
			continue;
		} 

		if (retnotice.z_kind != ACKED) {
			ZFreeNotice(&retnotice);
			return (ZERR_INTERNAL);
		}

		nrecv++;

		end = retnotice.z_message+retnotice.z_message_len;

		__subscriptions_num = 0;
		for (ptr=retnotice.z_message;ptr<end;ptr++)
			if (!*ptr)
				__subscriptions_num++;

		__subscriptions_num = __subscriptions_num / 3;

		list = (ZSubscription_t *)
		    malloc(__subscriptions_num * sizeof(ZSubscription_t));
		if (__subscriptions_num && !list) {
			ZFreeNotice(&retnotice);
			return (ENOMEM);
		}

		ptr = retnotice.z_message;
		for (i = 0; i < __subscriptions_num; i++) {
			list[i].zsub_class = (char *)
			    malloc(strlen(ptr) + 1);
			if (!list[i].zsub_class) {
				ZFreeNotice(&retnotice);
				return (ENOMEM);
			}
			strcpy(list[i].zsub_class, ptr);
			ptr += strlen(ptr)+1;
			list[i].zsub_classinst = (char *)
			    malloc(strlen(ptr) + 1);
			if (!list[i].zsub_classinst) {
				ZFreeNotice(&retnotice);
				return (ENOMEM);
			}
			strcpy(list[i].zsub_classinst, ptr);
			ptr += strlen(ptr)+1;
			ptr2 = ptr;
			list[i].zsub_recipient = (char *)
			    malloc(strlen(ptr2) + 2);
			if (!list[i].zsub_recipient) {
				ZFreeNotice(&retnotice);
				return (ENOMEM);
			}
			if (*ptr2 == '@' || *ptr2 == 0) {
				*list[i].zsub_recipient = '*';
				strcpy(list[i].zsub_recipient + 1, ptr2);
			} else {
				strcpy(list[i].zsub_recipient, ptr2);
			}
			ptr += strlen(ptr)+1;
		}
		ZFreeNotice(&retnotice);
	}

	__subscriptions_list = list;
	__subscriptions_next = 0;
	*nsubs = __subscriptions_num;

	return (ZERR_NONE);
}
