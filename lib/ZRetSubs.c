/* This file is part of the Project Athena Zephyr Notification System.
 * It contains source for the ZRetrieveSubscriptions function.
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

#include <zephyr/mit-copyright.h>

#include <zephyr/zephyr_internal.h>

Code_t ZRetrieveSubscriptions(port,nsubs)
	u_short port;
	int *nsubs;
{
	int subscription_pred();
	
	int i,retval;
	ZNotice_t notice,retnotice;
	ZPacket_t buffer;
	char *ptr,*end;
	
	retval = ZFlushSubscriptions();

	if (retval != ZERR_NONE && retval != ZERR_NOSUBSCRIPTIONS)
		return (retval);
	
	notice.z_kind = ACKED;
	notice.z_port = port;
	notice.z_class = ZEPHYR_CTL_CLASS;
	notice.z_class_inst = ZEPHYR_CTL_CLIENT;
	notice.z_opcode = CLIENT_GIMMESUBS;
	notice.z_sender = 0;
	notice.z_recipient = "";
	notice.z_message_len = 0;

	if ((retval = ZSendNotice(&notice,ZAUTH)) != ZERR_NONE)
		return (retval);

	if ((retval = Z_NoAuthIfNotice(buffer,sizeof buffer,&retnotice,
				ZCompareUIDPred,(char *)&notice.z_uid)) !=
	    ZERR_NONE)
		return (retval);

	if (retnotice.z_kind == SERVNAK)
		return (ZERR_SERVNAK);
	
	if (retnotice.z_kind != SERVACK)
		return (ZERR_INTERNAL);

	end = retnotice.z_message+retnotice.z_message_len;

	__subscriptions_num = 0;
	
	for (ptr=retnotice.z_message;ptr<end;ptr++)
		if (!*ptr)
			__subscriptions_num++;

	__subscriptions_num /= 3;

	__subscriptions_list = (ZSubscription_t *)malloc((unsigned)__subscriptions_num*
					       sizeof(ZSubscription_t));
	if (!__subscriptions_list)
		return (ENOMEM);
	
	for (ptr=retnotice.z_message,i=0;i<__subscriptions_num;i++) {
		__subscriptions_list[i].class = (char *)
			malloc((unsigned)strlen(ptr)+1);
		if (!__subscriptions_list[i].class)
			return (ENOMEM);
		(void) strcpy(__subscriptions_list[i].class,ptr);
		ptr += strlen(ptr)+1;
		__subscriptions_list[i].classinst = (char *)
			malloc((unsigned)strlen(ptr)+1);
		if (!__subscriptions_list[i].classinst)
			return (ENOMEM);
		(void) strcpy(__subscriptions_list[i].classinst,ptr);
		ptr += strlen(ptr)+1;
		__subscriptions_list[i].recipient = (char *)
			malloc((unsigned)strlen(ptr)+1);
		if (!__subscriptions_list[i].recipient)
			return (ENOMEM);
		(void) strcpy(__subscriptions_list[i].recipient,ptr);
		ptr += strlen(ptr)+1;
	}

	__subscriptions_next = 0;
	*nsubs = __subscriptions_num;

	if (strcmp(retnotice.z_opcode,CLIENT_INCOMPSUBS))
		return (ZERR_NONE);
	return (ZERR_TOOMANYSUBS);
}
