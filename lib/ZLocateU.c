/* This file is part of the Project Athena Zephyr Notification System.
 * It contains source for the ZLocateUser function.
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

Code_t ZLocateUser(user,nlocs)
	char *user;
	int *nlocs;
{
	int locate_pred();
	
	int i,retval,auth;
	ZNotice_t notice,retnotice;
	ZPacket_t buffer;
	char *ptr,*end;
	
	retval = ZFlushLocations();

	if (retval != ZERR_NONE && retval != ZERR_NOLOCATIONS)
		return (retval);
	
	notice.z_kind = ACKED;
	notice.z_port = 0;
	notice.z_class = LOCATE_CLASS;
	notice.z_class_inst = user;
	notice.z_opcode = LOCATE_LOCATE;
	notice.z_sender = 0;
	notice.z_recipient = "";
	notice.z_message_len = 0;

	if ((retval = ZSendNotice(&notice,0)) != ZERR_NONE)
		return (retval);

	if ((retval = ZIfNotice(buffer,sizeof buffer,&retnotice,&auth,
				locate_pred,(char *)&notice.z_uid)) !=
	    ZERR_NONE)
		return (retval);

	if (retnotice.z_kind != SERVACK)
		return (ZERR_INTERNAL);

	end = retnotice.z_message+retnotice.z_message_len+1;

	__locate_num = 0;
	
	for (ptr=retnotice.z_message;ptr<end;ptr++)
		if (!*ptr)
			__locate_num++;

	__locate_list = (char **)malloc(__locate_num*sizeof(char *));
	if (!__locate_list)
		return (ENOMEM);
	
	for (ptr=retnotice.z_message,i=0;i<__locate_num;i++) {
		__locate_list[i] = (char *)malloc(strlen(ptr)+1);
		if (!__locate_list[i])
			return (ENOMEM);
		strcpy(__locate_list[i],ptr);
		ptr += strlen(ptr)+1;
	}

	__locate_next = 0;
	*nlocs = __locate_num;
	
	return (ZERR_NONE);
}

static int locate_pred(notice,uid)
	ZNotice_t *notice;
	ZUnique_Id_t *uid;
{
	return (ZCompareUID(uid,&notice->z_uid));
}
