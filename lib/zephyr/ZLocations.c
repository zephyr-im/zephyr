/* This file is part of the Project Athena Zephyr Notification System.
 * It contains source for the ZSetLocation.c function.
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

#include <pwd.h>
#include <sys/file.h>

Code_t ZSetLocation()
{
	int retval,quiet;
	ZNotice_t notice,retnotice;
	ZPacket_t buffer;
	char bfr[BUFSIZ];
	struct passwd *pw;
	
        quiet = 0;
	if (pw = getpwuid(getuid())) {
		sprintf(bfr,"%s/.hideme",pw->pw_dir);
		quiet = !access(bfr,F_OK);
	} 
	
	notice.z_kind = ACKED;
	notice.z_port = 0;
	notice.z_class = LOGIN_CLASS;
	notice.z_class_inst = ZGetSender();
	notice.z_opcode = quiet?LOGIN_QUIET_LOGIN:LOGIN_USER_LOGIN;
	notice.z_sender = 0;
	notice.z_recipient = "";
	notice.z_message_len = 0;

	if ((retval = ZSendNotice(&notice,1)) != ZERR_NONE)
		return (retval);

	if ((retval = ZIfNotice(buffer,sizeof buffer,&retnotice,0,
			        ZCompareUID,(char *)&notice.z_uid)) !=
	    ZERR_NONE)
		return (retval);

	if (retnotice.z_kind == SERVNAK)
		return (ZERR_SERVNAK);
	
	if (retnotice.z_kind != SERVACK)
		return (ZERR_INTERNAL);

	return (ZERR_NONE);
}
