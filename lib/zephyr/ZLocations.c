/* This file is part of the Project Athena Zephyr Notification System.
 * It contains source for the ZSetLocation, ZUnsetLocation, ZHideLocation,
 * and ZUnhideLocation functions.
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
static char rcsid_ZLocations_c[] = "$Header$";
#endif lint

#include <zephyr/mit-copyright.h>

#include <zephyr/zephyr_internal.h>

#include <pwd.h>
#include <sys/file.h>
#include <sys/param.h>
#include <netdb.h>

uid_t getuid();

Code_t ZSetLocation()
{
	char bfr[BUFSIZ];
	int quiet;
	struct passwd *pw;
	
        quiet = 0;
	/* XXX a uid_t is a u_short (now), but getpwuid wants an int. AARGH! */
	if (pw = getpwuid((int) getuid())) {
		(void) sprintf(bfr,"%s/.hideme",pw->pw_dir);
		quiet = !access(bfr,F_OK);
	} 

	return (Z_SendLocation(LOGIN_CLASS,quiet?LOGIN_QUIET_LOGIN:
			       LOGIN_USER_LOGIN,ZAUTH));
}

Code_t ZUnsetLocation()
{
	return (Z_SendLocation(LOGIN_CLASS,LOGIN_USER_LOGOUT,ZNOAUTH));
}

Code_t ZHideLocation()
{
	return (Z_SendLocation(LOCATE_CLASS,LOCATE_HIDE,ZAUTH));
}

Code_t ZUnhideLocation()
{
	return (Z_SendLocation(LOCATE_CLASS,LOCATE_UNHIDE,ZAUTH));
}

Z_SendLocation(class,opcode,auth)
	char *class;
	char *opcode;
	int (*auth)();
{
	char *ttyname(),*ctime();

	int retval;
	long ourtime;
	ZNotice_t notice,retnotice;
	ZPacket_t buffer;
	char *bptr[3],host[MAXHOSTNAMELEN],mytty[100];
	struct hostent *hent;

	notice.z_kind = ACKED;
	notice.z_port = 0;
	notice.z_class = class;
	notice.z_class_inst = ZGetSender();
	notice.z_opcode = opcode;
	notice.z_sender = 0;
	notice.z_recipient = "";

	if (gethostname(host,MAXHOSTNAMELEN) < 0)
		return (errno);

	hent = gethostbyname(host);
	if (!hent)
		bptr[0] = "unknown";
	else {
		(void) strcpy(host,hent->h_name);
		bptr[0] = host;
	} 

	ourtime = time((long *)0);
	bptr[1] = ctime(&ourtime);
	bptr[1][strlen(bptr[1])-1] = '\0';

	strcpy(mytty,ttyname(0));
	bptr[2] = rindex(mytty,'/');
	if (bptr[2])
		bptr[2]++;
	else
		bptr[2] = mytty;
	
	if ((retval = ZSendList(&notice,bptr,2,auth)) != ZERR_NONE)
		return (retval);

	if ((retval = ZIfNotice(buffer,sizeof buffer,&retnotice,(int *)0,
			        ZCompareUIDPred,(char *)&notice.z_uid)) !=
	    ZERR_NONE)
		return (retval);

	if (retnotice.z_kind == SERVNAK) {
		if (!retnotice.z_message_len)
			return (ZERR_SERVNAK);
		if (!strcmp(retnotice.z_message,ZSRVACK_NOTSENT))
			return (ZERR_AUTHFAIL);
		if (!strcmp(retnotice.z_message,ZSRVACK_FAIL))
			return (ZERR_LOGINFAIL);
		return (ZERR_SERVNAK);
	} 
	
	if (retnotice.z_kind != SERVACK)
		return (ZERR_INTERNAL);

	if (!retnotice.z_message_len)
		return (ZERR_INTERNAL);

	if (strcmp(retnotice.z_message,ZSRVACK_SENT) &&
	    strcmp(retnotice.z_message,ZSRVACK_NOTSENT))
		return (ZERR_INTERNAL);
	
	return (ZERR_NONE);
}
