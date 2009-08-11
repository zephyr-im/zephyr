/* This file is part of the Project Athena Zephyr Notification System.
 * It contains source for the ZSetLocation, ZUnsetLocation, and
 * ZFlushMyLocations functions.
 *
 *	Created by:	Robert French
 *
 *	$Id$
 *
 *	Copyright (c) 1987,1988,1991 by the Massachusetts Institute of Technology.
 *	For copying and distribution information, see the file
 *	"mit-copyright.h". 
 */

#ifndef lint
static const char rcsid_ZLocations_c[] =
    "$Id$";
#endif

#include <internal.h>

#include <pwd.h>

static char host[MAXHOSTNAMELEN], mytty[MAXPATHLEN];
static int location_info_set = 0;

Code_t
ZInitLocationInfo(char *hostname,
		  char *tty)
{
    char *ttyp, *p;
    struct hostent *hent;

    if (hostname) {
	strcpy(host, hostname);
    } else {
	if (gethostname(host, MAXHOSTNAMELEN) < 0)
	    return (errno);
	hent = gethostbyname(host);
	if (hent) {
	   (void) strncpy(host, hent->h_name, sizeof(host));
	   host[sizeof(host) - 1] = '\0';
	}
    }
    if (tty) {
	strcpy(mytty, tty);
    } else {
	ttyp = ttyname(0);
	if (ttyp && *ttyp) {
	    p = strchr(ttyp + 1, '/');
	    strcpy(mytty, (p) ? p + 1 : ttyp);
	} else {
	    strcpy(mytty, "unknown");
	}
    }
    location_info_set = 1;
    return (ZERR_NONE);
}

Code_t
ZSetLocation(char *exposure)
{
    return (Z_SendLocation(LOGIN_CLASS, exposure, ZAUTH, 
			   "$sender logged in to $1 on $3 at $2"));
}

Code_t
ZUnsetLocation(void)
{
    return (Z_SendLocation(LOGIN_CLASS, LOGIN_USER_LOGOUT, ZNOAUTH, 
			   "$sender logged out of $1 on $3 at $2"));
}

Code_t
ZFlushMyLocations(void)
{
    return (Z_SendLocation(LOGIN_CLASS, LOGIN_USER_FLUSH, ZAUTH, ""));
}

char *
ZParseExposureLevel(char *text)
{
    if (!strcasecmp(text, EXPOSE_NONE))
	return (EXPOSE_NONE);
    else if (!strcasecmp(text, EXPOSE_OPSTAFF))
	return (EXPOSE_OPSTAFF);
    else if (!strcasecmp(text, EXPOSE_REALMVIS))
	return (EXPOSE_REALMVIS);
    else if (!strcasecmp(text, EXPOSE_REALMANN))
	return (EXPOSE_REALMANN);
    else if (!strcasecmp(text, EXPOSE_NETVIS))
	return (EXPOSE_NETVIS);
    else if (!strcasecmp(text, EXPOSE_NETANN))
	return (EXPOSE_NETANN);
    else
	return(NULL);
}

/* lifted from lib/ZSendPkt.c wait_for_hmack, but waits for SERVACK instead */
static int
wait_for_srvack(ZNotice_t *notice, void *uid)
{
    return ((notice->z_kind == SERVACK || notice->z_kind == SERVNAK)
	    && ZCompareUID(&notice->z_uid, (ZUnique_Id_t *)uid));
}

Code_t
Z_SendLocation(char *class,
	       char *opcode,
	       Z_AuthProc auth,
	       char *format)
{
    int retval;
    time_t ourtime;
    ZNotice_t notice, retnotice;
    char *bptr[3];
    short wg_port = ZGetWGPort();

    if (!location_info_set)
	ZInitLocationInfo(NULL, NULL);

    memset((char *)&notice, 0, sizeof(notice));
    notice.z_kind = ACKED;
    notice.z_port = (u_short) ((wg_port == -1) ? 0 : wg_port);
    notice.z_class = class;
    notice.z_class_inst = ZGetSender();
    notice.z_opcode = opcode;
    notice.z_sender = 0;
    notice.z_recipient = "";
    notice.z_num_other_fields = 0;
    notice.z_default_format = format;

    bptr[0] = host;
    ourtime = time((time_t *)0);
    bptr[1] = ctime(&ourtime);
    bptr[1][strlen(bptr[1])-1] = '\0';
    bptr[2] = mytty;

    if ((retval = ZSendList(&notice, bptr, 3, auth)) != ZERR_NONE)
	return (retval);

    retval = Z_WaitForNotice (&retnotice, wait_for_srvack, &notice.z_uid,
			      SRV_TIMEOUT);
    if (retval != ZERR_NONE)
      return retval;

    if (retnotice.z_kind == SERVNAK) {
	if (!retnotice.z_message_len) {
	    ZFreeNotice(&retnotice);
	    return (ZERR_SERVNAK);
	}
	if (!strcmp(retnotice.z_message, ZSRVACK_NOTSENT)) {
	    ZFreeNotice(&retnotice);
	    return (ZERR_AUTHFAIL);
	}
	if (!strcmp(retnotice.z_message, ZSRVACK_FAIL)) {
	    ZFreeNotice(&retnotice);
	    return (ZERR_LOGINFAIL);
	}
	ZFreeNotice(&retnotice);
	return (ZERR_SERVNAK);
    } 
	
    if (retnotice.z_kind != SERVACK) {
	ZFreeNotice(&retnotice);
	return (ZERR_INTERNAL);
    }

    if (!retnotice.z_message_len) {
	ZFreeNotice(&retnotice);
	return (ZERR_INTERNAL);
    }

    if (strcmp(retnotice.z_message, ZSRVACK_SENT) &&
	strcmp(retnotice.z_message, ZSRVACK_NOTSENT)) {
	ZFreeNotice(&retnotice);
	return (ZERR_INTERNAL);
    }

    ZFreeNotice(&retnotice);
	
    return (ZERR_NONE);
}
