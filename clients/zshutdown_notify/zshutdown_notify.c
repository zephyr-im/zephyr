/*
 *	$Source$
 *	$Author$
 *	$Locker$
 *	$Log$
 *	Revision 1.1  1987-08-08 03:42:52  tony
 *	Initial revision
 *
 */

#ifndef lint
static char *rcsid_zshutdown_notify_c = "$Header$";
#endif	lint

/* This file is part of the Project Athena Zephyr Notification System.
 * It contains code for "zshutdown_notify", a utility called by
 * shutdown(8) to do Zephyr notification on shutdown.
 *
 *	Created by:	C. Anthony Della Fera
 *
 *	$Source$
 *	$Author$
 *
 *	Copyright (c) 1987 by the Massachusetts Institute of Technology.
 *	For copying and distribution information, see the file
 *	"mit-copyright.h". 
 */

#include <zephyr/mit-copyright.h>

#include <zephyr/zephyr.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdio.h>

#ifndef lint
#ifndef SABER
static char rcsid_zlogin_c[] = "$Header$";
#endif SABER
#endif lint

#define N_KIND		UNSAFE
#define N_CLASS_ROOT	"FILSRV"
#define N_CLASS_INST	"STATUS"
#define N_OPCODE	"SHUTDOWN"
#define N_DEF_FORMAT	"@bold(Shutdown message from $1 at $time)\n@center(System going down, message is:)\n\n$2\n\n@center(@bold($3))\n@center(@bold($4))"
#define N_FIELD_CNT	4

/*
 * Standard warning strings appended as extra fields to
 * the message body.
 */

static char warn1[] = "Please detach any filesystems you may have";
static char warn2[] = "attached from this host!";

main(argc,argv)
    int argc;
    char *argv[];
{
    ZNotice_t notice, retnotice;
    struct hostent *hp;
    int retval;
    char class_str[BUFSIZ];
    char hostname[MAXHOSTNAMELEN];
    char msgbuff[BUFSIZ], message[Z_MAXPKTLEN], *ptr;
    char *msg[N_FIELD_CNT];

    msg[0] = hostname;
    msg[1] = message;
    msg[2] = warn1;
    msg[3] = warn2;

    if ((retval = ZInitialize()) != ZERR_NONE) {
	com_err(argv[0], retval, "while initializing");
	exit(1);
    } 

    if (gethostname(hostname, MAXHOSTNAMELEN) < 0) {
	com_err(argv[0], errno, "while finding hostname");
	exit(1);
    }

    if ((hp = gethostbyname(hostname)) != NULL) strcpy(hostname, hp->h_name);

    sprintf(class_str, "%s.%s", N_CLASS_ROOT, hostname);

    ptr = message;

    for (;;) {
	if (!fgets(msgbuff, sizeof(msgbuff), stdin))
	    break;
	if ((strlen(msgbuff) + (ptr - message)) > Z_MAXPKTLEN){
	    break;
	}
	strcpy(ptr, msgbuff);
	ptr += strlen(ptr);
    }

    bzero(&notice, sizeof(ZNotice_t));

    notice.z_kind = N_KIND;
    notice.z_port = 0;
    notice.z_class = class_str;
    notice.z_class_inst = N_CLASS_INST;
    notice.z_opcode = N_OPCODE;
    notice.z_sender = 0;
    notice.z_message_len = 0;
    notice.z_recipient = "";
    notice.z_default_format = N_DEF_FORMAT;

    if ((retval = ZSendList(&notice, msg, N_FIELD_CNT, ZNOAUTH)) != ZERR_NONE) {
	    com_err(argv[0], retval, "while sending notice");
	    exit(1);
    } 
}
