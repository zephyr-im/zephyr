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
#include <string.h>

#ifndef lint
#ifndef SABER
static char *rcsid_zshutdown_notify_c = "$Header$";
#endif SABER
#endif lint

#define N_KIND		UNSAFE
#define N_CLASS		"FILSRV"
#define N_OPCODE	"SHUTDOWN"
#define N_DEF_FORMAT	"@bold(Shutdown message from $1 at $time)\n@center(System going down, message is:)\n\n$2\n\n@center(@bold($3))"
#define N_FIELD_CNT	3

/*
 * Standard warning strings appended as extra fields to
 * the message body.
 */

static char warning[] = "Please detach any filesystems you may have\nattached from this host!";

/*ARGSUSED*/
main(argc,argv)
    int argc;
    char *argv[];
{
    ZNotice_t notice;
    struct hostent *hp;
    int retval;
    char hostname[MAXHOSTNAMELEN];
    char msgbuff[BUFSIZ], message[Z_MAXPKTLEN], *ptr;
    char *msg[N_FIELD_CNT];

    msg[0] = hostname;
    msg[1] = message;
    msg[2] = warning;

    if ((retval = ZInitialize()) != ZERR_NONE) {
	com_err(argv[0], retval, "while initializing");
	exit(1);
    } 

    if (gethostname(hostname, MAXHOSTNAMELEN) < 0) {
	com_err(argv[0], errno, "while finding hostname");
	exit(1);
    }

    if ((hp = gethostbyname(hostname)) != NULL)
	    (void) strcpy(hostname, hp->h_name);

    ptr = message;

    for (;;) {
	if (!fgets(msgbuff, sizeof(msgbuff), stdin))
	    break;
	if ((strlen(msgbuff) + (ptr - message)) > Z_MAXPKTLEN){
	    break;
	}
	(void) strcpy(ptr, msgbuff);
	ptr += strlen(ptr);
    }

    bzero((char *)&notice, sizeof(ZNotice_t));

    notice.z_kind = N_KIND;
    notice.z_port = 0;
    notice.z_class = N_CLASS;
    notice.z_class_inst = hostname;
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
