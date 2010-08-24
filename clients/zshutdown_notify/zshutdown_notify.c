/* This file is part of the Project Athena Zephyr Notification System.
 * It contains code for "zshutdown_notify", a utility called by
 * shutdown(8) to do Zephyr notification on shutdown.
 *
 *	Created by:	C. Anthony Della Fera
 *
 *	$Id$
 *
 *	Copyright (c) 1987, 1993 by the Massachusetts Institute of Technology.
 *	For copying and distribution information, see the file
 *	"mit-copyright.h".
 */

#include <sysdep.h>
#include <zephyr/mit-copyright.h>
#include <zephyr/zephyr.h>

#include <sys/socket.h>
#include <netdb.h>
#include <arpa/nameser.h>

#ifndef lint
static const char rcsid_zshutdown_notify_c[] =
    "$Id$";
#endif

#define N_KIND		UNSAFE
#define N_CLASS		"FILSRV"
#define N_OPCODE	"SHUTDOWN"
#define N_DEF_FORMAT	"From $sender:\n@bold(Shutdown message from $1 at $time)\n@center(System going down, message is:)\n\n$2\n\n@center(@bold($3))"
#define N_FIELD_CNT	3

#ifdef HAVE_KRB4
#define SVC_NAME	"rcmd"
#endif

/*
 * Standard warning strings appended as extra fields to
 * the message body.
 */

static char warning[] = "Please detach any filesystems you may have\nattached from this host by typing detach -host %s";

/*ARGSUSED*/
int
main(int argc,
     char *argv[])
{
    ZNotice_t notice;
    struct hostent *hp;
    int retval;
    char hostname[NS_MAXDNAME];
    char msgbuff[BUFSIZ], message[Z_MAXPKTLEN], *ptr;
    char scratch[BUFSIZ];
    char *msg[N_FIELD_CNT];
#ifdef HAVE_KRB4
    char tkt_filename[MAXPATHLEN];
    char rlm[REALM_SZ];
    char hn2[NS_MAXDNAME];
    char *cp;
#endif

    if (gethostname(hostname, sizeof(hostname)) < 0) {
	com_err(argv[0], errno, "while finding hostname");
	exit(1);
    }

    if ((hp = gethostbyname(hostname)) != NULL)
	    (void) strcpy(hostname, hp->h_name);

    msg[0] = hostname;
    msg[1] = message;
    sprintf(scratch, warning, hostname);
    msg[2] = scratch;

#ifdef HAVE_KRB4
    (void) sprintf(tkt_filename, "/tmp/tkt_zshut_%d", getpid());
    krb_set_tkt_string(tkt_filename);

    cp = krb_get_phost(hostname);
    if (cp)
	(void) strcpy(hn2, cp);
    else {
	fprintf(stderr, "%s: can't figure out canonical hostname\n",argv[0]);
	exit(1);
    }
    retval = krb_get_lrealm(rlm, 1);
    if (retval) {
	fprintf(stderr, "%s: can't get local realm: %s\n",
		argv[0], krb_get_err_text(retval));
	exit(1);
    }
    retval = krb_get_svc_in_tkt(SVC_NAME, hn2, rlm,
				SERVER_SERVICE, SERVER_INSTANCE, 1,
				KEYFILE);
    if (retval) {
	fprintf(stderr, "%s: can't get tickets: %s\n",
		argv[0], krb_get_err_text(retval));
	exit(1);
    }
#endif

    if ((retval = ZInitialize()) != ZERR_NONE) {
	com_err(argv[0], retval, "while initializing");
	exit(1);
    }

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

    (void) memset((char *)&notice, 0, sizeof(notice));

    notice.z_kind = N_KIND;
    notice.z_port = 0;
    notice.z_charset = ZCHARSET_UNKNOWN;
    notice.z_class = N_CLASS;
    notice.z_class_inst = hostname;
    notice.z_opcode = N_OPCODE;
    notice.z_sender = 0;
    notice.z_message_len = 0;
    notice.z_recipient = "";
    notice.z_default_format = N_DEF_FORMAT;

    retval = ZSendList(&notice, msg, N_FIELD_CNT, ZAUTH);
#ifdef HAVE_KRB4
    (void) dest_tkt();
#endif

    if (retval != ZERR_NONE) {
	com_err(argv[0], retval, "while sending notice");
	exit(1);
    }
    return 0;
}
