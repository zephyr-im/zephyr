/* This file is part of the Project Athena Zephyr Notification System.
 * It contains code for the "zwrite" command.
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

#include <zephyr/mit-copyright.h>

#include <zephyr/zephyr.h>
#include <string.h>

#ifndef lint
static char rcsid_zwrite_c[] = "$Header$";
#endif lint

#define DEFAULT_CLASS "MESSAGE"
#define DEFAULT_INSTANCE "PERSONAL"
#define URGENT_INSTANCE "URGENT"

#define MAXRECIPS 100

int nrecips, msgarg, verbose, quiet;
char *whoami, *inst, *class, *recips[MAXRECIPS];
int (*auth)();

char *malloc(), *realloc();

main(argc, argv)
    int argc;
    char *argv[];
{
    ZNotice_t notice;
    int retval, arg, nocheck, nchars, msgsize;
    char bfr[BUFSIZ], *message, *signature;
    char classbfr[BUFSIZ], instbfr[BUFSIZ], sigbfr[BUFSIZ];
	
    whoami = argv[0];

    if ((retval = ZInitialize()) != ZERR_NONE) {
	com_err(whoami, retval, "while initializing");
	exit(1);
    } 

    if (argc < 2)
	usage(whoami);

    bzero((char *) &notice, sizeof(ZNotice_t));

    auth = ZAUTH;
    verbose = quiet = msgarg = nrecips = nocheck = 0;

    if (class = ZGetVariable("zwrite-class")) {
	(void) strcpy(classbfr, class);
	class = classbfr;
    }
    else
	class = DEFAULT_CLASS;
    if (inst = ZGetVariable("zwrite-inst")) {
	(void) strcpy(instbfr, inst);
	inst = instbfr;
    }
    else
	inst = DEFAULT_INSTANCE;
    signature = ZGetVariable("zwrite-signature");
    if (signature) {
	(void) strcpy(sigbfr, signature);
	signature = sigbfr;
    } 
	
    arg = 1;
	
    for (;arg<argc&&!msgarg;arg++) {
	if (*argv[arg] != '-') {
	    recips[nrecips++] = argv[arg];
	    continue;
	} 
	if (strlen(argv[arg]) > 2)
	    usage(whoami);
	switch (argv[arg][1]) {
	case 'a':		/* Backwards compatibility */
	    break;
	case 'o':
	    class = DEFAULT_CLASS;
	    inst = DEFAULT_INSTANCE;
	    break;
	case 'd':
	    auth = ZNOAUTH;
	    break;
	case 'v':
	    verbose = 1;
	    break;
	case 'q':
	    quiet = 1;
	    break;
	case 'n':
	    nocheck = 1;
	    break;
	case 'u':
	    inst = URGENT_INSTANCE;
	    break;
	case 'i':
	    if (arg == argc-1)
		usage(whoami);
	    arg++;
	    inst = argv[arg];
	    break;
	case 'c':
	    if (arg == argc-1)
		usage(whoami);
	    arg++;
	    class = argv[arg];
	    break;
	case 'm':
	    if (arg == argc-1)
		usage(whoami);
	    msgarg = arg+1;
	    break;
	default:
	    usage(whoami);
	}
    }

    if (!nrecips && !(strcmp(class, DEFAULT_CLASS) ||
		      strcmp(inst, DEFAULT_INSTANCE))) {
	fprintf(stderr, "No recipients specified.\n");
	exit (1);
    }

    notice.z_kind = ACKED;
    notice.z_port = 0;
    notice.z_class = class;
    notice.z_class_inst = inst;
    notice.z_opcode = "PING";
    notice.z_sender = 0;
    notice.z_message_len = 0;
    notice.z_recipient = "";
    notice.z_default_format = "";
    notice.z_num_other_fields = 0;

    if (!nocheck && !msgarg)
	send_off(&notice, 0);
	
    if (!msgarg && isatty(0))
	printf("Type your message now.  End with control-D or a dot on a line by itself.\n");

    message = NULL;
    msgsize = 0;
    if (signature) {
	message = malloc((unsigned)(strlen(signature)+1));
	(void) strcpy(message, signature);
	msgsize = strlen(message)+1;
    }
	
    if (msgarg) {
	int size = msgsize;
	for (arg=msgarg;arg<argc;arg++)
		size += (strlen(argv[arg]) + 1);
	size++;				/* for the newline */
	if (message)
		message = realloc(message, (unsigned) size);
	else
		message = malloc((unsigned) size);
	for (arg=msgarg;arg<argc;arg++) {
	    (void) strcpy(message+msgsize, argv[arg]);
	    msgsize += strlen(argv[arg]);
	    if (arg != argc-1) {
		message[msgsize] = ' ';
		msgsize++;
	    } 
	}
	message[msgsize] = '\n';
	message[msgsize+1] = '\0';
	msgsize += 2;
    } else {
	if (isatty(0)) {
	    for (;;) {
		if (!fgets(bfr, sizeof bfr, stdin))
		    break;
		if (bfr[0] == '.' &&
		    (bfr[1] == '\n' || bfr[1] == '\0'))
		    break;
		if (message)
			message = realloc(message,
					  (unsigned)(msgsize+strlen(bfr)));
		else
			message = malloc((unsigned)(msgsize+strlen(bfr)));
		(void) strcpy(message+msgsize, bfr);
		msgsize += strlen(bfr);
	    }
	    message = realloc(message, (unsigned)(msgsize+1));
	    message[msgsize] = '\0';
	}
	else {	/* Use read so you can send binary messages... */
	    while (nchars = read(fileno(stdin), bfr, sizeof bfr)) {
		if (nchars == -1) {
		    fprintf(stderr, "Read error from stdin!  Can't continue!\n");
		    exit(1);
		}
		message = realloc(message, (unsigned)(msgsize+nchars));
		bcopy(bfr, message+msgsize, nchars);
		msgsize += nchars;
	    }
	} 
    }

    notice.z_opcode = "";
    notice.z_message = message;
    notice.z_message_len = msgsize;

    send_off(&notice, 1);
    exit(0);
}

send_off(notice, real)
    ZNotice_t *notice;
    int real;
{
    int i, success, retval;
    char bfr[BUFSIZ];
    ZNotice_t retnotice;

    success = 0;
	
    for (i=0;i<nrecips || !nrecips;i++) {
	notice->z_recipient = nrecips?recips[i]:"";
	if (verbose && real)
	    printf("Sending %smessage, class %s, instance %s, to %s\n", 
		   auth?"authenticated ":"", 
		   class, inst, 
		   nrecips?notice->z_recipient:"everyone");
	if ((retval = ZSendNotice(notice, real?auth:ZNOAUTH)) != ZERR_NONE) {
	    (void) sprintf(bfr, "while sending notice to %s", 
		    nrecips?notice->z_recipient:inst);
	    com_err(whoami, retval, bfr);
	    continue;
	}
	if ((retval = ZIfNotice(&retnotice, (struct sockaddr_in *) 0,
				ZCompareUIDPred, 
				(char *)&notice->z_uid)) !=
	    ZERR_NONE) {
	    ZFreeNotice(&retnotice);
	    (void) sprintf(bfr, "while waiting for acknowledgement for %s", 
		    nrecips?notice->z_recipient:inst);
	    com_err(whoami, retval, bfr);
	    continue;
	}
	if (retnotice.z_kind == SERVNAK) {
	    printf("Received authentication failure while sending to %s\n", 
		   nrecips?notice->z_recipient:inst);
	    ZFreeNotice(&retnotice);
	    continue;
	} 
	if (retnotice.z_kind != SERVACK || !retnotice.z_message_len) {
	    printf("Detected server failure while receiving acknowledgement for %s\n", 
		   nrecips?notice->z_recipient:inst);
	    ZFreeNotice(&retnotice);
	    continue;
	}
	if (!real || (!quiet && real))
	    if (!strcmp(retnotice.z_message, ZSRVACK_SENT)) {
		if (real) {
		    if (verbose)
			printf("Successful\n");
		    else
			printf("%s: Message sent\n", 
			       nrecips?notice->z_recipient:inst);
		}
		else
		    success = 1;
	    } 
	    else
		if (!strcmp(retnotice.z_message, 
			    ZSRVACK_NOTSENT)) {
		    if (verbose && real) {
			if (strcmp(class, DEFAULT_CLASS))
			    printf("Not logged in or not subscribing to class %s, instance %s\n", 
				   class, inst);
			else
			    printf("Not logged in or not subscribing to messages\n");
		    } 
		    else
			if (!nrecips)
			    printf("No one subscribing to class %s, instance %s\n", 
				   class, inst);
			else {
			    if (strcmp(class, DEFAULT_CLASS))
				printf("%s: Not logged in or not subscribing to class %s, instance %s\n", 
				       notice->z_recipient, class, inst);
			    else
				printf("%s: Not logged in or not subscribing to messages\n", 
				       notice->z_recipient);
			} 
		} 
		else
		    printf("Internal failure - illegal message field in server response\n");
	ZFreeNotice(&retnotice);
	if (!nrecips)
	    break;
    }
    if (!real && !success)
	exit(1);
} 

usage(s)
    char *s;
{
    printf("Usage: %s [-a] [-d] [-v] [-q] [-u] [-o] [-c class] [-i inst] [user ...]\n       [-m message]\n", s);
    exit(1);
} 
