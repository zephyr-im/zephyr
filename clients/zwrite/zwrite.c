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

#ifndef lint
static char rcsid_zwrite_c[] = "$Header$";
#endif lint

#define FUDGEFACTOR 10
#define DEFAULT_CLASS "MESSAGE"
#define DEFAULT_INSTANCE "PERSONAL"
#define URGENT_INSTANCE "URGENT"

#define MAXRECIPS 100

int nrecips, msgarg, verbose, quiet;
char *whoami, *inst, *class, *recips[MAXRECIPS];
int (*auth)();

char *getenv();

main(argc,argv)
	int argc;
	char *argv[];
{
	ZNotice_t notice, retnotice;
	ZPacket_t buffer;
	int retval, len, arg, nocheck, nchars, maxlen;
	long ourtime;
	char bfr[BUFSIZ], message[Z_MAXPKTLEN], *ptr, *signature;

	whoami = argv[0];

	if ((retval = ZInitialize()) != ZERR_NONE) {
		com_err(whoami, retval, "while initializing");
		exit(1);
	} 

	if (argc < 2)
		usage(whoami);

	bzero(&notice, sizeof(ZNotice_t));

	maxlen = Z_MAXPKTLEN-FUDGEFACTOR;
	auth = ZAUTH;
	verbose = quiet = msgarg = nrecips = nocheck = 0;

	if (!(class = getenv("ZEPHYR_CLASS")))
		class = DEFAULT_CLASS;
	if (!(inst = getenv("ZEPHYR_INST")))
		inst = DEFAULT_INSTANCE;
	signature = getenv("ZEPHYR_SIGNATURE");
	if (signature)
		maxlen -= strlen(signature)+1;
	
	arg = 1;
	
	for (;arg<argc&&!msgarg;arg++) {
		if (*argv[arg] != '-') {
			recips[nrecips++] = argv[arg];
			continue;
		} 
		if (strlen(argv[arg]) > 2)
			usage(whoami);
		switch (argv[arg][1]) {
		case 'a':  /* Backwards compatibility */
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

	if (!nocheck)
		send_off(&notice, 0);
	
	if (!msgarg && isatty(0))
		printf("Type your message now.  End with control-D or a dot on a line by itself.\n");

	notice.z_opcode = "";
	notice.z_recipient = "foobar12";
	if (signature)
		notice.z_default_format = "Message from $1 <$sender> at $time:\n\n$2";
	else
		notice.z_default_format = "Message from $sender at $time:\n\n$2";
	
	if ((retval = ZFormatNotice(&notice, buffer, sizeof buffer, &len,
				    auth)) != ZERR_NONE) {
		com_err(whoami, retval, "formatting notice");
		exit(1);
	} 

	maxlen -= len;
	
	if (signature) {
		strcpy(message, signature);
		ptr = message+strlen(message)+1;
	}
	else {
		message[0] = '\0';
		ptr = message+1;
	}
	
	if (msgarg) {
		for (arg=msgarg;arg<argc;arg++) {
			strcpy(ptr, argv[arg]);
			if (arg != argc-1)
				strcat(ptr, " ");
			ptr += strlen(ptr);
		}
		*ptr++ = '\n';
		*ptr++ = '\0';
	}
	else {
		if (isatty(0)) {
			for (;;) {
				if (!fgets(bfr, sizeof bfr, stdin))
					break;
				if (bfr[0] == '.' &&
				    (bfr[1] == '\n' || bfr[1] == '\0'))
					break;
				if (strlen(bfr)+(ptr-message) > maxlen) {
					printf("Your message is too long.  It will be truncated at this line.\n");
					break;
				}
				strcpy(ptr, bfr);
				ptr += strlen(ptr);
			}
			*ptr++ = '\0';
		}
		else { /* Use read so you can send binary messages... */
			nchars = read(fileno(stdin), ptr, maxlen+1);
			if (nchars == -1) {
				fprintf(stderr, "Read error from stdin!  Can't continue!\n");
				exit(1);
			}
			if (nchars > maxlen) {
				printf("Message too long.  Truncated.\n");
				nchars = maxlen;
			}
			ptr += nchars;
		} 
	}

	notice.z_message = message;
	notice.z_message_len = ptr-message;

	send_off(&notice, 1);
}

send_off(notice, real)
	ZNotice_t *notice;
	int real;
{
	int i, success, retval;
	char bfr[BUFSIZ];
	ZPacket_t buffer;
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
			sprintf(bfr,"while sending notice to %s",
				nrecips?notice->z_recipient:inst);
			com_err(whoami, retval, bfr);
			continue;
		}
		if ((retval = ZIfNotice(buffer, sizeof buffer, &retnotice,
					0, ZCompareUIDPred,
					(char *)&notice->z_uid)) !=
		    ZERR_NONE) {
			sprintf(bfr, "while waiting for acknowledgement for %s",
				nrecips?notice->z_recipient:inst);
			com_err(whoami, retval, bfr);
			continue;
		} 
		if (retnotice.z_kind == SERVNAK) {
			printf("Received authentication failure while sending to %s\n",
			       nrecips?notice->z_recipient:inst);
			continue;
		} 
		if (retnotice.z_kind != SERVACK || !retnotice.z_message_len) {
			printf("Detected server failure while receiving acknowledgement for %s\n",
			       nrecips?notice->z_recipient:inst);
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
