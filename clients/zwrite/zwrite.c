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

#define FUDGEFACTOR 20
#define MESSAGE_CLASS "MESSAGE"
#define PERSONAL "PERSONAL"
#define URGENT "URGENT"

int nrecips,everyone,msgarg,verbose,quiet;
char *whoami,*inst,*class;
int (*auth)();

main(argc,argv)
	int argc;
	char *argv[];
{
	ZNotice_t notice,retnotice;
	ZPacket_t buffer;
	int retval,len,arg,nocheck;
	long ourtime;
	char bfr[BUFSIZ],message[Z_MAXPKTLEN],*ptr;

	whoami = argv[0];

	if ((retval = ZInitialize()) != ZERR_NONE) {
		com_err(whoami,retval,"while initializing");
		exit(1);
	} 

	if (argc < 2)
		usage(whoami);

	bzero(&notice,sizeof(ZNotice_t));
	
	auth = ZAUTH;
	verbose = quiet = msgarg = nrecips = everyone = nocheck = 0;

	class = MESSAGE_CLASS;
	inst = PERSONAL;
	
	arg = 1;
	
	for (;arg<argc&&!msgarg;arg++) {
		if (*argv[arg] != '-') {
			nrecips++;
			everyone = 0;
			continue;
		} 
		if (strlen(argv[arg]) > 2)
			usage(whoami);
		switch (argv[arg][1]) {
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
			inst = URGENT;
			break;
		case 'i':
			if (arg == argc-1)
				usage(whoami);
			arg++;
			inst = argv[arg];
			everyone = 1;
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

	if (!nrecips && !everyone) {
		fprintf(stderr,"No recipients specified.\n");
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
		send_off(&notice,argc,argv,0);
	
	if (!msgarg && isatty(0))
		printf("Type your message now.  End with control-D or a dot on a line by itself.\n");

	notice.z_opcode = "";
	notice.z_recipient = "foobar12";
	notice.z_default_format = "Message from $sender at $time:\n\n$message";
	
	if ((retval = ZFormatNotice(&notice,buffer,sizeof buffer,&len,
				    auth)) != ZERR_NONE) {
		com_err(whoami,retval,"formatting notice");
		exit(1);
	} 

	ptr = message;

	if (msgarg) {
		for (arg=msgarg;arg<argc;arg++) {
			strcpy(ptr,argv[arg]);
			if (arg != argc-1)
				strcat(ptr," ");
			ptr += strlen(ptr);
		}
		*ptr++ = '\n';
		*ptr++ = '\0';
	}
	else {
		for (;;) {
			if (!fgets(bfr,sizeof bfr,stdin))
				break;
			if (bfr[0] == '.' &&
			    (bfr[1] == '\n' || bfr[1] == '\0'))
				break;
			if (strlen(bfr)+(ptr-message) > Z_MAXPKTLEN-len-FUDGEFACTOR) {
				if (isatty(0))
					printf("Your message is too long.  It will be truncated at this line.\n");
				else
					printf("Message too long.  Truncated.\n");
				break;
			}
			strcpy(ptr,bfr);
			ptr += strlen(ptr);
		}

		*ptr++ = '\0';
	}
	
	notice.z_message = message;
	notice.z_message_len = ptr-message;

	send_off(&notice,argc,argv,1);
}

send_off(notice,argc,argv,real)
	ZNotice_t *notice;
	int argc;
	char *argv[];
	int real;
{
	int arg,success,retval;
	char bfr[BUFSIZ];
	ZPacket_t buffer;
	ZNotice_t retnotice;

	success = 0;
	
	for (arg=1;everyone||(arg<argc&&!(msgarg&&arg>=msgarg));arg++) {
		if (*argv[arg] == '-' && !everyone)
			continue;
		if (!strcmp(argv[arg-1],"-c"))
			continue;
		if (!strcmp(argv[arg-1],"-i") && !everyone)
			continue;
		notice->z_recipient = everyone?"":argv[arg];
		if (verbose && real)
			printf("Sending %smessage, instance %s, to %s\n",
			       auth?"authenticated ":"",
			       inst,everyone?"everyone":notice->z_recipient);
		if ((retval = ZSendNotice(notice,auth)) != ZERR_NONE) {
			sprintf(bfr,"while sending notice to %s",
				everyone?inst:notice->z_recipient);
			com_err(whoami,retval,bfr);
			continue;
		}
		if ((retval = ZIfNotice(buffer,sizeof buffer,&retnotice,
					0,ZCompareUIDPred,
					(char *)&notice->z_uid)) !=
		    ZERR_NONE) {
			sprintf(bfr,"while waiting for SERVACK for %s",
				everyone?inst:notice->z_recipient);
			com_err(whoami,retval,bfr);
			continue;
		} 
		if (retnotice.z_kind == SERVNAK) {
			printf("Received authentication failure while sending to %s\n",
			       everyone?inst:notice->z_recipient);
			continue;
		} 
		if (retnotice.z_kind != SERVACK || !retnotice.z_message_len) {
			printf("Detected server failure while receiving SERVACK for %s\n",
			       everyone?inst:notice->z_recipient);
			continue;
		}
		if (!quiet && real)
			if (!strcmp(retnotice.z_message,ZSRVACK_SENT)) {
				if (verbose)
					printf("Successful\n");
				else
					printf("%s: Message sent\n",
					       everyone?inst:notice->z_recipient);
			} 
			else
				if (!strcmp(retnotice.z_message,
					    ZSRVACK_NOTSENT)) {
					if (verbose)
						printf("Not logged in or not subscribing to messages\n");
					else
						if (everyone)
							printf("%s: No one subscribing to this instance\n",inst);
						else
							printf("%s: Not logged in or not subscribing to messages\n",notice->z_recipient);
				} 
				else
					printf("Internal failure - illegal message field in server response\n");
		if (!real) {
			if (!strcmp(retnotice.z_message,ZSRVACK_NOTSENT)) {
				if (everyone)
					printf("%s: No one subscribing to this instance\n",inst);
				else
					printf("%s: Not logged in or not subscribing to messages\n",notice->z_recipient);
			}
			else
				success = 1;
		}
		
		if (everyone)
			break;
	}
	if (!real && !success)
		exit(1);
} 

usage(s)
	char *s;
{
	printf("Usage: %s [-d] [-v] [-q] [-u] [-i inst] [-c class] [user ...]  [-m message]\n",s);
	exit(1);
} 
