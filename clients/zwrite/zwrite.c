/* This file is part of the Project Athena Zephyr Notification System.
 * It contains code for the "sendmsg" command.
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
static char rcsid_sendmsg_c[] = "$Header$";
#endif lint

#define FUDGEFACTOR 150
#define MESSAGE_CLASS "MESSAGE"
#define PERSONAL "PERSONAL"
#define URGENT "URGENT"

main(argc,argv)
	int argc;
	char *argv[];
{
	ZNotice_t notice,retnotice;
	ZPacket_t buffer;
	int retval,auth,verbose,urgent;
	char *whoami,bfr[BUFSIZ],message[Z_MAXPKTLEN],*ptr;

	ZInitialize();
	
	whoami = argv[0];
	
	auth = verbose = urgent = 0;
	
	for (argv++,argc--;argc;argc--,argv++) {
		if (**argv != '-')
			break;
		if (strlen(argv[0]) > 2)
			usage(whoami);
		switch (*(*argv+1)) {
		case 'a':
			auth = 1;
			break;
		case 'v':
			verbose = 1;
			break;
		case 'u':
			urgent = 1;
			break;
		default:
			usage(whoami);
		}
	}
	
	if (argc < 1)
		usage(whoami);

	notice.z_kind = ACKED;
	notice.z_port = 0;
	notice.z_class = MESSAGE_CLASS;
	notice.z_class_inst = urgent?URGENT:PERSONAL;
	notice.z_opcode = "";
	notice.z_sender = 0;

	printf("Type your message now.  End with a control-D.\n");

	ptr = message;

	for (;;) {
		if (!gets(bfr))
			break;
		if (strlen(bfr)+(ptr-message)+2 > Z_MAXPKTLEN-FUDGEFACTOR) {
			printf("Your message is too long.  It will be truncated at this line.\n");
			break;
		}
		strcpy(ptr,bfr);
		ptr += strlen(ptr);
		*ptr++ = '\n';
	}

	*ptr++ = '\0';

	notice.z_message = message;
	notice.z_message_len = ptr-message;

	while (argc--) {
		notice.z_recipient = *(argv++);
		if (verbose)
			printf("Sending %s%smessage to %s\n",
			       auth?"authenticated ":"",
			       urgent?"urgent ":"",notice.z_recipient);
		if ((retval = ZSendNotice(&notice,auth)) != ZERR_NONE) {
			sprintf(bfr,"while sending notice to %s",
				notice.z_recipient);
			com_err(whoami,retval,bfr);
			continue;
		}
		if ((retval = ZIfNotice(buffer,sizeof buffer,&retnotice,0,
					ZCompareUIDPred,
					(char *)&notice.z_uid)) !=
		    ZERR_NONE) {
			sprintf(bfr,"while waiting for SERVACK for %s",
				notice.z_recipient);
			com_err(whoami,retval,bfr);
			continue;
		} 
		if (retnotice.z_kind == SERVNAK) {
			printf("Received SERVNAK for %s\n",
			       notice.z_recipient);
			continue;
		} 
		if (retnotice.z_kind != SERVACK) {
			printf("Internal failure while receiving SERVACK for %s\n",
			       notice.z_recipient);
			continue;
		} 
		if (verbose)
			printf("Successful.\n");
	}
}

usage(s)
	char *s;
{
	printf("Usage: %s [-a] [-v] [-u] user ...\n",s);
	exit(1);
} 
