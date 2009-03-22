/* This file is part of the Project Athena Zephyr Notification System.
 * It contains code for the "zaway" command.
 *
 *	Created by:	Robert French
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
#include <pwd.h>
#include <com_err.h>

#ifndef lint
static const char rcsid_zaway_c[] = "$Id$";
#endif

#define MESSAGE_CLASS "MESSAGE"
#define DEFAULT_MSG "I'm sorry, but I am currently away from the terminal and am\nnot able to receive your message.\n"
#define RESPONSE_OPCODE ""

RETSIGTYPE cleanup(int);
u_short port;

void
usage(char *name)
{
	printf("Usage: %s [OPTIONS] [FILE]\n"
	       "\n"
	       "  -m STRING    use STRING as the body of the reply message\n"
	       "  -w           watch your location and only reply if you aren't locatable\n"
	       "  -h           display this help and exit\n",
	       name);
}

int
main(int argc,
     char *argv[])
{
	FILE *fp;
	ZNotice_t notice;
	ZSubscription_t sub;
	register int retval;
	struct passwd *pw;
	register char *ptr;
	char awayfile[BUFSIZ],*msg[2],*envptr;
	int optchar, watch_location;
	char *cmdline_msg;
	int nlocs;
	char *find_message(ZNotice_t *, FILE *);
	char *charset = NULL;
	unsigned short zcharset;
	    
#ifdef _POSIX_VERSION
	struct sigaction sa;
#endif
	
	if ((retval = ZInitialize()) != ZERR_NONE) {
		com_err(argv[0],retval,"while initializing");
		exit(1);
	}

	port = 0;
	if ((retval = ZOpenPort(&port)) != ZERR_NONE) {
		com_err(argv[0],retval,"while opening port");
		exit(1);
	}

	sub.zsub_class = MESSAGE_CLASS;
	sub.zsub_classinst = "*";
	sub.zsub_recipient = ZGetSender();

	cmdline_msg = 0;
	watch_location = 0;
	while ((optchar = getopt(argc, argv, "m:whx:")) != EOF) {
		switch (optchar) {
		case 'm':
			cmdline_msg = optarg;
			break;

		case 'w':
			watch_location = 1;
			break;

		case 'h':
			usage(argv[0]);
			return 0;

		case 'x':
			charset = optarg;
			break;

		case '?':
			fprintf(stderr,
				"Unrecognized option '-%c'.\n"
				"Try '%s -h' for more information.\n",
				optopt, argv[0]);
			return 1;
		}
	}

	zcharset = ZGetCharset(charset);

	if (argc > optind)
		(void) strcpy(awayfile,argv[optind]);
	else {
		envptr = getenv("HOME");
		if (envptr)
			(void) sprintf(awayfile,"%s/.away",envptr);
		else {
			if (!(pw = getpwuid((int) getuid()))) {
				fprintf(stderr,"Who are you?\n");
				exit(1);
			}
			(void) sprintf(awayfile,"%s/.away",pw->pw_dir);
		} 
	}

	fp = fopen(awayfile,"r");
	if (!fp && argc > optind) {
		fprintf(stderr,"File %s not found!\n",awayfile);
		exit(1);
	} 
#ifdef _POSIX_VERSION
	(void) sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	sa.sa_handler = cleanup;
	(void) sigaction(SIGINT, &sa, (struct sigaction *)0);
	(void) sigaction(SIGTERM, &sa, (struct sigaction *)0);
	(void) sigaction(SIGHUP, &sa, (struct sigaction *)0);
#else
	(void) signal(SIGINT, cleanup);
	(void) signal(SIGTERM, cleanup);
	(void) signal(SIGHUP, cleanup);
#endif
	if ((retval = ZSubscribeToSansDefaults(&sub,1,port)) != ZERR_NONE) {
		com_err(argv[0],retval,"while subscribing");
		exit(1);
	}

	for (;;) {
		if ((retval = ZReceiveNotice(&notice, (struct sockaddr_in *)0)) != ZERR_NONE) {
			if (retval != ETIMEDOUT)
				com_err(argv[0],retval,"while receiving notice");
			continue;
		}

		if (strcmp(notice.z_sender,ZGetSender()) == 0 ||
		    strcmp(notice.z_opcode,"PING") == 0 ||
		    strcmp(notice.z_opcode,"AUTO") == 0 ||
		    strcmp(notice.z_message,"Automated reply:") == 0) {
		     ZFreeNotice(&notice);
		     continue;
		}

		if (watch_location) {
			if ((retval = ZLocateUser(ZGetSender(), &nlocs, ZNOAUTH))
			    != ZERR_NONE) {
				com_err(argv[0],retval,"while locating self");
				continue;
			}

			if (nlocs != 0) {
				/* User is logged in.  Don't send an autoreply. */
				continue;
			}

			ZFlushLocations();
		}

		if (cmdline_msg) {
		    ptr = strdup(cmdline_msg);
		    if (!ptr) {
			com_err(argv[0],ENOMEM,"while getting cmdline message");
			exit(1);
		    }
		}
		else if (fp) {
			if (!(ptr = find_message(&notice,fp))) {
				ZFreeNotice(&notice);
				continue;
			}
		}
		else {
			ptr = malloc(sizeof(DEFAULT_MSG)+1);
			if (!ptr) {
				com_err(argv[0],ENOMEM,"while getting default message");
				exit(1);
			}
			(void) strcpy(ptr,DEFAULT_MSG);
		}
		notice.z_recipient = notice.z_sender;
		notice.z_sender = 0;
		notice.z_default_format = "";
		notice.z_opcode = RESPONSE_OPCODE;
		notice.z_charset = zcharset;

		msg[0] = "Automated reply:";
		msg[1] = ptr;
		
		notice.z_message_len = strlen(notice.z_message)+1;
		if ((retval = ZSendList(&notice,msg,2,ZNOAUTH)) != ZERR_NONE) {
			com_err(argv[0],retval,"while sending notice");
		}
		free(ptr);
		ZFreeNotice(&notice);
	}
}

char *
find_message(ZNotice_t *notice,
	     FILE *fp)
{
	char *ptr,*ptr2;
	char bfr[BUFSIZ],sender[BUFSIZ];
	int gotone,lastwasnt;
	
	rewind(fp);

	(void) strcpy(sender,notice->z_sender);
	ptr2 = strchr(sender,'@');
	if (ptr2)
		*ptr2 = '\0';
	
	ptr = 0;
	gotone = 0;
	lastwasnt = 0;
	
	while (fgets(bfr,sizeof bfr,fp) != (char *)0) {
		if (*bfr == '>') {
			if (lastwasnt)
				gotone = 0;
			bfr[strlen(bfr)-1] = '\0';
			ptr2 = strchr(bfr,'@');
			if (ptr2)
				*ptr2 = '\0';
			if (!strcmp(bfr+1,sender) ||
			    !strcmp(bfr+1,"*") ||
			    (!strcmp(bfr+1,"%") && !ptr))
				gotone = 1;
			lastwasnt = 0;
		} 
		else {
			if (gotone) {
				if (!ptr) {
					ptr = malloc((unsigned)(strlen(bfr)+1));
					*ptr = '\0';
				} 
				else
					ptr = realloc(ptr,(unsigned)(strlen(bfr)+strlen(ptr)+1));
				(void) strcat(ptr,bfr);
			}
			lastwasnt = 1;
		}
	}

	return (ptr);
}

RETSIGTYPE
cleanup(int ignored)
{
    ZCancelSubscriptions(port);
    exit(1);
}
