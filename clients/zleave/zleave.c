/* This file is part of the Project Athena Zephyr Notification System.
 * It contains code for the "zleave" command.
 *
 *      Created by:     David Jedlinsky
 *
 *      $Source$
 *      $Author$
 *
 *      Copyright (c) 1987,1988 by the Massachusetts Institute of Technology.
 *      For copying and distribution information, see the file
 *      "mit-copyright.h". 
 */

#include <zephyr/mit-copyright.h>

#include <zephyr/zephyr.h>

#ifndef lint
static char rcsid_zlocate_c[] = "$Header$";
#endif lint

/*
 * Copyright (c) 1980 Regents of the University of California.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that this notice is preserved and that due credit is given
 * to the University of California at Berkeley. The name of the University
 * may not be used to endorse or promote products derived from this
 * software without specific written prior permission. This software
 * is provided ``as is'' without express or implied warranty.
 */

#ifndef lint
char copyright[] =
"@(#) Copyright (c) 1980 Regents of the University of California.\n\
 All rights reserved.\n";
#endif /* not lint */

#ifndef lint
static char sccsid[] = "@(#)leave.c	5.2 (Berkeley) 12/2/87";
#endif /* not lint */

#include <stdio.h>
#include <ctype.h>
#include <signal.h>
#include <string.h>

#define MESSAGE_CLASS "MESSAGE"
#define INSTANCE "LEAVE"
/*
 * zleave [[+]hhmm] [can[cel]]
 *
 * Reminds you when you have to leave.
 * Leave prompts for input and goes away if you hit return.
 * Messages are sent through Zephyr.  Subscriptions are handled automagically.
 * It nags you like a mother hen.
 */
char origlogin[20];
char tempfile[40];
char *getlogin();
char *whenleave;
char buff[100];
int use_zephyr=1, oldpid;

extern uid_t getuid();
long time();

main(argc, argv)
char **argv;
{
	long when, now, diff, hours, minutes;
	char *cp;
	FILE *fp;
	struct tm *nv;
	int gethm();
	int port;
	ZSubscription_t sub;
	
	if (ZInitialize() != ZERR_NONE) {
	      fprintf(stderr,"No Zephyr! Will write directly to terminal.\n");
	      use_zephyr = 0;
	}
	(void) sprintf(tempfile, "/tmp/zleave.%d", (int) getuid());

	if (use_zephyr) {
		if ((port = ZGetWGPort()) == -1) {
			fprintf(stderr,
				"Can't find WindowGram subscription port.\n");
			fprintf(stderr,"Will write directly to terminal.\n");
			use_zephyr = 0;
		} else {
			sub.class = MESSAGE_CLASS;
			sub.classinst = INSTANCE;
			sub.recipient = ZGetSender();
			if (ZSubscribeTo(&sub,1,(u_short)port) != ZERR_NONE) {
				fprintf(stderr,
					"Subscription error!  Writing to your terminal...\n");
				use_zephyr = 0;
			} 
		}
	}	
	if (!use_zephyr) {
	    if ((cp = getlogin()) == NULL) {
		fputs("leave: You are not logged in.\n", stderr);
		exit(1);
	    }
	    (void) strcpy(origlogin, cp);
	}

	if (argc < 2) {
		printf("When do you have to leave? ");
		(void) fflush(stdout);
		buff[read(0, buff, sizeof buff)] = 0;
		cp = buff;
	} else
		cp = argv[1];
	if (*cp == '\n')
		exit(0);
	if (*cp == '+') {
		cp++;
		if (!gethm(cp, &hours, &minutes))
			usage();
		if (minutes < 0 || minutes > 59)
			usage();
		diff = 60*hours+minutes;
		doalarm(diff);
		exit(0);
	}
	if (!strcmp(cp, "cancel") || !strcmp(cp, "can")) {
	      if (!(fp = fopen(tempfile,"r"))) {
		    printf("No zleave is currently running.\n");
		    exit(0);
	      }
	      if (fscanf(fp, "%d", &oldpid) != 1) {
		      printf("The zleave pid file is corrupted.\n");
		      (void) fclose(fp);
		      exit(0);
	      }
	      (void) fclose(fp);
	      if (kill(oldpid,9))
		    printf("No zleave is currently running.\n");
	      (void) unlink(tempfile);
	      exit(0);
	}
	if (!gethm(cp, &hours, &minutes))
		usage();
	if (hours > 12)
		hours -= 12;
	if (hours == 12)
		hours = 0;

	if (hours < 0 || hours > 12 || minutes < 0 || minutes > 59)
		usage();

	(void) time(&now);
	nv = localtime(&now);
	when = 60*hours+minutes;
	if (nv->tm_hour > 12)
		nv->tm_hour -= 12;	/* do am/pm bit */
	now = 60 * nv->tm_hour + nv->tm_min;
	diff = when - now;
	while (diff < 0)
		diff += 12*60;
	if (diff > 11*60) {
		fprintf(stderr, "That time has already passed!\n");
		exit(1);
	}

	doalarm(diff);
	exit(0);
}

usage()
{
	fprintf(stderr, "usage: zleave [[+]hhmm] [can[cel]]\n");
	exit(1);
}

int
gethm(cp, hp, mp)
register char *cp;
int *hp, *mp;
{
	register char c;
	register int tod;

	tod = 0;
	while ((c = *cp++) != '\0') {
		if (!isdigit(c))
			return(0);
		tod = tod * 10 + (c - '0');
	}
	*hp = tod / 100;
	*mp = tod % 100;
	return(1);
}

doalarm(nmins)
long nmins;
{
	char *msg1, *msg2, *msg3, *msg4;
	register int i;
	long slp1, slp2, slp3, slp4;
	long seconds, gseconds;
	long daytime;
	FILE *fp;

	seconds = 60 * nmins;
	if (seconds <= 0)
		seconds = 1;
	gseconds = seconds;

	msg1 = "You have to leave in 5 minutes";
	if (seconds <= 60*5) {
		slp1 = 0;
	} else {
		slp1 = seconds - 60*5;
		seconds = 60*5;
	}

	msg2 = "Just one more minute!";
	if (seconds <= 60) {
		slp2 = 0;
	} else {
		slp2 = seconds - 60;
		seconds = 60;
	}

	msg3 = "Time to leave!";
	slp3 = seconds;

	msg4 = "You're going to be late!";
	slp4 = 60L;

	(void) time(&daytime);
	daytime += gseconds;
	whenleave = ctime(&daytime);

	if (fp = fopen(tempfile,"r")) {
	      if (fscanf(fp, "%d", &oldpid) == 1)
		      if (!kill(oldpid,9))
			      printf("Old zleave process killed.\n");
	      (void) fclose(fp);
	}
	printf("Alarm set for %s", whenleave);

/* Subscribe to MESSAGE.LEAVE here */

	switch(fork()) {
	    case -1:
	      perror("fork");
	      exit(-1);
	      break;
	    case 0:
	      break;
	    default:
	      exit(0);
	      break;
	}
	if (!(fp = fopen(tempfile, "w")))
	  fprintf(stderr, "Cannot open pid file.\n");
	else {
	      fprintf(fp, "%d\n", getpid());
	      if (fclose(fp) == EOF)
		      (void) perror("fclose on pid file");
	}

	(void) signal(SIGINT, SIG_IGN);
	(void) signal(SIGQUIT, SIG_IGN);
	(void) signal(SIGTERM, SIG_IGN);
	(void) signal(SIGTTOU, SIG_IGN);

	if (slp1)
		bother(slp1, msg1);
	if (slp2)
		bother(slp2, msg2);
	bother(slp3, msg3);
	for (i = 0; i < 10; i++)
		bother(slp4, msg4);

	bother(0L, "That was the last time I'll tell you. Bye.");
	exit(0);
}

bother(slp, msg)
long slp;
char *msg;
{
      ZNotice_t notice;
      ZNotice_t retnotice;
      int retval;

      delay(slp);

      if (use_zephyr) {
	    (void) bzero((char *)&notice, sizeof(notice));
	    notice.z_kind = ACKED;
	    notice.z_port = 0;
	    notice.z_class = MESSAGE_CLASS;
	    notice.z_class_inst = INSTANCE;
	    notice.z_recipient = ZGetSender();
	    notice.z_opcode = "";
	    notice.z_sender = (char *) 0;
	    notice.z_default_format = "\n$1";
	    notice.z_message = msg;
	    notice.z_message_len = strlen(msg);
	    
	    if (ZSendNotice(&notice, ZNOAUTH) != ZERR_NONE) {
		  printf("\7\7\7%s\n", msg);
		  use_zephyr = 0;
	    }
	    if ((retval = ZIfNotice(&retnotice, (struct sockaddr_in *) 0,
				    ZCompareUIDPred, 
				    (char *)&notice.z_uid)) != ZERR_NONE) {
		fprintf(stderr,
			"zleave: %s while waiting for acknowledgement\n", 
			error_message(retval));
		use_zephyr = 0;
	    }
	    if (retnotice.z_kind == SERVNAK) {
		fprintf(stderr,
			"zleave: authorization failure while sending\n");
		use_zephyr = 0;
	    } 
	    if (retnotice.z_kind != SERVACK || !retnotice.z_message_len) {
		fprintf(stderr, "zleave: Detected server failure while receiving acknowledgement\n");
		use_zephyr = 0;
	    }
	    if (strcmp(retnotice.z_message, ZSRVACK_SENT)) {
		/* it wasn't sent */
		exit(0);
	    }
	    if (!use_zephyr)
		exit(1);
	    ZFreeNotice(&retnotice);
      } else
	printf("\7\7\7%s\n", msg);
}

/*
 * delay is like sleep but does it in 100 sec pieces and
 * knows what zero means.
 */
delay(secs)
long secs;
{
	long n;
	register char *l;

	while (secs > 0) {
		n = 100;
		if (secs < n)
			n = secs;
		secs -= n;
		if (n > 0)
			sleep((unsigned) n);
		if (!use_zephyr) {
		    l = getlogin();
		    if (l == NULL)
			exit(0);
		    if (strcmp(origlogin, l) != 0)
			exit(0);
		}
	}
}

#ifdef V6
char *getlogin() {
#include <utmp.h>

	static struct utmp ubuf;
	int ufd;

	ufd = open("/etc/utmp",0);
	seek(ufd, ttyn(0)*sizeof(ubuf), 0);
	read(ufd, &ubuf, sizeof(ubuf));
	ubuf.ut_name[sizeof(ubuf.ut_name)] = 0;
	return(&ubuf.ut_name);
}
#endif
