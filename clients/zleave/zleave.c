/* This file is part of the Project Athena Zephyr Notification System.
 * It contains code for the "zlocate" command.
 *
 *      Created by:     David Jedlinsky
 *
 *      $Source$
 *      $Author$
 *
 *      Copyright (c) 1987 by the Massachusetts Institute of Technology.
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
 * All rights reserved.  The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 */

#ifndef lint
char copyright[] =
"@(#) Copyright (c) 1980 Regents of the University of California.\n\
 All rights reserved.\n";
#endif not lint

#ifndef lint
static char sccsid[] = "@(#)leave.c	5.1 (Berkeley) 5/31/85";
#endif not lint

#include <stdio.h>
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
char tmpfile[40];
char *getlogin();
char *whenleave;
char buff[100];
int use_zephyr=1, oldpid;

extern uid_t getuid();
long time();

main(argc, argv)
char **argv;
{
	long when, tod, now, diff, hours, minutes;
	char *cp;
	FILE *fp;
	struct tm *nv;
	int atoi();
	short port;
	ZSubscription_t sub;
	
	if (ZInitialize() != ZERR_NONE) {
	      fprintf(stderr,"No Zephyr! Will write directly to terminal.\n");
	      use_zephyr = 0;
	}
	(void) strcpy(origlogin, getlogin());
	(void) sprintf(tmpfile, "/tmp/zleave.%d", (int) getuid());

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
		if (*cp < '0' || *cp > '9')
			usage();
		tod = atoi(cp);
		hours = tod / 100;
		minutes = tod % 100;
		if (minutes < 0 || minutes > 59)
			usage();
		diff = 60*hours+minutes;
		doalarm(diff);
		exit(0);
	}
	if (!strcmp(cp, "cancel") || !strcmp(cp, "can")) {
	      if (!(fp = fopen(tmpfile,"r"))) {
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
	      (void) unlink(tmpfile);
	      exit(0);
	}
	if (*cp < '0' || *cp > '9')
		usage();
	tod = atoi(cp);
	hours = tod / 100;
	if (hours > 12)
		hours -= 12;
	if (hours == 12)
		hours = 0;
	minutes = tod % 100;

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
		printf("That time has already passed!\n");
		exit(1);
	}

	doalarm(diff);
	exit(0);
}

usage()
{
	printf("usage: zleave [[+]hhmm] [can[cel]]\n");
	exit(1);
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

	if (fp = fopen(tmpfile,"r")) {
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
	if (!(fp = fopen(tmpfile, "w")))
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

      delay(slp);

      if (use_zephyr) {
	    (void) bzero((char *)&notice, sizeof(notice));
	    notice.z_kind = UNACKED;
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
	    }
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

	while (secs > 0) {
		n = 100;
		if (secs < n)
			n = secs;
		secs -= n;
		if (n > 0)
			sleep((unsigned) n);
		if (strcmp(origlogin, getlogin()))
			exit(0);
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
