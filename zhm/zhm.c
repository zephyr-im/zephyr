/* This file is part of the Project Athena Zephyr Notification System.
 * It contains the hostmanager client program.
 *
 *      Created by:     David C. Jedlinsky
 *
 *      $Id$
 *
 *      Copyright (c) 1987,1991 by the Massachusetts Institute of Technology.
 *      For copying and distribution information, see the file
 *      "mit-copyright.h".
 */

#include "zhm.h"
#include <zephyr_version.h>

static const char rcsid_hm_c[] = "$Id$";

#ifdef HAVE_HESIOD
int use_hesiod = 0;
#endif

#ifdef macII
#define srandom srand48
#endif

#define PIDDIR "/var/run/"

int hmdebug, rebootflag, noflushflag, errflg, dieflag, inetd, oldpid, nofork;
int no_server = 1, nservchang, nserv, nclt;
int booting = 1, timeout_type, deactivated = 1;
int started = 0;
long starttime;
u_short cli_port;
struct sockaddr_in cli_sin, serv_sin, from;
int numserv;
char **serv_list = NULL;
char prim_serv[NS_MAXDNAME], cur_serv[NS_MAXDNAME];
char *zcluster;
int deactivating = 0;
int terminating = 0;
struct hostent *hp;
char hostname[NS_MAXDNAME], loopback[4];
char PidFile[128];

static RETSIGTYPE deactivate(int);
static RETSIGTYPE terminate(int);
static void choose_server(void);
static void init_hm(void);
#ifndef DEBUG
static void detach(void);
#endif
static void send_stats(ZNotice_t *, struct sockaddr_in *);
static char *strsave(const char *);

static RETSIGTYPE
deactivate(int ignored)
{
    deactivating = 1;
}

static RETSIGTYPE
terminate(int ignored)
{
    terminating = 1;
}

int
main(int argc,
     char *argv[])
{
    ZNotice_t notice;
    ZPacket_t packet;
    Code_t ret;
    int opt, pak_len, fd, count;
    fd_set readers;
    struct timeval tv;

    sprintf(PidFile, "%szhm.pid", PIDDIR);

    if (gethostname(hostname, sizeof(hostname)) < 0) {
	printf("Can't find my hostname?!\n");
	exit(-1);
    }
    prim_serv[0] = '\0';
    while ((opt = getopt(argc, argv, "drhinfN")) != EOF)
	switch(opt) {
	  case 'd':
	    hmdebug = 1;
	    break;
	  case 'h':
	    /* Die on SIGHUP */
	    dieflag = 1;
	    break;
	  case 'r':
	    /* Reboot host -- send boot notice -- and exit */
	    rebootflag= 1;
	    break;
	  case 'i':
	    /* inetd operation: don't do bind ourselves, fd 0 is
	       already connected to a socket. Implies -h */
	    inetd = 1;
	    dieflag = 1;
	    break;
	  case 'n':
	    nofork = 1;
	    break;
	  case 'f':
	    noflushflag = 1;
	    break;
	  case 'N':
	    booting = 0;
	    break;
	  case '?':
	  default:
	    errflg++;
	    break;
	}
    if (errflg) {
	fprintf(stderr, "Usage: %s [-d] [-h] [-r] [-n] [-f] [server]\n",
		argv[0]);
	exit(2);
    }

    numserv = 0;

    /* Override server argument? */
    if (optind < argc) {
	if ((hp = gethostbyname(argv[optind++])) == NULL) {
	    printf("Unknown server name: %s\n", argv[optind-1]);
	} else {
	    strncpy(prim_serv, hp->h_name, sizeof(prim_serv));
	    prim_serv[sizeof(prim_serv) - 1] = '\0';
	}

	/* argc-optind is the # of other servers on the command line */
	serv_list = (char **) malloc((argc - optind + 2) * sizeof(char *));
	if (serv_list == NULL) {
	    printf("Out of memory.\n");
	    exit(-5);
	}
	serv_list[numserv++] = prim_serv;
	for (; optind < argc; optind++) {
	    if ((hp = gethostbyname(argv[optind])) == NULL) {
		printf("Unknown server name '%s', ignoring\n", argv[optind]);
		continue;
	    }
	     serv_list[numserv++] = strsave(hp->h_name);
	}
	serv_list[numserv] = NULL;
    }
#ifdef HAVE_HESIOD
    else
	use_hesiod = 1;
#endif

    choose_server();
    if (*prim_serv == '\0') {
	printf("No valid primary server found, exiting.\n");
	exit(ZERR_SERVNAK);
    }
    init_hm();
    started = 1;

    DPR2("zephyr server port: %u\n", ntohs(serv_sin.sin_port));
    DPR2("zephyr client port: %u\n", ntohs(cli_port));

    /* Main loop */
    for (;;) {
	/* Wait for incoming packets or queue timeouts. */
	DPR("Waiting for a packet...");
	fd = ZGetFD();
	FD_ZERO(&readers);
	FD_SET(fd, &readers);
	count = select(fd + 1, &readers, NULL, NULL, timer_timeout(&tv));
	if (count == -1 && errno != EINTR) {
	    syslog(LOG_CRIT, "select() failed: %m");
	    die_gracefully();
	}

	if (terminating)
	    die_gracefully();

	if (deactivating) {
	    deactivating = 0;
	    if (dieflag) {
		die_gracefully();
	    } else {
		choose_server();
		send_flush_notice(HM_FLUSH);
		deactivated = 1;
	    }
	}

	timer_process();

	if (count > 0) {
	    ret = ZReceivePacket(packet, &pak_len, &from);
	    if ((ret != ZERR_NONE) && (ret != EINTR)){
		Zperr(ret);
		com_err("hm", ret, "receiving notice");
	    } else if (ret != EINTR) {
		/* Where did it come from? */
		if ((ret = ZParseNotice(packet, pak_len, &notice))
		    != ZERR_NONE) {
		    Zperr(ret);
		    com_err("hm", ret, "parsing notice");
		} else {
		    DPR("Got a packet.\n");
		    DPR("notice:\n");
		    DPR2("\tz_kind: %d\n", notice.z_kind);
		    DPR2("\tz_port: %u\n", ntohs(notice.z_port));
		    DPR2("\tz_class: %s\n", notice.z_class);
		    DPR2("\tz_class_inst: %s\n", notice.z_class_inst);
		    DPR2("\tz_opcode: %s\n", notice.z_opcode);
		    DPR2("\tz_sender: %s\n", notice.z_sender);
		    DPR2("\tz_recip: %s\n", notice.z_recipient);
		    DPR2("\tz_def_format: %s\n", notice.z_default_format);
		    DPR2("\tz_message: %s\n", notice.z_message);
		    if (memcmp(loopback, &from.sin_addr, 4) &&
			((notice.z_kind == SERVACK) ||
			 (notice.z_kind == SERVNAK) ||
			 (notice.z_kind == HMCTL))) {
			server_manager(&notice);
		    } else {
			if (!memcmp(loopback, &from.sin_addr, 4) &&
			    ((notice.z_kind == UNSAFE) ||
			     (notice.z_kind == UNACKED) ||
			     (notice.z_kind == ACKED) ||
			     (notice.z_kind == HMCTL))) {
			    /* Client program... */
			    if (deactivated) {
				send_boot_notice(HM_BOOT);
				deactivated = 0;
			    }
			    transmission_tower(&notice, packet, pak_len);
			    DPR2("Pending = %d\n", ZPending());
			} else {
			    if (notice.z_kind == STAT) {
				send_stats(&notice, &from);
			    } else {
				syslog(LOG_INFO,
				       "Unknown notice type: %d",
				       notice.z_kind);
			    }
			}
		    }
		}
	    }
	}
    }
}

static void
choose_server(void)
{
#ifdef HAVE_HESIOD
    int i = 0;
    char **clust_info, **cpp;

    if (use_hesiod) {

	/* Free up any previously used resources */
	if (prim_serv[0])
	    i = 1;
	while (i < numserv)
	    free(serv_list[i++]);
	if (serv_list)
	    free(serv_list);

	numserv = 0;
	prim_serv[0] = '\0';

	if ((clust_info = hes_resolve(hostname, "CLUSTER")) == NULL) {
	    zcluster = NULL;
	} else {
	    for (cpp = clust_info; *cpp; cpp++) {
		/* Remove the following check once we have changed over to
		 * new Hesiod format (i.e. ZCLUSTER.sloc lookup, no primary
		 * server
		 */
		if (!strncasecmp("ZEPHYR", *cpp, 6)) {
		    register char *c;

		    if ((c = strchr(*cpp, ' ')) == 0) {
			printf("Hesiod error getting primary server info.\n");
		    } else {
			strncpy(prim_serv, c+1, sizeof(prim_serv));
			prim_serv[sizeof(prim_serv) - 1] = '\0';
		    }
		    break;
		}
		if (!strncasecmp("ZCLUSTER", *cpp, 9)) {
		    register char *c;

		    if ((c = strchr(*cpp, ' ')) == 0) {
			printf("Hesiod error getting zcluster info.\n");
		    } else {
			if ((zcluster = malloc((unsigned)(strlen(c+1)+1)))
			    != NULL) {
			    strcpy(zcluster, c+1);
			} else {
			    printf("Out of memory.\n");
			    exit(-5);
			}
		    }
		    break;
		}
	    }
	    for (cpp = clust_info; *cpp; cpp++)
		free(*cpp);
	}

	if (zcluster == NULL) {
	    if ((zcluster = malloc((unsigned)(strlen("zephyr")+1))) != NULL)
		strcpy(zcluster, "zephyr");
	    else {
		printf("Out of memory.\n");
		exit(-5);
	    }
	}
	while ((serv_list = hes_resolve(zcluster, "sloc")) == (char **)NULL) {
	    syslog(LOG_ERR, "No servers or no hesiod");
	    if (!started)
		return; /* do not hang forever*/
	    /* wait a bit, and try again */
	    sleep(30);
	}
	cpp = (char **) malloc(2 * sizeof(char *));
	if (cpp == NULL) {
	    printf("Out of memory.\n");
	    exit(-5);
	}
	if (prim_serv[0])
	    cpp[numserv++] = prim_serv;
	for (i = 0; serv_list[i]; i++) {
	    /* copy in non-duplicates */
	    /* assume the names returned in the sloc are full domain names */
	    if (!prim_serv[0] || strcasecmp(prim_serv, serv_list[i])) {
		cpp = (char **) realloc(cpp, (numserv+2) * sizeof(char *));
		if (cpp == NULL) {
		    printf("Out of memory.\n");
		    exit(-5);
		}
		cpp[numserv++] = strsave(serv_list[i]);
	    }
	}
	for (i = 0; serv_list[i]; i++)
	    free(serv_list[i]);
	cpp[numserv] = NULL;
	serv_list = cpp;
    }
#endif

    if (!prim_serv[0] && numserv) {
	srandom(time(NULL));
	strncpy(prim_serv, serv_list[random() % numserv], sizeof(prim_serv));
	prim_serv[sizeof(prim_serv) - 1] = '\0';
    }
}

static void
init_hm(void)
{
     struct servent *sp;
     Code_t ret;
#ifndef DEBUG
     FILE *fp;
#endif
#ifdef _POSIX_VERSION
     struct sigaction sa;
#endif

     starttime = time((time_t *)0);
     OPENLOG("hm", LOG_PID, LOG_DAEMON);

     ZSetServerState(1);	/* Aargh!!! */
     if ((ret = ZInitialize()) != ZERR_NONE) {
	 Zperr(ret);
	 com_err("hm", ret, "initializing");
	 closelog();
	 exit(-1);
     }
     init_queue();

     if (*prim_serv == '\0') {
	 strncpy(prim_serv, *serv_list, sizeof(prim_serv));
	 prim_serv[sizeof(prim_serv) - 1] = '\0';
     }

     loopback[0] = 127;
     loopback[1] = 0;
     loopback[2] = 0;
     loopback[3] = 1;

     if (inetd) {
	 ZSetFD(0);		/* fd 0 is on the socket, thanks to inetd */
     } else {
	 /* Open client socket, for receiving client and server notices */
	 sp = getservbyname(HM_SVCNAME, "udp");
	 cli_port = (sp) ? sp->s_port : HM_SVC_FALLBACK;

	 if ((ret = ZOpenPort(&cli_port)) != ZERR_NONE) {
	     Zperr(ret);
	     com_err("hm", ret, "opening port");
	     exit(ret);
	 }
     }
     cli_sin = ZGetDestAddr();

     sp = getservbyname(SERVER_SVCNAME, "udp");
     memset(&serv_sin, 0, sizeof(struct sockaddr_in));
     serv_sin.sin_port = (sp) ? sp->s_port : SERVER_SVC_FALLBACK;

#ifndef DEBUG
     if (!inetd && !nofork)
	 detach();
     else {
       /* Write pid to file */
       fp = fopen(PidFile, "w");
       if (fp != NULL) {
	 fprintf(fp, "%d\n", getpid());
	 fclose(fp);
       }
     }
#endif /* DEBUG */

     if (hmdebug) {
	  syslog(LOG_INFO, "Debugging on.");
     }

     /* Set up communications with server */
     /* target is SERVER_SVCNAME port on server machine */

     serv_sin.sin_family = AF_INET;

     /* who to talk to */
     if ((hp = gethostbyname(prim_serv)) == NULL) {
	  DPR("gethostbyname failed\n");
	  find_next_server(NULL);
     } else {
	  DPR2("Server = %s\n", prim_serv);
	  strncpy(cur_serv, prim_serv, sizeof(cur_serv));
	  cur_serv[sizeof(cur_serv) - 1] = '\0';
	  memcpy(&serv_sin.sin_addr, hp->h_addr, 4);
     }

     if (booting)
          send_boot_notice(HM_BOOT);
     else
          send_boot_notice(HM_ATTACH);
     deactivated = 0;

#ifdef _POSIX_VERSION
     sigemptyset(&sa.sa_mask);
     sa.sa_flags = 0;
     sa.sa_handler = deactivate;
     sigaction(SIGHUP, &sa, (struct sigaction *)0);
     sa.sa_handler = terminate;
     sigaction(SIGTERM, &sa, (struct sigaction *)0);
#else
     signal(SIGHUP, deactivate);
     signal(SIGTERM, terminate);
#endif
}

#ifndef DEBUG
static void
detach(void)
{
     /* detach from terminal and fork. */
     register int i, x = ZGetFD();
     register long size;
     FILE *fp;

     i = fork();
     if (i) {
	  if (i < 0)
	    perror("fork");
	  /* Write pid to file */
	  fp = fopen(PidFile, "w");
	  if (fp != NULL) {
	    fprintf(fp, "%d\n", i);
	    fclose(fp);
	  }
	  exit(0);
     }
#ifdef _POSIX_VERSION
     size = sysconf(_SC_OPEN_MAX);
#else
     size = getdtablesize();
#endif
     for (i = 0; i < size; i++)
	  if (i != x)
	       close(i);

     if ((i = open("/dev/tty", O_RDWR, 0666)) < 0)
	  ;		/* Can't open tty, but don't flame about it. */
     else {
#ifdef TIOCNOTTY
	  /* Necessary for old non-POSIX systems which automatically assign
	   * an opened tty as the controlling terminal of a process which
	   * doesn't already have one.  POSIX systems won't include
	   * <sys/ioctl.h> (see ../h/sysdep.h); if TIOCNOTTY is defined anyway,
	   * this is unnecessary but won't hurt. */
	  ioctl(i, TIOCNOTTY, NULL);
#endif
	  close(i);
     }
#ifdef _POSIX_VERSION
     setsid();
#endif
}
#endif

static char version[BUFSIZ];

static char *
stats_malloc(size_t size)
{
    char *p = malloc(size);

    if (p == NULL) {
        printf("Out of memory.\n"); /*XXXXXXXXXXX ? */
        exit(-5);
    }

    return p;
}

static void
send_stats(ZNotice_t *notice,
	   struct sockaddr_in *sin)
{
     ZNotice_t newnotice;
     Code_t ret;
     char *bfr;
     char *list[20];
     int len, i, nitems = 10;
     unsigned long size;
     extern int Zauthtype; /* XXX this may be changing in the future */

     newnotice = *notice;

     if ((ret = ZSetDestAddr(sin)) != ZERR_NONE) {
	  Zperr(ret);
	  com_err("hm", ret, "setting destination");
     }
     newnotice.z_kind = HMACK;

     list[0] = stats_malloc(NS_MAXDNAME);
     strcpy(list[0], cur_serv);

     list[1] = stats_malloc(64);
     sprintf(list[1], "%d", queue_len());

     list[2] = stats_malloc(64);
     sprintf(list[2], "%d", nclt);

     list[3] = stats_malloc(64);
     sprintf(list[3], "%d", nserv);

     list[4] = stats_malloc(64);
     sprintf(list[4], "%d", nservchang);

     list[5] = stats_malloc(256);
     snprintf(list[5], 256, "%s (%d)", ZEPHYR_VERSION_STRING, Zauthtype);
     list[5][255] = '\0';

     list[6] = stats_malloc(64);
     if (no_server)
	  sprintf(list[6], "yes");
     else
	  sprintf(list[6], "no");

     list[7] = stats_malloc(64);
     sprintf(list[7], "%ld", time((time_t *)0) - starttime);

#ifdef adjust_size
     size = (unsigned long)sbrk(0);
     adjust_size (size);
#else
     size = -1;
#endif
     list[8] = stats_malloc(64);
     sprintf(list[8], "%ld", size);

     list[9] = stats_malloc(32);
     strncpy(list[9], MACHINE_TYPE, 32);
     list[9][31] = '\0';

     /* Since ZFormatRaw* won't change the version number on notices,
	we need to set the version number explicitly.  This code is taken
	from Zinternal.c, function Z_FormatHeader */
     if (!*version)
	     sprintf(version, "%s%d.%d", ZVERSIONHDR, ZVERSIONMAJOR,
		     ZVERSIONMINOR);
     newnotice.z_version = version;

     if ((ret = ZFormatRawNoticeList(&newnotice, list, nitems, &bfr,
				     &len)) != ZERR_NONE) {
	 syslog(LOG_INFO, "Couldn't format stats packet");
     } else {
	 if ((ret = ZSendPacket(bfr, len, 0)) != ZERR_NONE) {
	     Zperr(ret);
	     com_err("hm", ret, "sending stats");
	 }
     }
     free(bfr);
     for(i=0;i<nitems;i++)
	  free(list[i]);
}

void
die_gracefully(void)
{
     syslog(LOG_INFO, "Terminate signal caught...");
     unlink(PidFile);
     closelog();
     exit(0);
}

static char *
strsave(const char *sp)
{
    register char *ret;

    if((ret = strdup(sp)) == NULL) {
	    abort();
    }
    return(ret);
}
