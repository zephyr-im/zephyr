/* This file is part of the Project Athena Zephyr Notification System.
 * It contains the hostmanager client program.
 *
 *      Created by:     David C. Jedlinsky
 *
 *      $Source$
 *      $Author$
 *
 *      Copyright (c) 1987,1991 by the Massachusetts Institute of Technology.
 *      For copying and distribution information, see the file
 *      "mit-copyright.h". 
 */

#include <stdio.h>
#include <errno.h>
#include <sys/param.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "zhm.h"

static const char rcsid_hm_c[] = "$Id$";

#ifdef ZEPHYR_USES_HESIOD
int use_hesiod = 0;
#endif

#ifdef macII
#define srandom srand48
#endif

#ifdef _PATH_VARRUN
#define PIDDIR _PATH_VARRUN
#else
#define PIDDIR "/etc/"
#endif

int hmdebug = 0;
time_t starttime;
u_short cli_port;
struct sockaddr_in cli_sin;
char PidFile[128];

char *conffile = NULL;
char *confline = NULL;
realm_info *realm_list = NULL;
int nrealms = 0;

volatile int deactivating = 0;
volatile int terminating = 0;

static RETSIGTYPE deactivate __P((void));
static RETSIGTYPE terminate __P((void));
static void init_hm __P((int, int));
static void parse_conf __P((char *, char *));
static void detach __P((void));
static void send_stats __P((ZNotice_t *, struct sockaddr_in *));
static void die_gracefully __P((void));
static char *strsave __P((const char *));
extern int optind;
extern char *optarg;

static RETSIGTYPE deactivate()
{
    deactivating = 1;
}

static RETSIGTYPE terminate()
{
    terminating = 1;
}

main(argc, argv)
char *argv[];
{
    ZNotice_t notice;
    ZPacket_t packet;
    Code_t ret;
    int opt, pak_len, i, j = 0, fd, count;
    int dieflag = 0, rebootflag = 0, inetd = 0, nofork = 0, errflg = 0;
    fd_set readers;
    struct timeval tv;
    struct hostent *hp;
    struct sockaddr_in from;

    sprintf(PidFile, "%szhm.pid", PIDDIR);

    while ((opt = getopt(argc, argv, "drhinc:")) != EOF)
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
	    rebootflag = 1;
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
	  case 'c':
	    conffile = optarg;
	    break;
	  case '?':
	  default:
	    errflg++;
	    break;
	}

    if (optind < argc) {
	if (conffile) {
	    errflg++;
	} else {
	    int len;
	    static const char lr[] = "default-realm hostlist";

	    len = sizeof(lr)+1;
	    for (i=optind; i < argc; i++)
		len += strlen(argv[i])+1;

	    if ((confline = (char *) malloc(len)) == NULL) {
		fprintf(stderr, "Out of memory constructing default realm");
		exit(1);
	    }
	    strcpy(confline, lr);
	    for (i=optind; i < argc; i++) {
		strcat(confline, " ");
		strcat(confline, argv[i]);
	    }
	}
    }

    if (errflg) {
	fprintf(stderr, "Usage: %s [-d] [-h] [-r] [-n] [server... | -c conffile ]\n", argv[0]);
	exit(2);
    }

    ZSetServerState(1);		/* Aargh!!! */
    if ((ret = ZInitialize()) != ZERR_NONE) {
	Zperr(ret);
	com_err("hm", ret, "initializing");
	closelog();
	exit(-1);
    }

    parse_conf(conffile, confline);

    init_hm(inetd, nofork);

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
		for (i=0; i<nrealms; i++)
		    realm_reset(&realm_list[i]);
	    }
	}

	timer_process();

	if (count == 0)
	    continue;

	if ((ret = ZReceivePacket(packet, &pak_len, &from)) != ZERR_NONE) {
	    if (ret != EINTR) {
		Zperr(ret);
		com_err("hm", ret, "receiving notice");
	    }
	    continue;
	}

	/* Where did it come from? */
	if ((ret = ZParseNotice(packet, pak_len, &notice)) != ZERR_NONE) {
	    Zperr(ret);
	    com_err("hm", ret, "parsing notice");

	    continue;
	}

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

	if ((from.sin_addr.s_addr != htonl(INADDR_LOOPBACK)) &&
	    ((notice.z_kind == SERVACK) ||
	     (notice.z_kind == SERVNAK) ||
	     (notice.z_kind == HMCTL))) {
	    server_manager(&notice, &from);
	} else if ((from.sin_addr.s_addr == htonl(INADDR_LOOPBACK)) &&
		   ((notice.z_kind == UNSAFE) ||
		    (notice.z_kind == UNACKED) ||
		    (notice.z_kind == ACKED) ||
		    (notice.z_kind == HMCTL))) {
	    transmission_tower(&notice, &from, packet, pak_len);
	    DPR2("Pending = %d\n", ZPending());
	} else if (notice.z_kind == STAT) {
	    send_stats(&notice, &from);
	} else {
	    syslog(LOG_INFO, "Unknown notice type: %d",
		   notice.z_kind);
	}
    }
}

static void parse_conf(conffile, confline)
     char *conffile;
     char *confline;
{
    struct servent *sp;
    int zsrvport;
    char filename[MAXPATHLEN];
    FILE *file;
    int lineno;
    char buf[1024];
    Code_t code;
    int i;

    /* this isn't a wonderful place to put this, but the alternatives
       don't seem any better */

    sp = getservbyname(SERVER_SVCNAME, "udp");
    zsrvport = (sp) ? sp->s_port : SERVER_SVC_FALLBACK;

    if (confline) {
	if ((realm_list = (realm_info *) malloc(sizeof(realm_info))) == NULL) {
	    fprintf(stderr, "Out of memory parsing command line %s",
		    filename);
	    exit(1);
	}

	if (code = Z_ParseRealmConfig(confline,
				      &realm_list[nrealms].realm_config)) {
	    fprintf(stderr, "Error in command line: %s", error_message(code));
	    exit(1);
	}

	if (realm_list[nrealms].realm_config.realm == NULL) {
	    fprintf(stderr,
		    "the command line did not contain any valid realms.");
	    exit(1);
	}

	nrealms++;
    } else {
	if (conffile == NULL)
	    sprintf(filename, "%s/zhm.conf", SYSCONFDIR);
	else
	    strcpy(filename, conffile);

	if ((file = fopen(filename, "r")) == NULL) {
#ifdef ZEPHYR_USES_HESIOD
	    if ((realm_list = (realm_info *) malloc(sizeof(realm_info)))
		== NULL) {
		fprintf(stderr, "Out of memory parsing command line %s",
			filename);
		exit(1);
	    }

	    if (code = Z_ParseRealmConfig("default-realm hesiod zephyr",
					  &realm_list[nrealms].realm_config)) {
		fprintf(stderr, "Internal error parsing hesiod default");
		exit(1);
	    }

	    if (realm_list[nrealms].realm_config.realm == NULL) {
		fprintf(stderr, "Internal error using hesiod default");
		exit(1);
	    }

	    nrealms++;
#else
	    fprintf(stderr, "Error opening configuration file %s: %s",
		    filename, strerror(errno));
	    exit(1);
#endif
	} else {
	    for (lineno = 1; ; lineno++) {
		if (fgets(buf, sizeof(buf), file) == NULL) {
		    if (ferror(file)) {
			fprintf(stderr,
				"Error reading configuration file %s: %s",
				filename, strerror(errno));
			exit(1);
		    }
		    break;
		}

		if (realm_list) {
		    realm_list = (realm_info *)
			realloc(realm_list, sizeof(realm_info)*(nrealms+1));
		} else {
		    realm_list = (realm_info *)
			malloc(sizeof(realm_info));
		}

		if (realm_list == NULL) {
		    fprintf(stderr,
			    "Out of memory reading configuration file %s",
			    filename);
		    exit(1);
		}

		if (code = Z_ParseRealmConfig(buf,
					      &realm_list[nrealms].realm_config)) {
		    fprintf(stderr,
			    "Error in configuration file %s, line %d: %s",
			    filename, lineno, error_message(code));
		    exit(1);
		}

		if (realm_list[nrealms].realm_config.realm)
		    nrealms++;
	    }
	}

	if (nrealms == 0) {
	    fprintf(stderr,
		    "Configuration file %s did not contain any valid realms.");
	    exit(1);
	}
    }

    for (i=0; i<nrealms; i++) {
	realm_list[i].current_server = NO_SERVER;
	realm_list[i].sin.sin_len = sizeof(struct in_addr);
	realm_list[i].sin.sin_family = AF_INET;
	realm_list[i].sin.sin_port = zsrvport;
	realm_list[i].state = NEED_SERVER;
	realm_list[i].nchange = 0;
	realm_list[i].nsrvpkts = 0;
	realm_list[i].ncltpkts = 0;
	realm_list[i].queue = NULL;
	init_realm_queue(&realm_list[i]);
	realm_list[i].boot_timer = NULL;
    }
}

static void init_hm(inetd, nofork)
     int inetd;
     int nofork;
{
     struct servent *sp;
     Code_t ret;
     FILE *fp;
#ifdef _POSIX_VERSION
     struct sigaction sa;
#endif
     struct hostent *hp;
     int i;

     starttime = time((time_t *)0);
     OPENLOG("hm", LOG_PID, LOG_DAEMON);
  
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

#ifndef DEBUG
     if (!inetd && !nofork)
	 detach();
  
     /* Write pid to file */
     fp = fopen(PidFile, "w");
     if (fp != NULL) {
	 fprintf(fp, "%d\n", getpid());
	 fclose(fp);
     }
#endif /* DEBUG */

     if (hmdebug) {
	  syslog(LOG_INFO, "Debugging on.");
     }

     /* Initiate communication with each realm */

     for (i=0; i<nrealms; i++)
	 realm_new_server(&realm_list[i], NULL);

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

static void detach()
{
     /* detach from terminal and fork. */
     register int i, x = ZGetFD();
     register long size;
  
     if (i = fork()) {
	  if (i < 0)
	       perror("fork");
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
	  ioctl(i, TIOCNOTTY, (caddr_t) 0);
#endif
	  close(i);
     }
#ifdef _POSIX_VERSION
     setsid();
#endif
}

static char version[BUFSIZ];

static void send_stats(notice, sin)
     ZNotice_t *notice;
     struct sockaddr_in *sin;
{
     ZNotice_t newnotice;
     Code_t ret;
     char *bfr;
     char **list;
     int len, i, j, nitems;
     unsigned long size;

     newnotice = *notice;
     
     if ((ret = ZSetDestAddr(sin)) != ZERR_NONE) {
	  Zperr(ret);
	  com_err("hm", ret, "setting destination");
     }
     newnotice.z_kind = HMACK;

#define NSTATS 12

     nitems = NSTATS*nrealms;

     list = (char **) malloc(sizeof(char *)*nitems);

     for (i=0; i<nrealms; i++) {
	list[i*NSTATS] = (char *) malloc(MAXHOSTNAMELEN);
	if (realm_list[i].current_server == NO_SERVER)
	    strcpy(list[i*NSTATS+0], "NO_SERVER");
	else if (realm_list[i].current_server == EXCEPTION_SERVER)
	    strcpy(list[i*NSTATS+0], inet_ntoa(realm_list[i].sin.sin_addr));
	else
	    strcpy(list[i*NSTATS+0],
		   realm_list[i].realm_config.server_list[realm_list[i].current_server].name);
	list[i*NSTATS+1] = (char *) malloc(64);
	sprintf(list[i*NSTATS+1], "%d", realm_queue_len(&realm_list[i]));
	list[i*NSTATS+2] = (char *) malloc(64);
	sprintf(list[i*NSTATS+2], "%d", realm_list[i].ncltpkts);
	list[i*NSTATS+3] = (char *) malloc(64);
	sprintf(list[i*NSTATS+3], "%d", realm_list[i].nsrvpkts);
	list[i*NSTATS+4] = (char *) malloc(64);
	sprintf(list[i*NSTATS+4], "%d", realm_list[i].nchange);
	list[i*NSTATS+5] = (char *) malloc(64);
	strcpy(list[i*NSTATS+5], rcsid_hm_c);
	list[i*NSTATS+6] = (char *) malloc(64);
	switch (realm_list[i].state) {
	case NEED_SERVER:
	    sprintf(list[i*NSTATS+6], "yes (need server)");
	    break;
	case DEAD_SERVER:
	    sprintf(list[i*NSTATS+6], "yes (dead server)");
	    break;
	case BOOTING:
	    sprintf(list[i*NSTATS+6], "yes (booting)");
	    break;
	case ATTACHING:
	    sprintf(list[i*NSTATS+6], "yes (attaching)");
	    break;
	case ATTACHED:
	    sprintf(list[i*NSTATS+6], "no (attached)");
	    break;
	default:
	    sprintf(list[i*NSTATS+6], "weird value %x", realm_list[i].state);
	    break;
	}
	list[i*NSTATS+7] = (char *) malloc(64);
	sprintf(list[i*NSTATS+7], "%ld", (long) (time((time_t *)0) - starttime));
#ifdef adjust_size
	size = (unsigned long)sbrk(0);
	adjust_size (size);
#else
	size = -1;
#endif
	list[i*NSTATS+8] = (char *)malloc(64);
	sprintf(list[i*NSTATS+8], "%ld", size);
	list[i*NSTATS+9] = (char *)malloc(32);
	strcpy(list[i*NSTATS+9], MACHINE_TYPE);
	list[i*NSTATS+10] = (char *)malloc(64);
	strcpy(list[i*NSTATS+10], realm_list[i].realm_config.realm);

	len = strlen(realm_list[i].realm_config.realm)+1;
	len += strlen("hostlist ");
	for (j=0; j<realm_list[i].realm_config.nservers; j++)
	   len += 1+strlen(realm_list[i].realm_config.server_list[j].name);
	len++;

	list[i*NSTATS+11] = (char *) malloc(len);
	strcpy(list[i*NSTATS+11], realm_list[i].realm_config.realm);
	strcat(list[i*NSTATS+11], " hostlist");
	for (j=0; j<realm_list[i].realm_config.nservers; j++) {
	   strcat(list[i*NSTATS+11], " ");
	   strcat(list[i*NSTATS+11],
		  realm_list[i].realm_config.server_list[j].name);
	}
     }

     /* Since ZFormatRaw* won't change the version number on notices,
	we need to set the version number explicitly.  This code is taken
	from Zinternal.c, function Z_FormatHeader */
     if (!*version)
	     sprintf(version, "%s%d.%d", ZVERSIONHDR, ZVERSIONMAJOR,
		     ZVERSIONMINOR_NOREALM);
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
     free(list);
}

static void die_gracefully()
{
    int i;

    syslog(LOG_INFO, "Terminate signal caught...");

    for (i=0; i<nrealms; i++)
	realm_flush(&realm_list[i]);

    unlink(PidFile);
    closelog();
    exit(0);
}

static char *strsave(sp)
    const char *sp;
{
    register char *ret;

    if((ret = malloc((unsigned) strlen(sp)+1)) == NULL) {
	    abort();
    }
    strcpy(ret,sp);
    return(ret);
}
