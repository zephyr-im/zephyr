/* This file is part of the Project Athena Zephyr Notification System.
 * It contains the main loop of the Zephyr server
 *
 *	Created by:	John T. Kohl
 *
 *	$Source$
 *	$Author$
 *
 *	Copyright (c) 1987,1988,1991 by the Massachusetts Institute of Technology.
 *	For copying and distribution information, see the file
 *	"mit-copyright.h". 
 */

#include <zephyr/mit-copyright.h>

#ifndef lint
#ifndef SABER
static char rcsid_main_c[] =
    "$Id$";
#endif
#endif

/*
 * Server loop for Zephyr.
 */

/*
  The Zephyr server maintains several linked lists of information.

  There is an array of servers (otherservers) initialized and maintained
  by server_s.c.

  Each server descriptor contains a pointer to a linked list of hosts
  which are ``owned'' by that server.  The first server is the ``limbo''
  server which owns any host which was formerly owned by a dead server.

  Each of these host list entries has an IP address and a pointer to a
  linked list of clients on that host.

  Each client has a sockaddr_in, a list of subscriptions, and possibly
  a session key.

  In addition, the class manager has copies of the pointers to the
  clients which are registered with a particular class, the
  not-yet-acknowledged list has copies of pointers to some clients,
  and the hostm manager may have copies of pointers to some clients
  (if the client has not acknowledged a packet after a given timeout).
*/

#include "zserver.h"
#include <sys/socket.h>
#include <sys/resource.h>

#define	EVER		(;;)		/* don't stop looping */

static int do_net_setup __P((void));
static int initialize __P((void));
static void usage __P((void));
static void do_reset __P((void));
static RETSIGTYPE bye __P((int));
static RETSIGTYPE dbug_on __P((int));
static RETSIGTYPE dbug_off __P((int));
static RETSIGTYPE sig_dump_db __P((int));
static RETSIGTYPE sig_dump_strings __P((int));
static RETSIGTYPE reset __P((int));
static RETSIGTYPE reap __P((int));
static void read_from_dump __P((char *dumpfile));
static void dump_db __P((void));
static void dump_strings __P((void));

#ifndef DEBUG
static void detach __P((void));
#endif

static short doreset = 0;		/* if it becomes 1, perform
					   reset functions */

int srv_socket;				/* dgram socket for clients
					   and other servers */
int bdump_socket = -1;			/* brain dump socket fd
					   (closed most of the time) */
fd_set interesting;			/* the file descrips we are listening
					   to right now */
int nfildes;				/* number to look at in select() */
struct sockaddr_in srv_addr;		/* address of the socket */
struct timeval nexthost_tv;		/* time till next timeout for select */

Unacked *nacklist = NULL;		/* list of packets waiting for ack's */

unsigned short hm_port;			/* host manager receiver port */
unsigned short hm_srv_port;		/* host manager server sending port */

char *programname;			/* set to the basename of argv[0] */
char myname[MAXHOSTNAMELEN];		/* my host name */

#ifndef ZEPHYR_USES_HESIOD
char list_file[128];
#endif
#ifdef ZEPHYR_USES_KERBEROS
char srvtab_file[128];
static char tkt_file[128];
#endif
char acl_dir[128];
char subs_file[128];

int zdebug;
#ifdef DEBUG_MALLOC
int dump_malloc_stats = 0;
unsigned long m_size;
#endif
#ifdef DEBUG
int zalone;
#endif

struct timeval t_local;			/* store current time for other uses */

static int dump_db_flag = 0;
static int dump_strings_flag = 0;

u_long npackets;			/* number of packets processed */
long uptime;				/* when we started operations */
static int nofork;
struct in_addr my_addr;
char *bdump_version = "1.2";

int
main(argc, argv)
    int argc;
    char **argv;
{
    int nfound;			/* #fildes ready on select */
    fd_set readable;
    struct timeval *tvp;
    int init_from_dump = 0;
    char *dumpfile;
#ifdef _POSIX_VERSION
    struct sigaction action;
#endif
    int optchar;			/* option processing */
    extern char *optarg;
    extern int optind;

#ifndef ZEPHYR_USES_HESIOD
    sprintf(list_file, "%s/%s", CONFDIR, SERVER_LIST_FILE);
#endif
#ifdef ZEPHYR_USES_KERBEROS
    sprintf(srvtab_file, "%s/%s", CONFDIR, ZEPHYR_SRVTAB);
    sprintf(tkt_file, "%s/%s", CONFDIR, ZEPHYR_TKFILE);
#endif
    sprintf(acl_dir, "%s/%s", CONFDIR, ZEPHYR_ACL_DIR);
    sprintf(subs_file, "%s/%s", CONFDIR, DEFAULT_SUBS_FILE);

    /* set name */
    programname = strrchr(argv[0],'/');
    programname = (programname) ? programname + 1 : argv[0];

    /* process arguments */
    while ((optchar = getopt(argc, argv, "dsnv:f:")) != EOF) {
	switch(optchar) {
	  case 'd':
	    zdebug = 1;
	    break;
#ifdef DEBUG
	  case 's':
	    zalone = 1;
	    break;
#endif
	  case 'n':
	    nofork = 1;
	    break;
	  case 'v':
	    bdump_version = optarg;
	    break;
	  case 'f':
	    init_from_dump = 0;
	    dumpfile = optarg;
	    break;
	  case '?':
	  default:
	    usage();
	    /*NOTREACHED*/
	}
    }

#ifdef ZEPHYR_USES_KERBEROS
    /* if there is no readable srvtab and we are not standalone, there
       is no possible way we can succeed, so we exit */

    if (access(srvtab_file, R_OK)
#ifdef DEBUG		
	&& !zalone
#endif /* DEBUG */
	) {
	fprintf(stderr, "NO ZEPHYR SRVTAB (%s) available; exiting\n",
		srvtab_file);
	exit(1);
    }
#endif /* ZEPHYR_USES_KERBEROS */

#ifndef DEBUG
    if (!nofork)
	detach();
#endif /* DEBUG */

    /* open log */
    OPENLOG(programname, LOG_PID, LOG_LOCAL6);

#if defined (DEBUG) && 0
    if (zalone)
	syslog(LOG_DEBUG, "standalone operation");
#endif
#if 0
    if (zdebug)
	syslog(LOG_DEBUG, "debugging on");
#endif

    /* set up sockets & my_addr and myname, 
       find other servers and set up server table, initialize queues
       for retransmits, initialize error tables,
       set up restricted classes */

    /* Initialize t_local for other uses */
    gettimeofday(&t_local, NULL);

    if (initialize())
	exit(1);

    if (init_from_dump)
	read_from_dump(dumpfile);

    /* Seed random number set.  */
    srandom(getpid() ^ time(0));

    /* chdir to somewhere where a core dump will survive */
    if (chdir(TEMP_DIRECTORY) != 0)
	syslog(LOG_ERR, "chdir failed (%m) (execution continuing)");

    FD_ZERO(&interesting);
    FD_SET(srv_socket, &interesting);

    nfildes = srv_socket + 1;


#ifdef _POSIX_VERSION
    action.sa_flags = 0;
    sigemptyset(&action.sa_mask);

    action.sa_handler = bye;
    sigaction(SIGINT, &action, NULL);
    sigaction(SIGTERM, &action, NULL);

    action.sa_handler = dbug_on;
    sigaction(SIGUSR1, &action, NULL);

    action.sa_handler = dbug_off;
    sigaction(SIGUSR2, &action, NULL);

    action.sa_handler = reap;
    sigaction(SIGCHLD, &action, NULL);

    action.sa_handler = sig_dump_db;
    sigaction(SIGFPE, &action, NULL);

#ifdef SIGEMT
    action.sa_handler = sig_dump_strings;
    sigaction(SIGEMT, &action, NULL);
#endif

    action.sa_handler = reset;
    sigaction(SIGHUP, &action, NULL);
#else /* !posix */
    signal(SIGINT, bye);
    signal(SIGTERM, bye);
    signal(SIGUSR1, dbug_on);
    signal(SIGUSR2, dbug_off);
    signal(SIGCHLD, reap);
    signal(SIGFPE, sig_dump_db);
#ifdef SIGEMT
    signal(SIGEMT, sig_dump_strings);
#endif
    signal(SIGHUP, reset);
#endif /* _POSIX_VERSION */

    syslog(LOG_NOTICE, "Ready for action");

    /* Reinitialize t_local now that initialization is done. */
    gettimeofday(&t_local, NULL);
    uptime = NOW;
#ifdef ZEPHYR_USES_KERBEROS
    timer_set_rel(SWEEP_INTERVAL, sweep_ticket_hash_table, NULL);
#endif

#ifdef DEBUG_MALLOC
    malloc_inuse(&m_size);
#endif
    for EVER {
	if (doreset)
	    do_reset();

	if (dump_db_flag)
	    dump_db();
	if (dump_strings_flag)
	    dump_strings();

	nexthost_tv.tv_usec = 0;
	tvp = &nexthost_tv;

	if (nexttimo != 0L) {
	    nexthost_tv.tv_sec = nexttimo - NOW;
	    if (nexthost_tv.tv_sec <= 0) {
		/* timeout has passed! */
		/* so we process one timeout, then pop to
		   select, polling for input.  This way we get
		   work done even if swamped with many
		   timeouts */
		/* this will reset nexttimo */
		timer_process();
		nexthost_tv.tv_sec = 0;
	    }
	} else {			/* no timeouts to process */
	    nexthost_tv.tv_sec = 15;
	}
	readable = interesting;
	if (msgs_queued()) {
	    /* when there is input in the queue, we
	       artificially set up to pick up the input */
	    nfound = 1;
	    FD_ZERO(&readable);
	} else  {
	    nfound = select(nfildes, &readable, NULL, NULL, tvp);
	}

	/* Initialize t_local for other uses */
	gettimeofday(&t_local, (struct timezone *)0);
		
	/* don't flame about EINTR, since a SIGUSR1 or SIGUSR2
	   can generate it by interrupting the select */
	if (nfound < 0) {
	    if (errno != EINTR)
		syslog(LOG_WARNING, "select error: %m");
#ifdef DEBUG_MALLOC
	    if (dump_malloc_stats) {
		unsigned long foo,histid2;

		dump_malloc_stats = 0;
		foo = malloc_inuse(&histid2);
		printf("Total inuse: %d\n",foo);
		malloc_list(2,m_size,histid2);
	    }
#endif
	    continue;
	}

	if (nfound == 0) {
	    /* either we timed out or we were just
	       polling for input.  Either way we want to continue
	       the loop, and process the next timeout */
	    continue;
	} else {
	    if (bdump_socket >= 0 && FD_ISSET(bdump_socket,&readable))
		bdump_send();
	    else if (msgs_queued() || FD_ISSET(srv_socket, &readable))
		handle_packet();
	    else
		syslog(LOG_ERR, "select weird?!?!");
	}
    }
}

/* Initialize net stuff.
   Set up the server array.
   Initialize the packet ack queues to be empty.
   Initialize the error tables.
   Restrict certain classes.
   */

static int
initialize()
{
    if (do_net_setup())
	return(1);

    server_init();

    nexttimo = 1L;	/* trigger the timerss when we hit the FOR loop */

#ifdef ZEPHYR_USES_KERBEROS
    krb_set_tkt_string(tkt_file);
#endif

    ZInitialize();		/* set up the library */
    init_zsrv_err_tbl();	/* set up err table */

    ZSetServerState(1);
    ZSetFD(srv_socket);		/* set up the socket as the input fildes */

    /* set up default strings */

    class_control = make_string(ZEPHYR_CTL_CLASS, 1);
    class_admin = make_string(ZEPHYR_ADMIN_CLASS, 1);
    class_hm = make_string(HM_CTL_CLASS, 1);
    class_ulogin = make_string(LOGIN_CLASS, 1);
    class_ulocate = make_string(LOCATE_CLASS, 1);
    wildcard_instance = make_string(WILDCARD_INSTANCE, 1);
    empty = make_string("", 0);

    /* restrict certain classes */
    access_init();
    return 0;
}

/* 
 * Set up the server and client sockets, and initialize my_addr and myname
 */

static int
do_net_setup()
{
    struct servent *sp;
    struct hostent *hp;
    char hostname[MAXHOSTNAMELEN+1];
    int flags;

    if (gethostname(hostname, MAXHOSTNAMELEN + 1)) {
	syslog(LOG_ERR, "no hostname: %m");
	return 1;
    }
    hp = gethostbyname(hostname);
    if (!hp) {
	syslog(LOG_ERR, "no gethostbyname repsonse");
	strncpy(myname, hostname, MAXHOSTNAMELEN);
	return 1;
    }
    strncpy(myname, hp->h_name, MAXHOSTNAMELEN);
    memcpy(&my_addr, hp->h_addr, sizeof(hp->h_addr));

    setservent(1);		/* keep file/connection open */

    memset(&srv_addr, 0, sizeof(srv_addr));
    sp = getservbyname(SERVER_SVCNAME, "udp");
    srv_addr.sin_port = (sp) ? sp->s_port : SERVER_SVC_FALLBACK;

    sp = getservbyname(HM_SVCNAME, "udp");
    hm_port = (sp) ? sp->s_port : HM_SVC_FALLBACK;
	
    sp = getservbyname(HM_SRV_SVCNAME, "udp");
    hm_srv_port = (sp) ? sp->s_port : HM_SRV_SVC_FALLBACK;
	
    srv_socket = socket(AF_INET, SOCK_DGRAM, 0);
    if (srv_socket < 0) {
	syslog(LOG_ERR, "client_sock failed: %m");
	return 1;
    }
    if (bind(srv_socket, (struct sockaddr *) &srv_addr,
	     sizeof(srv_addr)) < 0) {
	syslog(LOG_ERR, "client bind failed: %m");
	return 1;
    }

    /* set not-blocking */
#ifdef _POSIX_VERSION
    flags = fcntl(srv_socket, F_GETFL);
    flags |= O_NONBLOCK;
    fcntl(srv_socket, F_SETFL, flags);
#else
    flags = 1;
    ioctl(srv_socket, FIONBIO, &flags);
#endif

    return 0;
}    


/*
 * print out a usage message.
 */

static void
usage()
{
#ifdef DEBUG
	fprintf(stderr,"Usage: %s [-d] [-s] [-n] [-f dumpfile]\n",programname);
#else
	fprintf(stderr,"Usage: %s [-d] [-n] [-f dumpfile]\n",programname);
#endif /* DEBUG */
	exit(2);
}

int
packets_waiting()
{
    fd_set readable, initial;
    struct timeval tv;

    if (msgs_queued())
	return 1;
    FD_ZERO(&initial);
    FD_SET(srv_socket, &initial);
    readable = initial;
    tv.tv_sec = tv.tv_usec = 0;
    return (select(srv_socket + 1, &readable, NULL, NULL, &tv) > 0);
}

static RETSIGTYPE
bye(sig)
    int sig;
{
    server_shutdown();		/* tell other servers */
#ifdef ZEPHYR_USES_KERBEROS
    dest_tkt();
#endif
    syslog(LOG_NOTICE, "goodbye (sig %d)", sig);
    exit(0);
}

static RETSIGTYPE
dbug_on(sig)
    int sig;
{
    syslog(LOG_DEBUG, "debugging turned on");
#ifdef DEBUG_MALLOC
    dump_malloc_stats = 1;
#endif
    zdebug = 1;
}

static RETSIGTYPE
dbug_off(sig)
    int sig;
{
    syslog(LOG_DEBUG, "debugging turned off");
#ifdef DEBUG_MALLOC
    malloc_inuse(&m_size);
#endif
    zdebug = 0;
}

int fork_for_dump = 0;

static RETSIGTYPE
sig_dump_strings(sig)
    int sig;
{
    dump_strings_flag = 1;
}

static void dump_strings()
{
    char filename[128];

    FILE *fp;
    int oerrno = errno;

    sprintf(filename, "%szephyr.strings", TEMP_DIRECTORY);
    fp = fopen (filename, "w");
    if (!fp) {
	syslog(LOG_ERR, "can't open strings dump file: %m");
	errno = oerrno;
	dump_strings_flag = 0;
	return;
    }
    syslog(LOG_INFO, "dumping strings to disk");
    print_string_table(fp);
    if (fclose(fp) == EOF)
	syslog(LOG_ERR, "error writing strings dump file");
    else
	syslog(LOG_INFO, "dump done");
    oerrno = errno;
    dump_strings_flag = 0;
    return;
}

static RETSIGTYPE
sig_dump_db(sig)
    int sig;
{
    dump_db_flag = 1;
}

static void dump_db()
{
    /* dump the in-core database to human-readable form on disk */
    FILE *fp;
    int oerrno = errno;
    int pid;
    char filename[128];

    pid = (fork_for_dump) ? fork() : -1;
    if (pid > 0) {
	dump_db_flag = 0;
	return;
    }
    sprintf(filename, "%szephyr.db", TEMP_DIRECTORY);
    fp = fopen(filename, "w");
    if (!fp) {
	syslog(LOG_ERR, "can't open dump database");
	errno = oerrno;
	dump_db_flag = 0;
	return;
    }
    syslog(LOG_INFO, "dumping to disk");
    server_dump_servers(fp);
    uloc_dump_locs(fp);
    client_dump_clients(fp);
    triplet_dump_subs(fp);
    syslog(LOG_INFO, "dump done");
    if (fclose(fp) == EOF)
	syslog(LOG_ERR, "can't close dump db");
    if (pid == 0)
	exit(0);
    errno = oerrno;
    dump_db_flag = 0;
}

static RETSIGTYPE
reset(sig)
    int sig;
{
#if 1
    zdbug((LOG_DEBUG,"reset()"));
#endif
    doreset = 1;
}

static RETSIGTYPE
reap(sig)
    int sig;
{
    int oerrno = errno;

#ifdef _POSIX_VERSION
    int waitb;
    while (waitpid(-1, &waitb, WNOHANG) == 0) ;
#else
    union wait waitb;
    while (wait3 (&waitb, WNOHANG, (struct rusage*) 0) == 0) ;
#endif

    errno = oerrno;
}

static void
do_reset()
{
    int oerrno = errno;
#ifdef _POSIX_VERSION
    sigset_t mask, omask;
#else
    int omask;
#endif
#if 0
    zdbug((LOG_DEBUG,"do_reset()"));
#endif
#ifdef _POSIX_VERSION
    sigemptyset(&mask);
    sigaddset(&mask, SIGHUP);
    sigprocmask(SIG_BLOCK, &mask, &omask);
#else
    omask = sigblock(sigmask(SIGHUP));
#endif

    /* reset various things in the server's state */
    subscr_reset();
    server_reset();
    access_reinit();
    syslog(LOG_INFO, "restart completed");
    doreset = 0;
    errno = oerrno;
#ifdef _POSIX_VERSION
    sigprocmask(SIG_SETMASK, &omask, (sigset_t *)0);
#else
    sigsetmask(omask);
#endif
}

#ifndef DEBUG
/*
 * detach from the terminal
 */

static void
detach()
{
    /* detach from terminal and fork. */
    int i;
    long size;

#ifdef _POSIX_VERSION
    size = sysconf(_SC_OPEN_MAX);
#else
    size = getdtablesize();
#endif
    /* profiling seems to get confused by fork() */
    i = fork ();
    if (i) {
	if (i < 0)
	    perror("fork");
	exit(0);
    }

    for (i = 0; i < size; i++)
	close(i);

    i = open("/dev/tty", O_RDWR, 666);
#ifdef TIOCNOTTY /* Only necessary on old systems. */
    ioctl(i, TIOCNOTTY, NULL);
#endif
    close(i);
#ifdef _POSIX_VERSION
    setsid();
#endif
}
#endif /* not DEBUG */

static void
read_from_dump(dumpfile)
    char *dumpfile;
{
    /* Not yet implemented. */
    return;
}

