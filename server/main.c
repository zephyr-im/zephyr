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
/* which includes
   zephyr/zephyr.h
   <errno.h>
   <sys/types.h>
   <netinet/in.h>
   <sys/time.h>
   <stdio.h>
   <sys/file.h>
   <syslog.h>
   <strings.h>
   <signal.h>
   timer.h
   zsrv_err.h
   */

#include <netdb.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <sys/ioctl.h>
#include <sys/resource.h>
#include <sys/wait.h>
#ifdef POSIX
#include <termios.h>
#endif

#ifdef POSIX
#define SIGNAL_RETURN_TYPE void
#define SIG_RETURN return
#else
#define SIGNAL_RETURN_TYPE int
#define SIG_RETURN return(0)
#endif

#if !defined(__SABER__) && (defined (vax) || defined (ibm032))
#define MONCONTROL moncontrol
#else
#define MONCONTROL (void)
#endif

#define	EVER		(;;)		/* don't stop looping */

#ifdef __STDC__
# define        P(s) s
#else
# define P(s) ()
#endif

static int do_net_setup P((void)), initialize P((void));
static void usage P((void)), do_reset P((void));
static SIGNAL_RETURN_TYPE bye P((int sig)), dbug_on P((int)), 
					dbug_off P((int));
static SIGNAL_RETURN_TYPE dump_db P((int)), reset P((int)), reap P((int));
static SIGNAL_RETURN_TYPE dump_strings P((int));
static void read_from_dump P((char *dumpfile));
#ifndef DEBUG
static void detach P((void));
#endif /* DEBUG */
extern void perror P((Zconst char *));

#undef P

static short doreset = 0;		/* if it becomes 1, perform
					   reset functions */

int srv_socket;				/* dgram socket for clients
					   and other servers */
int bdump_socket = -1;			/* brain dump socket fd
					   (closed most of the time) */
fd_set interesting;			/* the file descrips we are listening
					   to right now */
int nfildes;				/* number to look at in select() */
struct sockaddr_in sock_sin;		/* address of the socket */
struct timeval nexthost_tv;		/* time till next timeout for select */

ZNotAcked_t *nacklist;			/* list of packets waiting for ack's */

u_short hm_port;			/* the port # of the host manager */

char *programname;			/* set to the basename of argv[0] */
char myname[MAXHOSTNAMELEN];		/* my host name */
int zdebug;
#ifdef DEBUG_MALLOC
int dump_malloc_stats = 0;
unsigned long m_size;
#endif
#ifdef DEBUG
int zalone;
#endif /* DEBUG */
u_long npackets;			/* number of packets processed */
long uptime;				/* when we started operations */
static int nofork;
struct in_addr my_addr;
char *bdump_version = "1.1";

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
#ifdef POSIX
	struct sigaction action;
#endif


	int optchar;			/* option processing */
	extern char *optarg;
	extern int optind;

	/* set name */
	if (programname = strrchr(argv[0],'/'))
		programname++;
	else programname = argv[0];

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

#ifdef KERBEROS
	/* if there is no readable srvtab and we are not standalone, there
	   is no possible way we can succeed, so we exit */

	if (access(ZEPHYR_SRVTAB, R_OK)
#ifdef DEBUG		
	    && !zalone
#endif /* DEBUG */
	    ) {
		fprintf(stderr, "NO ZEPHYR SRVTAB (%s) available; exiting\n",
			ZEPHYR_SRVTAB);
		exit(1);
	}
#endif /* KERBEROS */

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

	if (initialize())
		exit(1);

	if (init_from_dump)
	  read_from_dump(dumpfile);

	/* Seed random number set.  */
	srandom (getpid () ^ time (0));

#ifndef __SABER__
	/* chdir to somewhere where a core dump will survive */
	if (chdir("/usr/tmp") != 0)
		syslog(LOG_ERR,"chdir failed (%m) (execution continuing)");

#ifndef macII /* A/UX doesn't have setpriority */
	if (setpriority(PRIO_PROCESS, getpid(), -10))
		syslog(LOG_ERR,"setpriority failed (%m)");
#endif
#endif

	FD_ZERO(&interesting);
	FD_SET(srv_socket, &interesting);

	nfildes = srv_socket + 1;


#ifdef POSIX
	action.sa_flags = 0;
	sigemptyset(&action.sa_mask);
#endif /* POSIX */
#ifdef DEBUG
	/* DBX catches sigterm and does the wrong thing with sigint,
	   so we provide another hook */
#ifdef POSIX
	action.sa_handler = bye;
	sigaction(SIGALRM, &action, NULL);
	sigaction(SIGTERM, &action, NULL);
#else /* POSIX */
	(void) signal(SIGALRM, bye);
	(void) signal(SIGTERM, bye);
#endif /* POSIX */
#ifdef SignalIgnore
#undef SIG_IGN
#define SIG_IGN SignalIgnore
#endif /* SignalIgnore */
#ifdef POSIX
	action.sa_handler = SIG_IGN;
	sigaction(SIGINT, &action, NULL);
#else /* posix */
	(void) signal(SIGINT, SIG_IGN);
#endif /* POSIX */
#else /* ! debug */
#ifdef POSIX
	action.sa_handler = bye;
	sigaction(SIGINT, &action, NULL);
	sigaction(SIGTERM, &action, NULL);
#else /* posix */
	(void) signal(SIGINT, bye);
	(void) signal(SIGTERM, bye);
#endif /* POSIX */
#endif /* DEBUG */
	syslog(LOG_NOTICE, "Ready for action");
#ifdef POSIX
	action.sa_handler = dbug_on;
	sigaction(SIGUSR1, &action, NULL);

	action.sa_handler = dbug_off;
	sigaction(SIGUSR2, &action, NULL);

	action.sa_handler = reap;
	sigaction(SIGCHLD, &action, NULL);

	action.sa_handler = dump_db;
	sigaction(SIGFPE, &action, NULL);

	action.sa_handler = dump_strings;
	sigaction(SIGEMT, &action, NULL);

	action.sa_handler = reset;
	sigaction(SIGHUP, &action, NULL);
#else /* !posix */
	(void) signal(SIGUSR1, dbug_on);
	(void) signal(SIGUSR2, dbug_off);
	(void) signal(SIGCHLD, reap);
	(void) signal(SIGFPE, dump_db);
	(void) signal(SIGEMT, dump_strings);
	(void) signal(SIGHUP, reset);
#endif /* POSIX */

	/* GO! */
	uptime = NOW;
#ifdef DEBUG_MALLOC
	malloc_inuse(&m_size);
#endif
	for EVER {
		if (doreset)
			do_reset();

		tvp = &nexthost_tv;
		if (nexttimo != 0L) {
			nexthost_tv.tv_sec = nexttimo - NOW;
			nexthost_tv.tv_usec = 0;
			if (nexthost_tv.tv_sec < 0) {
				/* timeout has passed! */
				/* so we process one timeout, then pop to
				   select, polling for input.  This way we get
				   work done even if swamped with many
				   timeouts */
				/* this will reset nexttimo */
				(void) timer_process();
				nexthost_tv.tv_sec = 0;
			}
		} else {			/* no timeouts to process */
			tvp = (struct timeval *) NULL;
		}
		readable = interesting;
		if (msgs_queued()) {
			/* when there is input in the queue, we
			   artificially set up to pick up the input */
			nfound = 1;
			FD_ZERO(&readable);
		} else 
			nfound = select(nfildes, &readable, (fd_set *) NULL,
					(fd_set *) NULL, tvp);
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
		if (nfound == 0)
			/* either we timed out or we were just
			   polling for input.  Either way we want to continue
			   the loop, and process the next timeout */
			continue;
		else {
			if ((bdump_socket >= 0) &&
			    FD_ISSET(bdump_socket,&readable))
			    bdump_send();
			else if (msgs_queued() ||
				 FD_ISSET(srv_socket, &readable)) {
			    handle_packet();
			} else
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

#if 0
	if (!(nacklist = (ZNotAcked_t *) xmalloc(sizeof(ZNotAcked_t)))) {
		/* unrecoverable */
		syslog(LOG_CRIT, "nacklist malloc");
		abort();
	}
#else
	{
	    static ZNotAcked_t not_acked_head;
	    nacklist = &not_acked_head;
	}
#endif
	_BZERO((caddr_t) nacklist, sizeof(ZNotAcked_t));
	nacklist->q_forw = nacklist->q_back = nacklist;

	nexttimo = 1L;	/* trigger the timers when we hit
					   the FOR loop */

	(void) ZInitialize();		/* set up the library */
	(void) init_zsrv_err_tbl();	/* set up err table */

	(void) ZSetServerState(1);
	(void) ZSetFD(srv_socket);	/* set up the socket as the
					   input fildes */

	/* set up default strings */

	class_control = make_zstring(ZEPHYR_CTL_CLASS, 1);
	class_admin = make_zstring(ZEPHYR_ADMIN_CLASS, 1);
	class_hm = make_zstring(HM_CTL_CLASS, 1);
	class_ulogin = make_zstring(LOGIN_CLASS, 1);
	class_ulocate = make_zstring(LOCATE_CLASS, 1);
	wildcard_class = make_zstring(MATCHALL_CLASS, 1);
	wildcard_instance = make_zstring(WILDCARD_INSTANCE, 1);
	empty = make_zstring("", 0);

	matchall_sub.q_forw = &matchall_sub;
	matchall_sub.q_back = &matchall_sub;
	matchall_sub.zst_dest.classname = wildcard_class;
	matchall_sub.zst_dest.inst = dup_zstring(empty);
	matchall_sub.zst_dest.recip = dup_zstring(empty);

	set_ZDestination_hash(&matchall_sub.zst_dest);
	/* restrict certain classes */
	access_init();
	return(0);
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

	if (gethostname(hostname, MAXHOSTNAMELEN+1)) {
		syslog(LOG_ERR, "no hostname: %m");
		return(1);
	}
	if (!(hp = gethostbyname(hostname))) {
		syslog(LOG_ERR, "no gethostbyname repsonse");
		(void) strncpy(myname, hostname, MAXHOSTNAMELEN);
		return(1);
	}
	(void) strncpy(myname, hp->h_name, MAXHOSTNAMELEN);
	_BCOPY((caddr_t) hp->h_addr, (caddr_t) &my_addr, sizeof(hp->h_addr));
	
	(void) setservent(1);		/* keep file/connection open */
	
	if (!(sp = getservbyname(SERVER_SVCNAME, "udp"))) {
		syslog(LOG_ERR, "%s/udp unknown",SERVER_SVCNAME);
		return(1);
	}
	_BZERO((caddr_t) &sock_sin, sizeof(sock_sin));
	sock_sin.sin_port = sp->s_port;
	
	if (!(sp = getservbyname(HM_SVCNAME, "udp"))) {
		syslog(LOG_ERR, "%s/udp unknown", HM_SVCNAME);
		return(1);
	}
	hm_port = sp->s_port;

	(void) endservent();
	
	if ((srv_socket = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		syslog(LOG_ERR, "client_sock failed: %m");
		return(1);
	}
	if (bind(srv_socket, (struct sockaddr *) &sock_sin,
		  sizeof(sock_sin)) < 0) {
		syslog(LOG_ERR, "client bind failed: %m");
		return(1);
	}

	/* set not-blocking */
#ifdef POSIX
	flags = fcntl(srv_socket, F_GETFL);
	flags |= O_NONBLOCK;
	(void) fcntl(srv_socket, F_SETFL, flags);
#else
	flags = 1;
	(void) ioctl(srv_socket, FIONBIO, (caddr_t) &flags);
#endif

	return(0);
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

/*
 * interrupt routine
 */

static SIGNAL_RETURN_TYPE
#ifdef __STDC__
bye(int sig)
#else
bye(sig)
     int sig;
#endif
{
	server_shutdown();		/* tell other servers */
	hostm_shutdown();		/* tell our hosts */
#ifdef KERBEROS
	(void) dest_tkt();
#endif
	syslog(LOG_NOTICE, "goodbye (sig %d)",sig);
	exit(0);
	/*NOTREACHED*/
}

static SIGNAL_RETURN_TYPE
#ifdef __STDC__
dbug_on(int sig)
#else
dbug_on(sig)
     int sig;
#endif
{
	syslog(LOG_DEBUG, "debugging turned on");
#ifdef DEBUG_MALLOC
	dump_malloc_stats = 1;
#endif
	zdebug = 1;
	SIG_RETURN;
}

static SIGNAL_RETURN_TYPE
#ifdef __STDC__
dbug_off(int sig)
#else
dbug_off(sig)
     int sig;
#endif
{
	syslog(LOG_DEBUG, "debugging turned off");
#ifdef DEBUG_MALLOC
	malloc_inuse(&m_size);
#endif
	zdebug = 0;
	SIG_RETURN;
}

int fork_for_dump = 0;

static SIGNAL_RETURN_TYPE
#ifdef __STDC__
dump_strings (int sig)
#else
dump_strings(sig)
     int sig;
#endif
{
    FILE *fp;
    int oerrno = errno;
    fp = fopen ("/usr/tmp/zephyr.strings", "w");
    if (!fp) {
	syslog (LOG_ERR, "can't open strings dump file: %m");
	errno = oerrno;
	SIG_RETURN;
    }
    syslog (LOG_INFO, "dumping strings to disk");
    print_zstring_table(fp);
    if (fclose (fp) == EOF)
	syslog (LOG_ERR, "error writing strings dump file");
    else
	syslog (LOG_INFO, "dump done");
    oerrno = errno;
    SIG_RETURN;
}

static SIGNAL_RETURN_TYPE
#ifdef __STDC__
dump_db(int sig)
#else
dump_db(sig)
     int sig;
#endif
{
	/* dump the in-core database to human-readable form on disk */
	FILE *fp;
	int oerrno = errno;
	int pid;

#ifdef __SABER__
	pid = -1;
#else
	if (fork_for_dump) {
	    MONCONTROL (0);
	    pid = fork ();
	    MONCONTROL (1);
	}
	else
	    pid = -1;
#endif
	if (pid > 0)
	    SIG_RETURN;
	if ((fp = fopen("/usr/tmp/zephyr.db", "w")) == (FILE *)0) {
		syslog(LOG_ERR, "can't open dump database");
		errno = oerrno;
		SIG_RETURN;
	}
	syslog(LOG_INFO, "dumping to disk");
	server_dump_servers(fp);
	uloc_dump_locs(fp);
	hostm_dump_hosts(fp);
	syslog(LOG_INFO, "dump done");
	if (fclose(fp) == EOF) {
		syslog(LOG_ERR, "can't close dump db");
	}
	if (pid == 0)
	    exit (0);
	errno = oerrno;
	SIG_RETURN;
}

static SIGNAL_RETURN_TYPE
#ifdef __STDC__
reset(int sig)
#else
reset(sig)
     int sig;
#endif
{
#if 1
	zdbug((LOG_DEBUG,"reset()"));
#endif
	doreset = 1;
	SIG_RETURN;
}

#ifdef __GNUG__
#define wait WaitStatus
#endif

static SIGNAL_RETURN_TYPE
#ifdef __STDC__
reap(int sig)
#else
reap(sig)
     int sig;
#endif
{
    int oerrno = errno;

#ifdef POSIX
    int waitb;
    while (waitpid(-1, &waitb, WNOHANG) == 0) ;
#else
    union wait waitb;
    while (wait3 (&waitb, WNOHANG, (struct rusage*) 0) == 0) ;
#endif

    errno = oerrno;
    SIG_RETURN;
}

static void
do_reset()
{
	int oerrno = errno;
#ifdef POSIX
	sigset_t mask, omask;
#else
	int omask;
#endif
#if 0
	zdbug((LOG_DEBUG,"do_reset()"));
#endif
#ifdef POSIX
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
	syslog (LOG_INFO, "restart completed");
	doreset = 0;
	errno = oerrno;
#ifdef POSIX
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
	register int i, size = getdtablesize();

	/* profiling seems to get confused by fork() */
	MONCONTROL (0);
	i = fork ();
	MONCONTROL (1);
	if (i) {
		if (i < 0)
			perror("fork");
		exit(0);
	}

	for (i = 0; i < size; i++) {
		(void) close(i);
	}
	i = open("/dev/tty", O_RDWR, 666);
	(void) ioctl(i, TIOCNOTTY, (caddr_t) 0);
	(void) close(i);
#ifdef POSIX
	(void) setsid();
#endif
}
#endif

static void
read_from_dump(dumpfile)
     char *dumpfile;
{
  return;
}
