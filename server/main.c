/* This file is part of the Project Athena Zephyr Notification System.
 * It contains the main loop of the Zephyr server
 *
 *	Created by:	John T. Kohl
 *
 *	$Source$
 *	$Author$
 *
 *	Copyright (c) 1987,1988 by the Massachusetts Institute of Technology.
 *	For copying and distribution information, see the file
 *	"mit-copyright.h". 
 */

#include <zephyr/mit-copyright.h>

#ifndef lint
#ifndef SABER
static char rcsid_main_c[] = "$Id$";
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

#include <new.h>
#ifndef __GNUG__
#define NO_INLINING	/* bugs in cfront inlining... */
#endif
#include "zserver.h"			/* which includes
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

extern "C" {
#include <netdb.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <sys/ioctl.h>
#include <sys/resource.h>
#include <sys/wait.h>
}

#define	EVER		(;;)		/* don't stop looping */

static int do_net_setup(void), initialize(void);
static void usage(void), do_reset (void);
#ifdef __GNUG__
typedef int SIGNAL_RETURN_TYPE;
#define SIG_RETURN return 0
#else
#define SIGNAL_RETURN_TYPE void
#define SIG_RETURN return
#endif
static SIGNAL_RETURN_TYPE bye(int sig), dbug_on(int), dbug_off(int);
static SIGNAL_RETURN_TYPE dump_db(int), reset(int), reap(int);
static SIGNAL_RETURN_TYPE dump_strings(int);
#ifndef DEBUG
static void detach(void);
#endif DEBUG
extern "C" void perror(const char *);

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
struct sockaddr_in bdump_sin;		/* addr of brain dump socket */
struct timeval nexthost_tv;		/* time till next timeout for select */

ZNotAcked_t *nacklist;			/* list of packets waiting for ack's */

u_short hm_port;			/* the port # of the host manager */

char *programname;			/* set to the basename of argv[0] */
char myname[MAXHOSTNAMELEN];		/* my host name */
int zdebug = 0;
#ifdef DEBUG
int zalone = 0;
#endif DEBUG
u_long npackets = 0;			/* number of packets processed */
long uptime;				/* when we started operations */
static int nofork;

main(int argc, char **argv)
{
	int nfound;			/* #fildes ready on select */
	fd_set readable;
	struct timeval *tvp;

	int optchar;			/* option processing */
	extern char *optarg;
	extern int optind;

#ifndef __GNUG__
	set_new_handler ((void(*)()) abort);
#else
	set_new_handler (abort);
#endif

	/* set name */
	if (programname = rindex(argv[0],'/'))
		programname++;
	else programname = argv[0];

	/* process arguments */
	
	while ((optchar = getopt(argc, argv, "ds3")) != EOF) {
		switch(optchar) {
		case 'd':
			zdebug = 1;
			break;
#ifdef DEBUG
		case 's':
			zalone = 1;
			break;
#endif
		case '3':
			nofork = 1;
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
#endif DEBUG
	    ) {
		fprintf(stderr, "NO ZEPHYR SRVTAB (%s) available; exiting\n",
			ZEPHYR_SRVTAB);
		exit(1);
	}
#endif KERBEROS

#ifndef DEBUG
	if (!nofork)
		detach();
#endif DEBUG

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

#ifndef __SABER__
	/* chdir to somewhere where a core dump will survive */
	if (chdir("/usr/tmp") != 0)
		syslog(LOG_ERR,"chdir failed (%m) (execution continuing)");

	if (setpriority(PRIO_PROCESS, getpid(), -10))
		syslog(LOG_ERR,"setpriority failed (%m)");
#endif

	FD_ZERO(&interesting);
	FD_SET(srv_socket, &interesting);

	nfildes = srv_socket + 1;


#ifdef DEBUG
	/* DBX catches sigterm and does the wrong thing with sigint,
	   so we provide another hook */
	(void) signal(SIGALRM, bye);	

	(void) signal(SIGTERM, bye);
#ifdef SignalIgnore
#undef SIG_IGN
#define SIG_IGN SignalIgnore
#endif
	(void) signal(SIGINT, SIG_IGN);
#else
	(void) signal(SIGINT, bye);
	(void) signal(SIGTERM, bye);
#endif
	syslog(LOG_INFO, "Ready for action");
	(void) signal(SIGUSR1, dbug_on);
	(void) signal(SIGUSR2, dbug_off);
	(void) signal(SIGCHLD, reap);
	(void) signal(SIGFPE, dump_db);
	(void) signal(SIGEMT, dump_strings);
	(void) signal(SIGHUP, reset);

	/* GO! */
	uptime = NOW;
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
initialize(void)
{
	if (do_net_setup())
		return(1);

	server_init();

	if (!(nacklist = (ZNotAcked_t *) xmalloc(sizeof(ZNotAcked_t)))) {
		/* unrecoverable */
		syslog(LOG_CRIT, "nacklist malloc");
		abort();
	}
	bzero((caddr_t) nacklist, sizeof(ZNotAcked_t));
	nacklist->q_forw = nacklist->q_back = nacklist;

	nexttimo = 1L;			/* trigger the timers when we hit
					   the FOR loop */

	(void) ZInitialize();		/* set up the library */
	(void) init_zsrv_err_tbl();	/* set up err table */

	(void) ZSetServerState(1);
	(void) ZSetFD(srv_socket);	/* set up the socket as the
					   input fildes */

	/* restrict certain classes */
	access_init();
	return(0);
}

/* 
 * Set up the server and client sockets, and initialize my_addr and myname
 */

static int
do_net_setup(void)
{
	struct servent *sp;
	struct hostent *hp;
	char hostname[MAXHOSTNAMELEN+1];
	int on = 1;

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
	bcopy((caddr_t) hp->h_addr, (caddr_t) &my_addr, sizeof(hp->h_addr));
	
	(void) setservent(1);		/* keep file/connection open */
	
	if (!(sp = getservbyname(SERVER_SVCNAME, "udp"))) {
		syslog(LOG_ERR, "%s/udp unknown",SERVER_SVCNAME);
		return(1);
	}
	bzero((caddr_t) &sock_sin, sizeof(sock_sin));
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
	(void) ioctl(srv_socket, FIONBIO, (caddr_t) &on);

	return(0);
}    


/*
 * print out a usage message.
 */

static void
usage(void)
{
#ifdef DEBUG
	fprintf(stderr,"Usage: %s [-d] [-s]\n",programname);
#else
	fprintf(stderr,"Usage: %s [-d]\n",programname);
#endif DEBUG
	exit(2);
}

/*
 * interrupt routine
 */

static SIGNAL_RETURN_TYPE
bye(int sig)
{
	server_shutdown();		/* tell other servers */
	hostm_shutdown();		/* tell our hosts */
#ifdef KERBEROS
	(void) dest_tkt();
#endif
	syslog(LOG_INFO, "goodbye (sig %d)",sig);
	exit(0);
	/*NOTREACHED*/
}

static SIGNAL_RETURN_TYPE
dbug_on(int sig)
{
	syslog(LOG_DEBUG, "debugging turned on");
	zdebug = 1;
	SIG_RETURN;
}

static SIGNAL_RETURN_TYPE
dbug_off(int sig)
{
	syslog(LOG_DEBUG, "debugging turned off");
	zdebug = 0;
	SIG_RETURN;
}

int fork_for_dump = 0;

static SIGNAL_RETURN_TYPE
dump_strings (int sig) {
    FILE *fp;
    int oerrno = errno;
    fp = fopen ("/usr/tmp/zephyr.strings", "w");
    if (!fp) {
	syslog (LOG_ERR, "can't open strings dump file: %m");
	errno = oerrno;
	SIG_RETURN;
    }
    syslog (LOG_INFO, "dumping strings to disk");
    ZString::print (fp);
    if (fclose (fp) == EOF)
	syslog (LOG_ERR, "error writing strings dump file");
    oerrno = errno;
    SIG_RETURN;
}

static SIGNAL_RETURN_TYPE
dump_db(int sig)
{
	/* dump the in-core database to human-readable form on disk */
	FILE *fp;
	int oerrno = errno;
	int pid;

#ifdef __SABER__
	pid = -1;
#else
	if (fork_for_dump) {
	    moncontrol (0);
	    pid = fork ();
	    moncontrol (1);
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
reset(int sig)
{
#if 0
	zdbug((LOG_DEBUG,"reset()"));
#endif
	doreset = 1;
	SIG_RETURN;
}

#ifdef __GNUG__
#define wait WaitStatus
#endif

static SIGNAL_RETURN_TYPE
reap(int sig)
{
	wait waitb;
	int oerrno = errno;
	while (wait3 (&waitb, WNOHANG, (struct rusage*) 0) == 0)
	    ;
	errno = oerrno;
	SIG_RETURN;
}

static void
do_reset(void)
{
	int oerrno = errno;
#if 0
	zdbug((LOG_DEBUG,"do_reset()"));
#endif
	SignalBlock no_hups (sigmask (SIGHUP));

	/* reset various things in the server's state */
	subscr_reset();
	server_reset();
	access_reinit();
	syslog (LOG_INFO, "restart completed");
	doreset = 0;
	errno = oerrno;
}

#ifndef DEBUG
/*
 * detach from the terminal
 */

static void
detach(void)
{
	/* detach from terminal and fork. */
	register int i, size = getdtablesize();

	/* profiling seems to get confused by fork() */
#ifndef __SABER__
	moncontrol (0);
#endif
	i = fork ();
#ifndef __SABER__
	moncontrol (1);
#endif
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

}
#endif

static /*const*/ ZString popular_ZStrings[] = {
    "filsrv",
    "",
    "login",
    "message",
    "personal",
    "operations",
    "athena.mit.edu:root.cell",
    "athena.mit.edu",
    "artemis.mit.edu",
    "athena.mit.edu:contrib",
    "athena.mit.edu:contrib.sipb",
    "talos.mit.edu",
    "unix:0.0",
    "aphrodite.mit.edu",
    "mail",
    "*",
    "cyrus.mit.edu",
    "odysseus.mit.edu",
    "discuss",
    "themis.mit.edu",
    "pop",
    "cyrus.mit.edu:/u2/lockers/games",
    "athena.mit.edu:contrib.xpix.nb",
    "talos.mit.edu:/u2/lockers/athenadoc",
    "pollux.mit.edu",
    "popret",
    "syslog",
    "maeander.mit.edu",
    "athena.mit.edu:contrib.consult",
    "athena.mit.edu:astaff",
    "athena.mit.edu:project",
    "aeneas.mit.edu",
    "aeneas.mit.edu:/u1/x11r3",
    "athena.mit.edu:project.gnu.nb",
    "odysseus.mit.edu:/u3/lockers/softbone",
    "urgent",
    "aphrodite.mit.edu:/u2/lockers/andrew",
    "helen.mit.edu",
    "help",
    "consult",
    "athena.mit.edu:contrib.watchmaker",
    "testers.athena.mit.edu:x11r4",
};
