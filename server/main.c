/* This file is part of the Project Athena Zephyr Notification System.
 * It contains the main loop of the Zephyr server
 *
 *	Created by:	John T. Kohl
 *
 *	$Source$
 *	$Author$
 *
 *	Copyright (c) 1987 by the Massachusetts Institute of Technology.
 *	For copying and distribution information, see the file
 *	"mit-copyright.h". 
 */

#include <zephyr/mit-copyright.h>

#ifndef lint
#ifndef SABER
static char rcsid_main_c[] = "$Header$";
static char copyright[] = "Copyright (c) 1987 Massachusetts Institute of Technology.\nPortions Copyright (c) 1986 Student Information Processing Board, Massachusetts Institute of Technology\n";
static char version[] = "Zephyr Server (Prerelease) 0.5";
#endif SABER
#endif lint

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
					   timer.h
					   zsrv_err.h
					 */

#include <netdb.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <sys/ioctl.h>
#include <signal.h>

#define	EVER		(;;)		/* don't stop looping */

static int do_net_setup(), initialize();
static void usage();
static int bye();
#ifdef DEBUG
static void dbug_on(), dbug_off();
#else
static void detach();
#endif DEBUG

int srv_socket;				/* dgram socket for clients
					   and other servers */
int bdump_socket = 0;			/* brain dump socket
					   (closed most of the time) */
fd_set interesting;			/* the file descrips we are listening
					 to right now */
int nfildes;				/* number to look at in select() */
struct sockaddr_in sock_sin;		/* address of the socket */
struct sockaddr_in bdump_sin;		/* addr of brain dump socket */
struct in_addr my_addr;			/* for convenience, my IP address */
struct timeval nexthost_tv;		/* time till next timeout for select */

ZNotAcked_t *nacklist;			/* list of packets waiting for ack's */

u_short hm_port;			/* the port # of the host manager */

char *programname;			/* set to the basename of argv[0] */
char myname[MAXHOSTNAMELEN];		/* my host name */
static ZAcl_t zctlacl = { ZEPHYR_CTL_ACL };
static ZAcl_t loginacl = { LOGIN_ACL };
static ZAcl_t locateacl = { LOCATE_ACL };
static ZAcl_t matchallacl = { MATCH_ALL_ACL };
#ifdef DEBUG
int zdebug = 0;
#endif DEBUG

main(argc,argv)
int argc;
char **argv;
{
	int nfound;			/* #fildes ready on select */
	int authentic;			/* authentic flag for ZParseNotice */
	Code_t status;
	ZNotice_t new_notice;		/* parsed from input_packet */
	ZPacket_t input_packet;		/* from the network */
	int input_len;			/* len of packet */
	struct sockaddr_in input_sin;	/* constructed for authent */

	fd_set readable;
	struct timeval *tvp;
	struct sockaddr_in whoisit;	/* for holding peer's address */

	int optchar;			/* option processing */
	extern char *optarg;
	extern int optind;

	/* set name */
	if (programname = rindex(argv[0],'/'))
		programname++;
	else programname = argv[0];

#ifdef DEBUG
	/* open log here, before we might send a message */
	/* XXX eventually make this LOG_DAEMON */
	openlog(programname, LOG_PID, LOG_LOCAL6);
#endif DEBUG
	/* process arguments */
	
	while ((optchar = getopt(argc, argv, "d")) != EOF) {
		switch(optchar) {
#ifdef DEBUG
		case 'd':
			syslog(LOG_DEBUG, "debugging on");
			zdebug = 1;
			break;
#endif DEBUG
		case '?':
		default:
			usage();
			/*NOTREACHED*/
		}
	}

#ifndef DEBUG
	detach();
	/* open log */
	/* XXX eventually make this LOG_DAEMON */
	openlog(programname, LOG_PID, LOG_LOCAL6);
#endif !DEBUG

	/* set up sockets & my_addr and myname, 
	   find other servers and set up server table, initialize queues
	   for retransmits, initialize error tables,
	   set up restricted classes */

	if (initialize())
		exit(1);

	FD_ZERO(&interesting);
	FD_SET(srv_socket, &interesting);

	nfildes = srv_socket + 1;


#ifdef DEBUG
	/* DBX catches sigterm and does the wrong thing with sigint,
	   so we provide another hook */
	(void) signal(SIGALRM, bye);	

	(void) signal(SIGTERM, bye);
	(void) signal(SIGINT, SIG_IGN);
	(void) signal(SIGUSR1, dbug_on);
	(void) signal(SIGUSR2, dbug_off);
	syslog(LOG_INFO, "Ready for action");
#else
	(void) signal(SIGINT, bye);
	(void) signal(SIGTERM, bye);
#endif DEBUG

	/* GO! */
	for EVER {
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
		if (ZQLength()) {
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
			if (bdump_socket && FD_ISSET(bdump_socket,&readable))
				bdump_send();
			else if (ZQLength() || FD_ISSET(srv_socket, &readable)) {
				/* handle traffic */
				
				if (status = ZReceivePacket(input_packet,
							    sizeof(input_packet),
							    &input_len,
							    &whoisit)) {
					syslog(LOG_ERR,
					       "bad packet receive: %s",
					       error_message(status));
					continue;
				}
				if (status = ZParseNotice(input_packet,
							  input_len,
							  &new_notice,
							  &authentic,
							  &whoisit)) {
					syslog(LOG_ERR,
					       "bad notice parse: %s",
					       error_message(status));
					continue;
				}
				if (server_which_server(&whoisit)) {
				/* we need to parse twice--once to get
				   the source addr, second to check
				   authentication */
					bzero((caddr_t) &input_sin,
					      sizeof(input_sin));
					input_sin.sin_addr.s_addr = new_notice.z_sender_addr.s_addr;
					input_sin.sin_port = new_notice.z_port;
					input_sin.sin_family = AF_INET;
					if (status = ZParseNotice(input_packet,
								  input_len,
								  &new_notice,
								  &authentic,
								  &input_sin)) {
						syslog(LOG_ERR,
						       "bad srv notice parse: %s",
						       error_message(status));
						continue;
					}
				}
				if (whoisit.sin_port != hm_port &&
				    whoisit.sin_port != sock_sin.sin_port &&
				    new_notice.z_kind != CLIENTACK) {
					syslog(LOG_ERR,
					       "bad port %s/%d",
					       inet_ntoa(whoisit.sin_addr),
					       ntohs(whoisit.sin_port));
					continue;
				}
				dispatch(&new_notice, authentic, &whoisit);
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
	(void) class_setup_restricted(ZEPHYR_CTL_CLASS, &zctlacl);
	(void) class_setup_restricted(LOGIN_CLASS, &loginacl);
	(void) class_setup_restricted(LOCATE_CLASS, &locateacl);
	(void) class_setup_restricted(MATCHALL_CLASS, &matchallacl);
	
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
	
	if (!(sp = getservbyname("zephyr-clt", "udp"))) {
		syslog(LOG_ERR, "zephyr-clt/udp unknown");
		return(1);
	}
	bzero((caddr_t) &sock_sin, sizeof(sock_sin));
	sock_sin.sin_port = sp->s_port;
	
	if (!(sp = getservbyname("zephyr-hm", "udp"))) {
		syslog(LOG_ERR, "zephyr-hm/udp unknown");
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
usage()
{
#ifdef DEBUG
	fprintf(stderr,"Usage: %s [-d]\n",programname);
#else
	fprintf(stderr,"Usage: %s\n",programname);
#endif DEBUG
	exit(2);
}

/*
 * interrupt routine
 */

static int
bye()
{
	server_shutdown();		/* tell other servers */
	hostm_shutdown();		/* tell our hosts */
	syslog(LOG_INFO, "goodbye");
	exit(0);
	/*NOTREACHED*/
}

#ifdef DEBUG
static void
dbug_on()
{
	syslog(LOG_DEBUG, "debugging turned on");
	zdebug = 1;
}

static void
dbug_off()
{
	syslog(LOG_DEBUG, "debugging turned off");
	zdebug = 0;
}
#else
/*
 * detach from the terminal
 */

static void
detach()
{
	/* detach from terminal and fork. */
	register int i, size = getdtablesize();

	if (i = fork()) {
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
#endif DEBUG
