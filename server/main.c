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
#endif SABER
#endif lint
static char copyright[] = "Copyright (c) 1987 Massachusetts Institute of Technology.\nPortions Copyright (c) 1986 Student Information Processing Board, Massachusetts Institute of Technology\n";
static char version[] = "Zephyr Server (Prerelease) 0.2";

/*
 * Server loop for Zephyr.
 */

/*
  The Zephyr server maintains several linked lists of information.

  There is an array of servers initialized in main.c and maintained
  by server_s.c.
  Each server descriptor contains a pointer to a linked list of hosts
  which are ``owned'' by that server.
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
					   <syslog.h>
					   timer.h
					 */

#include <netdb.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <sys/ioctl.h>
#include <signal.h>
#include <sys/file.h>

#define	EVER		(;;)		/* don't stop looping */
#define	max(a,b)	((a) > (b) ? (a) : (b))

static int do_net_setup(), initialize();
static struct in_addr *get_server_addrs();
static void usage(), setup_server();
static int bye();
#ifndef DEBUG
static void detach();
#endif DEBUG

int srv_socket;				/* dgram socket for clients
					   and other servers */
struct sockaddr_in sock_sin;		/* address of the socket */
struct in_addr my_addr;			/* for convenience, my IP address */
struct timeval nexthost_tv;		/* time till next timeout for select */

int nservers;				/* number of other servers */
ZServerDesc_t *otherservers;		/* points to an array of the known
					   servers */
int me_server_idx;			/* # of my entry in the array */
ZNotAcked_t *nacklist;			/* list of packets waiting for ack's */

char *programname;			/* set to the basename of argv[0] */
char myname[MAXHOSTNAMELEN];		/* my host name */

ZAcl_t zctlacl = { ZEPHYR_CTL_ACL };
ZAcl_t loginacl = { LOGIN_ACL };
ZAcl_t locateacl = { LOCATE_ACL };
ZAcl_t matchallacl = { MATCH_ALL_ACL };
#ifdef DEBUG
int zdebug = 0;
#endif DEBUG

main(argc,argv)
int argc;
char **argv;
{
	int nfound;			/* #fildes ready on select */
	int nfildes;			/* number to look at in select() */
	int authentic;			/* authentic flag for ZParseNotice */
	Code_t status;
	ZPacket_t new_packet;		/* from the network */
	ZNotice_t new_notice;		/* parsed from new_packet */
	fd_set readable, interesting;
	struct timeval *tvp;
	struct sockaddr_in whoisit;	/* for holding peer's address */

	int optchar;			/* option processing */
	extern char *optarg;
	extern int optind;

	/* print out various copyright bullshit */
	puts(version);
	puts(copyright);

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
		nfound = select(nfildes, &readable, (fd_set *) NULL,
				(fd_set *) NULL, tvp);
		if (nfound < 0) {
			syslog(LOG_WARNING, "select error: %m");
			continue;
		}
		if (nfound == 0)
			/* either we timed out or we were just
			   polling for input.  Either way we want to continue
			   the loop, and process the next timeout */
			continue;
		else {
			if (FD_ISSET(srv_socket, &readable)) {
				/* handle traffic */
				
				if (status = ZReceiveNotice(new_packet,
							    sizeof(new_packet),
							    &new_notice,
							    &authentic,
							    &whoisit)) {
					syslog(LOG_ERR,
					       "bad notice receive: %s",
					       error_message(status));
					continue;
				}
				dispatch(&new_notice, authentic, &whoisit);
			} else
				syslog(LOG_ERR, "select weird?!?!");
		}
	}
}

/* Initialize net stuff.
   Contact Hesiod to find all the other servers, allocate space for the
   structure, initialize them all to SERV_DEAD with expired timeouts.
   Initialize the packet ack queues to be empty.
   Initialize the error tables.
   Restrict certain classes.
   */

static int
initialize()
{
	register int i;
	struct in_addr *serv_addr, *hes_addrs;

	if (do_net_setup())
		return(1);

	/* talk to hesiod here, set nservers */
	if (!(hes_addrs = get_server_addrs(&nservers))) {
		    syslog(LOG_ERR, "No servers?!?");
		    exit(1);
	    }

	otherservers = (ZServerDesc_t *) xmalloc(nservers *
						sizeof(ZServerDesc_t));
	me_server_idx = -1;

	for (serv_addr = hes_addrs, i = 0; i < nservers; serv_addr++, i++) {
		setup_server(&otherservers[i], serv_addr);
		/* is this me? */
		if (serv_addr->s_addr == my_addr.s_addr) {
			me_server_idx = i;
			otherservers[i].zs_state = SERV_UP;
			timer_reset(otherservers[i].zs_timer);
			otherservers[i].zs_timer = (timer) NULL;
			zdbug((LOG_DEBUG,"found myself"));
		}
	}

	/* free up the addresses */
	xfree(hes_addrs);

	if (me_server_idx == -1) {
		ZServerDesc_t *temp;
		syslog(LOG_WARNING, "I'm a renegade server!");
		temp = (ZServerDesc_t *)realloc((caddr_t) otherservers, (unsigned) (++nservers * sizeof(ZServerDesc_t)));
		if (!temp) {
			syslog(LOG_CRIT, "renegade realloc");
			abort();
		}
		otherservers = temp;
		setup_server(&otherservers[nservers - 1], &my_addr);
		/* we are up. */
		otherservers[nservers - 1].zs_state = SERV_UP;

		/* cancel and reschedule all the timers--pointers need
		   adjusting */
		for (i = 0; i < nservers - 1; i++) {
			timer_reset(otherservers[i].zs_timer);
			/* all the HELLO's are due now */
			otherservers[i].zs_timer = timer_set_rel(0L, server_timo, (caddr_t) &otherservers[i]);
		}
		/* I don't send hello's to myself--cancel the timer */
		timer_reset(otherservers[nservers - 1].zs_timer);
		otherservers[nservers - 1].zs_timer = (timer) NULL;

		me_server_idx = nservers - 1;
	}
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
	
	(void) endservent();
	
	if ((srv_socket = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		syslog(LOG_ERR, "client_sock failed: %m");
		return(1);
	}
	if (bind (srv_socket, (struct sockaddr *) &sock_sin,
		  sizeof(sock_sin)) < 0) {
		syslog(LOG_ERR, "client bind failed: %m");
		return(1);
	}

	/* set not-blocking */
	(void) ioctl(srv_socket, FIONBIO, (caddr_t) &on);

	return(0);
}    


/*
 * get a list of server addresses, from Hesiod.  Return a pointer to an
 * array of allocated storage.  This storage is freed by the caller.
 */

static struct in_addr *
get_server_addrs(number)
int *number;				/* RETURN */
{
	register int i;
	char **hes_resolve();
	char **server_hosts;
	register char **cpp;
	struct in_addr *addrs;
	register struct in_addr *addr;
	register struct hostent *hp;

	/* get the names from Hesiod */
	if (!(server_hosts = hes_resolve("zephyr","sloc")))
		return((struct in_addr *)NULL);

	/* count up */
	for (cpp = server_hosts, i = 0; *cpp; cpp++, i++);
	
	addrs = (struct in_addr *) xmalloc(i * sizeof(struct in_addr));

	/* Convert to in_addr's */
	for (cpp = server_hosts, addr = addrs, i = 0; *cpp; cpp++) {
		hp = gethostbyname(*cpp);
		if (hp) {
			bcopy((caddr_t)hp->h_addr,
			      (caddr_t) addr,
			      sizeof(struct in_addr));
			addr++, i++;
		} else
			syslog(LOG_WARNING, "hostname failed, %s",*cpp);
	}
	*number = i;
	return(addrs);
}

/*
 * initialize the server structure for address addr, and set a timer
 * to go off immediately to send hello's to other servers.
 */

static void
setup_server(server, addr)
register ZServerDesc_t *server;
struct in_addr *addr;
{
	register ZHostList_t *host;
	extern int timo_dead;

	server->zs_state = SERV_DEAD;
	server->zs_timeout = timo_dead;
	server->zs_numsent = 0;
	server->zs_addr.sin_family = AF_INET;
	/* he listens to the same port we do */
	server->zs_addr.sin_port = sock_sin.sin_port;
	server->zs_addr.sin_addr = *addr;

	/* set up a timer for this server */
	server->zs_timer = timer_set_rel(0L, server_timo, (caddr_t) server);
	if (!(host = (ZHostList_t *) xmalloc(sizeof(ZHostList_t)))) {
		/* unrecoverable */
		syslog(LOG_CRIT, "zs_host malloc");
		abort();
	}
	host->q_forw = host->q_back = host;
	server->zs_hosts = host;
	return;
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
	hostm_shutdown();
	syslog(LOG_INFO, "goodbye");
	exit(0);
	/*NOTREACHED*/
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
