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
static char rcsid_main_c[] = "$Header$";
static char copyright[] = "Copyright (c) 1987 Massachusetts Institute of Technology.  Portions Copyright (c) 1986 Student Information Processing Board, Massachusetts Institute of Technology\n";
#endif lint

/*
 * Server loop for Zephyr.
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

#define	EVER		(;;)		/* don't stop looping */
#define	max(a,b)	((a) > (b) ? (a) : (b))

static int do_net_setup(), initialize();
static struct in_addr *get_server_addrs();
static void usage();
struct in_addr *get_server_addrs();
char *rindex();

int srv_socket;				/* dgram socket for clients
					   and other servers */
struct sockaddr_in sock_sin;
struct in_addr my_addr;
struct timeval nexthost_tv = {0, 0};	/* time till next host keepalive
					   initialize to zero so select doesn't
					   timeout */

int nservers;			/* number of other servers */
ZServerDesc_t *otherservers;		/* points to an array of the known
					   servers */
ZServerDesc_t *me_server;		/* pointer to my entry in the array */
ZNotAcked_t *nacklist;			/* list of packets waiting for ack's */

char *programname;			/* set to the last element of argv[0] */
char myname[MAXHOSTNAMELEN];		/* my host name */

int zdebug = 0;

main(argc,argv)
int argc;
char **argv;
{
	int nfound;			/* #fildes ready on select */
	int nfildes;			/* number to look at in select() */
	int packetsize;			/* size of packet received */
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

	/* set name */
	if (programname = rindex(argv[0],'/'))
		programname++;
	else programname = argv[0];

	/* process arguments */
	
	argv++, argc--;

	while ((optchar = getopt(argc, argv, "d")) != EOF) {
		switch(optchar) {
		case 'd':
			zdebug = 1;
		case '?':
		default:
			usage();
			/*NOTREACHED*/
		}
	}

	/* open log */
	/* XXX eventually make this LOG_DAEMON */
	openlog(programname, LOG_PID, LOG_LOCAL6);

	/* set up sockets & my_addr and myname, 
	   find other servers and set up server table, initialize queues
	   for retransmits, initialize error tables,
	   set up restricted classes */
	if (initialize())
		exit(1);

	FD_ZERO(&interesting);
	FD_SET(srv_socket, &interesting);

	nfildes = srv_socket + 1;


	/* GO! */
	syslog(LOG_INFO, "Ready for action");

	for EVER {
		tvp = &nexthost_tv;
		if (nexttimo != 0L) {
			nexthost_tv.tv_sec = nexttimo - NOW;
			nexthost_tv.tv_usec = 0;
			if (nexthost_tv.tv_sec < 0) { /* timeout has passed! */
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
			/* either we timed out for keepalive or we were just
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
   */

static int
initialize()
{
	register int i;
	struct in_addr *serv_addr, *hes_addrs;

	if (do_net_setup())
		return(1);

	/* talk to hesiod here, set nservers */
	if ((hes_addrs = get_server_addrs(&nservers)) ==
	    (struct in_addr *) NULL) {
		    syslog(LOG_ERR, "No servers?!?");
		    exit(1);
	    }

	otherservers = (ZServerDesc_t *) malloc(nservers *
						sizeof(ZServerDesc_t));
	for (serv_addr = hes_addrs, i = 0; serv_addr; serv_addr++, i++) {
		if (!bcmp(serv_addr, &my_addr, sizeof(struct sockaddr_in)))
			me_server = &otherservers[i];
		otherservers[i].zs_state = SERV_DEAD;
		otherservers[i].zs_timeout = 0;	/* he's due NOW */
		otherservers[i].zs_numsent = 0;
		otherservers[i].zs_addr.sin_family = AF_INET;
		/* he listens to the same port we do */
		otherservers[i].zs_addr.sin_port = sock_sin.sin_port;
		otherservers[i].zs_addr.sin_addr = *serv_addr;

		/* set up a timer for this server */
		otherservers[i].zs_timer =
			timer_set_rel(0L,
				      server_timo,
				      (caddr_t) &otherservers[i]);
		if ((otherservers[i].zs_hosts =
		     (ZHostList_t *) malloc(sizeof(ZHostList_t))) == NULLZHLT)
		{
			/* unrecoverable */
			syslog(LOG_CRIT, "zs_host malloc");
			abort();
		}
	}
	free(hes_addrs);
	if ((nacklist = (ZNotAcked_t *) malloc(sizeof(ZNotAcked_t))) ==
		(ZNotAcked_t *) NULL)
	{
		/* unrecoverable */
		syslog(LOG_CRIT, "nacklist malloc");
		abort();
	}
	nacklist->q_forw = nacklist->q_back = NULL;

	nexttimo = 1L;			/* trigger the timers when we hit
					   the FOR loop */

	ZInitialize();			/* set up the library */
	init_zsrv_err_tbl();		/* set up err table */

	ZSetFD(srv_socket);		/* set up the socket as the
					   input fildes */

	return;
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
	if ((hp = gethostbyname(hostname)) == (struct hostent *) NULL) {
		syslog(LOG_ERR, "no gethostbyname repsonse");
		strncpy(myname, hostname, MAXHOSTNAMELEN);
		return(1);
	}
	strncpy(myname, hp->h_name, MAXHOSTNAMELEN);
	bcopy(hp->h_addr, &my_addr, sizeof(hp->h_addr));
	
	/* note that getservbyname may actually ask hesiod and not
	   /etc/services */
	(void) setservent(1);		/* keep file/connection open */
	
	if ((sp = getservbyname("zephyr-clt", "udp")) ==
	    (struct servent *) NULL) {
		syslog(LOG_ERR, "zephyr-clt/udp unknown");
		return(1);
	}
	bzero(sock_sin, sizeof(sock_sin));
	bcopy(&sock_sin.sin_port, sp->s_port, sizeof(sp->s_port));
	
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
	(void) ioctl(srv_socket, FIONBIO, &on);

	return(0);
}    


/* get a list of server addresses, from Hesiod.  Return a pointer to an
   array of allocated storage.  This storage is freed by the caller.
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
	if ((server_hosts = hes_resolve("*","ZEPHYR-SERVER")) == (char **)NULL)
		return((struct in_addr *)NULL);

	/* count up */
	for (cpp = server_hosts, i = 0; *cpp; cpp++, i++);
	
	addrs = (struct in_addr *) malloc(i * sizeof(struct in_addr));

	/* Convert to in_addr's */
	for (cpp = server_hosts, addr = addrs, i = 0; *cpp; cpp++) {
		hp = gethostbyname(*cpp);
		if (hp) {
			bcopy(hp->h_addr, addr, sizeof(struct in_addr));
			addr++, i++;
		} else
			syslog(LOG_WARNING, "hostname failed, %s",*cpp);
	}
	*number = i;
	return(addrs);
}

static void
usage()
{
	fprintf(stderr,"Usage: %s [-d]\n",programname);
	exit(2);
}
