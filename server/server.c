/* This file is part of the Project Athena Zephyr Notification System.
 * It contains functions for communication with other servers.
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
static char rcsid_server_s_c[] = "$Header$";
#endif SABER
#endif lint

#include "zserver.h"
#include <sys/socket.h>			/* for AF_INET */
#include <netdb.h>			/* for gethostbyname */

/*
 * Server manager.  Deal with  traffic to and from other servers.
 *
 * void server_init()
 *
 *
 * void server_shutdown()
 *
 * void server_timo(which)
 * 	ZServerDesc_t *which;
 *
 * void server_dispatch(notice, auth, who)
 *	ZNotice_t *notice;
 * 	int auth;
 *	struct sockaddr_in *who;
 *
 * Code_t server_register(notice, who)
 *	ZNotice_t *notice;
 *	struct sockaddr_in *who;
 *
 * void server_recover(client)
 *	ZClient_t *client;
 *
 * void server_adispatch(notice, auth, who)
 *	ZNotice_t *notice;
 * 	int auth;
 *	struct sockaddr_in *who;
 *
 * void server_forward(notice, auth, who)
 *	ZNotice_t *notice;
 *	int auth;
 *	struct sockaddr_in *who;
 *
 */

static void server_hello(), server_flush(), admin_handle(), setup_server();
static void hello_respond(), hello_input(), send_msg();

static Code_t server_register();
static struct in_addr *get_server_addrs();
static ZServerDesc_t *which_server();

ZServerDesc_t *otherservers;		/* points to an array of the known
					   servers */
int nservers;				/* number of other servers */
int me_server_idx;			/* # of my entry in the array */

/* parameters controlling the transitions of the FSM's--patchable with adb */
int timo_up = TIMO_UP;
int timo_tardy = TIMO_TARDY;
int timo_dead = TIMO_DEAD;

/*
 * Initialize the array of servers.  The `limbo' server goes in the first
 * slot (otherservers[0]).
 * Contact Hesiod to find all the other servers, allocate space for the
 * structure, initialize them all to SERV_DEAD with expired timeouts.
 */

void
server_init()
{
	register int i;
	struct in_addr *serv_addr, *hes_addrs, limbo_addr;

	/* talk to hesiod here, set nservers */
	if (!(hes_addrs = get_server_addrs(&nservers))) {
		    syslog(LOG_ERR, "No servers?!?");
		    exit(1);
	    }

	/* increment servers to make room for 'limbo' */
	nservers++;

	otherservers = (ZServerDesc_t *) xmalloc(nservers *
						sizeof(ZServerDesc_t));
	me_server_idx = -1;

	/* set up limbo */
	limbo_addr.s_addr = (unsigned long) 0;
	setup_server(otherservers, &limbo_addr);
	timer_reset(otherservers[0].zs_timer);
	otherservers[0].zs_timer = (timer) NULL;

	for (serv_addr = hes_addrs, i = 1; i < nservers; serv_addr++, i++) {
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

		/* I don't send hello's to myself--cancel the timer */
		timer_reset(otherservers[nservers - 1].zs_timer);
		otherservers[nservers - 1].zs_timer = (timer) NULL;

		/* cancel and reschedule all the timers--pointers need
		   adjusting */
		/* don't reschedule limbo's timer, so start i=1 */
		for (i = 1; i < nservers - 2; i++) {
			timer_reset(otherservers[i].zs_timer);
			/* all the HELLO's are due now */
			otherservers[i].zs_timer = timer_set_rel(0L, server_timo, (caddr_t) &otherservers[i]);
		}
		me_server_idx = nservers - 1;
	}
}

/* 
 * A server timout has expired.  If enough hello's have been unanswered,
 * change state and act accordingly. Send a "hello" and reset the timer,
 * incrementing the number of hello's sent.
 *
 * See the FSM in the Zephyr document for a better picture of what's
 * happening here. 
 */

void
server_timo(which)
ZServerDesc_t *which;
{
	int auth;

	zdbug((LOG_DEBUG,"srv_timo: %s", inet_ntoa(which->zs_addr.sin_addr)));
	/* change state and reset if appropriate */
	switch(which->zs_state) {
	case SERV_DEAD:			/* leave him dead */
		server_flush(which);
		auth = 1;
		break;
	case SERV_UP:			/* he's now tardy */
		which->zs_state = SERV_TARDY;
		which->zs_numsent = 0;
		which->zs_timeout = timo_tardy;
		auth = 0;
		break;
	case SERV_TARDY:
	case SERV_STARTING:
		if (which->zs_numsent >= ((which->zs_state == SERV_TARDY) ?
					  H_NUM_TARDY :
					  H_NUM_STARTING)) {
			/* he hasn't answered, assume DEAD */
			which->zs_state = SERV_DEAD;
			which->zs_numsent = 0;
			which->zs_timeout = timo_dead;
			server_flush(which);
		}
		auth = 0;
		break;
	default:
		syslog(LOG_ERR,"Bad server state, server 0x%x\n",which);
		abort();
	}
	/* now he's either TARDY, STARTING, or DEAD
	   We send a "hello," which increments the counter */
	zdbug((LOG_DEBUG, "srv %s is %d",inet_ntoa(which->zs_addr.sin_addr),
	       (int) which->zs_state));
	server_hello(which, auth);
	/* reschedule the timer */
	which->zs_timer = timer_set_rel(which->zs_timeout, server_timo,
					(caddr_t) which);
}

/*
 * Dispatch a notice from some other server
 */

/*ARGSUSED*/
void
server_dispatch(notice, auth, who)
ZNotice_t *notice;
int auth;
struct sockaddr_in *who;
{
	ZServerDesc_t *server;
	struct sockaddr_in newwho;

	zdbug((LOG_DEBUG, "server_dispatch"));

	/* XXX set up a who for the real origin */
	bzero((caddr_t) &newwho, sizeof(newwho));
	newwho.sin_family = AF_INET;
	newwho.sin_addr.s_addr = notice->z_sender_addr.s_addr;
	newwho.sin_port = notice->z_port;

	server = which_server(who);

	if (class_is_admin(notice))
		admin_handle(notice, auth, who, server);
	else if (class_is_control(notice))
		control_dispatch(notice, auth, &newwho, server);
	else if (class_is_ulogin(notice))
		ulogin_dispatch(notice, auth, &newwho, server);
	else if (class_is_ulocate(notice))
		ulocate_dispatch(notice, auth, &newwho, server);
	else
		/* shouldn't come from another server */
		syslog(LOG_WARNING, "srv_disp: pkt cls %s",notice->z_class);
	return;
}

/*
 * Register a new server (one not in our list).  This MUST be authenticated.
 */

/*ARGSUSED*/
static Code_t
server_register(notice, auth, who)
ZNotice_t *notice;
int auth;
struct sockaddr_in *who;
{
	ZServerDesc_t *temp;
	register int i;
	long timerval;

	if (who->sin_port != sock_sin.sin_port) {
		zdbug((LOG_DEBUG, "srv_register wrong port %d",
		       ntohs(who->sin_port)));
		return(1);
	}
	/* Not yet... talk to ken about authenticators */
#ifdef notdef
	if (!auth) {
		zdbug((LOG_DEBUG, "srv_register unauth"));
		return(1);
	}
#endif notdef
	/* OK, go ahead and set him up. */
	temp = (ZServerDesc_t *)malloc((unsigned) ((nservers + 1) * sizeof(ZServerDesc_t)));
	if (!temp) {
		syslog(LOG_CRIT, "srv_reg malloc");
		return(1);
	}
	bcopy((caddr_t) otherservers, (caddr_t) temp, nservers * sizeof(ZServerDesc_t));
	xfree(otherservers);
	otherservers = temp;
	/* don't reschedule limbo's timer, so start i=1 */
	for (i = 1; i < nservers - 1; i++) {
		if (i == me_server_idx) /* don't reset myself */
			continue;
		/* reschedule the timers--we moved otherservers */
		timerval = timer_when(otherservers[i].zs_timer);
		timer_reset(otherservers[i].zs_timer);
		otherservers[i].zs_timer = timer_set_abs(timerval, server_timo, (caddr_t) &otherservers[i]);
	}
	setup_server(&otherservers[nservers], &who->sin_addr);
	otherservers[nservers].zs_state = SERV_STARTING;
	otherservers[nservers].zs_timeout = timo_tardy;
	nservers++;
	get_brain_dump(who);

	return(0);
}

/*
 * Recover a host whose client has stopped responding.
 * The hostm_ module takes care of pings, timeouts, etc.
 */

void
server_recover(client)
ZClient_t *client;
{
	ZHostList_t *host;

	zdbug((LOG_DEBUG,"server recover"));
	/* XXX */
	if ((host = hostm_find_host(&client->zct_sin.sin_addr)))
		/* send a ping, set up a timeout, and return */
		hostm_losing(client, host);
	else
		syslog(LOG_ERR, "srv_recover: no host for client");
	return;
}

/*
 * Flush all data associated with the server which
 */

static void
server_flush(which)
register ZServerDesc_t *which;
{
	register ZHostList_t *hst;

	if (!which->zs_hosts) /* no data to flush */
		return;

	for (hst = which->zs_hosts->q_forw;
	     hst != which->zs_hosts;
	     hst = which->zs_hosts->q_forw) {
		/* for each host, flush all data */
		hostm_flush(hst, which);
	}

}

/*
 * send a hello to which, updating the count of hello's sent
 * Authenticate if auth is set.
 */

static void
server_hello(which, auth)
ZServerDesc_t *which;
int auth;
{
	send_msg(&which->zs_addr, ADMIN_HELLO, 0);
	(which->zs_numsent)++;
	return;
}

/*
 * Handle an ADMIN message from a server
 */

/*ARGSUSED*/
static void
admin_handle(notice, auth, who, server)
ZNotice_t *notice;
int auth;
struct sockaddr_in *who;
ZServerDesc_t *server;
{
	register char *opcode = notice->z_opcode;
	register ZHostList_t *host, *hishost;;

	zdbug((LOG_DEBUG, "ADMIN received"));

	if (!strcmp(opcode, ADMIN_HELLO)) {
		hello_respond(who);
#ifdef notdef
		if ((him = which_server(who))) {
			/* XXX take a hint here that the other guy is up */
		}
#endif notdef		
	} else if (!strcmp(opcode, ADMIN_IMHERE)) {
		hello_input(notice, auth, who);
	} else if (!strcmp(opcode, ADMIN_SHUTDOWN)) {
		zdbug((LOG_DEBUG, "server shutdown"));
		/* we need to transfer all of its hosts to limbo */
		if (server) {
			hishost = server->zs_hosts;
			for (host = hishost->q_forw;
			     host != hishost;
			     host = hishost->q_forw)
				/* hostm transfer remque's the host and
				   attaches it to the new server */
				hostm_transfer(host, limbo_server);

		}
	} else
		syslog(LOG_WARNING, "ADMIN unknown opcode %s",opcode);
	return; 
}


/*
 * Handle an ADMIN message from some random client.
 * For now, assume it's a registration-type message from some other
 * previously unknown server
 */

void
server_adispatch(notice, auth, who, server)
ZNotice_t *notice;
int auth;
struct sockaddr_in *who;
ZServerDesc_t *server;
{

	/* this had better be a HELLO message--start of acquisition
	   protocol */
	syslog(LOG_INFO, "disp: new server?");
	if (server_register(notice, auth, who) != ZERR_NONE)
		syslog(LOG_INFO, "new server failed");
	else {
		syslog(LOG_INFO, "new server %s, %d",
		       inet_ntoa(who->sin_addr),
		       ntohs(who->sin_port));
		hello_respond(who);
	}
	return;
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
 * Someone sent us a hello message, respond to them.
 */

static void
hello_respond(who)
struct sockaddr_in *who;
{

	send_msg(who, ADMIN_IMHERE, 0);
	return;
}

/*
 * return the server descriptor for server at who
 */

static ZServerDesc_t *
which_server(who)
struct sockaddr_in *who;
{
	register ZServerDesc_t *server;
	register int i;

	/* don't check limbo */
	for (server = &otherservers[1], i = 1; i < nservers; i++, server++) {
		if (server->zs_addr.sin_addr.s_addr == who->sin_addr.s_addr)
			return(server);
	}
	return(NULLZSDT);
}

/*
 * We received a response to a hello packet. Adjust server state
 * appropriately.
 */
static void
hello_input(notice, auth, who)
ZNotice_t *notice;
int auth;
struct sockaddr_in *who;
{
	register ZServerDesc_t *which = which_server(who);

	if (!which) {
		syslog(LOG_ERR, "hello input from non-server?!");
		return;
	}

	switch (which->zs_state) {
	case SERV_DEAD:
		/* he responded, we thought he was dead. mark as starting
		   and negotiate */
		which->zs_state = SERV_STARTING;

	case SERV_STARTING:
		/* XXX here we negotiate and set up a braindump */

		/* fall through */
	case SERV_TARDY:
		which->zs_state = SERV_UP;
	case SERV_UP:
		/* reset the timer and counts */
		which->zs_numsent = 0;
		which->zs_timeout = timo_up;
		timer_reset(which->zs_timer);
		which->zs_timer = timer_set_rel(which->zs_timeout, server_timo,
						(caddr_t) which);
		break;
	}
	return;
}

/*
 * Send each of the other servers a shutdown message.
 */

void
server_shutdown()
{
	register int i;

	/* don't tell limbo to go away, start at 1*/
	for (i = 1; i < nservers; i++) {
		send_msg(&otherservers[i].zs_addr, ADMIN_SHUTDOWN, 0);
	}
	return;
}

/*
 * send a message to who with admin class and opcode as specified.
 * auth is set if we want to send authenticated
 */

static void
send_msg(who, opcode, auth)
struct sockaddr_in *who;
char *opcode;
int auth;
{
	ZNotice_t notice;
	register ZNotice_t *pnotice; /* speed hack */
	ZPacket_t pack;
	int packlen;
	Code_t retval;

	pnotice = &notice;

	pnotice->z_kind = ACKED;

	pnotice->z_port = sock_sin.sin_port;
	pnotice->z_class = ZEPHYR_ADMIN_CLASS;
	pnotice->z_class_inst = "";
	pnotice->z_opcode = opcode;
	pnotice->z_sender = myname;	/* myname is the hostname */
	pnotice->z_recipient = "";
	pnotice->z_message = (caddr_t) NULL;
	pnotice->z_message_len = 0;

	packlen = sizeof(pack);
	
	if ((retval = ZFormatNotice(pnotice, pack, packlen, &packlen, auth ? ZAUTH : ZNOAUTH)) != ZERR_NONE) {
		syslog(LOG_WARNING, "snd_msg format: %s", error_message(retval));
		return;
	}
	if ((retval = ZSetDestAddr(who)) != ZERR_NONE) {
		syslog(LOG_WARNING, "snd_msg set addr: %s",
		       error_message(retval));
		return;
	}
	if ((retval = ZSendPacket(pack, packlen)) != ZERR_NONE) {
		syslog(LOG_WARNING, "snd_msg xmit: %s", error_message(retval));
		return;
	}
	return;
}

/*
 * Forward the notice to the other servers
 */
void
server_forward(notice, auth, who)
ZNotice_t *notice;
int auth;
struct sockaddr_in *who;
{
	register int i;
	ZPacket_t pack;
	int packlen;
	Code_t retval;


	zdbug((LOG_DEBUG, "srv_forw"));
	/* don't send to limbo */
	for (i = 1; i < nservers; i++) {
		if (i == me_server_idx)	/* don't xmit to myself */
			continue;

		packlen = sizeof(pack);
		if ((retval = ZFormatRawNotice(notice, pack, packlen, &packlen)) != ZERR_NONE) {
			syslog(LOG_WARNING, "srv_fwd format: %s",
			       error_message(retval));
			continue;
		}
		if ((retval = ZSetDestAddr(&otherservers[i].zs_addr)) != ZERR_NONE) {
			syslog(LOG_WARNING, "srv_fwd set addr: %s",
			       error_message(retval));
			continue;
		}
		if ((retval = ZSendPacket(pack, packlen)) != ZERR_NONE) {
			syslog(LOG_WARNING, "srv_fwd xmit: %s", error_message(retval));
			continue;
		}			
	}
	return;
}
