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
 * void server_recover(client)
 *	ZClient_t *client;
 *
 * void server_adispatch(notice, auth, who, server)
 *	ZNotice_t *notice;
 * 	int auth;
 *	struct sockaddr_in *who;
 *	ZServerDesc_t *server;
 *
 * void server_forward(notice, auth, who)
 *	ZNotice_t *notice;
 *	int auth;
 *	struct sockaddr_in *who;
 *
 * ZServerDesc_t *server_which_server(who)
 *	struct sockaddr_in *who;
 *
 * void server_kill_clt(client);
 *	ZClient_t *client;
 *
 */

static void server_hello(), server_flush(), admin_dispatch(), setup_server();
static void hello_respond(), srv_responded(), send_msg(), send_msg_list();
static void srv_alive(), srv_nack_cancel(), srv_rexmit(), srv_nack_release();
static void recover_clt(), kill_clt(), server_lost();
static void send_stats();

static Code_t server_register();
static struct in_addr *get_server_addrs();

ZNotAcked_t *srv_nacklist;		/* not acked list for server-server
					   packets */
ZServerDesc_t *otherservers;		/* points to an array of the known
					   servers */
int nservers;				/* number of other servers */
int me_server_idx;			/* # of my entry in the array */

#define	ADJUST		(1)		/* adjust timeout on hello input */
#define	DONT_ADJUST	(0)		/* don't adjust timeout */

/* parameters controlling the transitions of the FSM's--patchable with adb */
int timo_up = TIMO_UP;
int timo_tardy = TIMO_TARDY;
int timo_dead = TIMO_DEAD;

long srv_rexmit_secs = REXMIT_SECS;

#ifdef DEBUG
extern int zalone;
#endif DEBUG
/*
 * Initialize the array of servers.  The `limbo' server goes in the first
 * slot (otherservers[0]).
 * Contact Hesiod to find all the other servers, allocate space for the
 * structure, initialize them all to SERV_DEAD with expired timeouts.
 * Set up a list header for server_forward retransmits.
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

#ifdef DEBUG
	if (zalone)
		nservers = 1;
	else
#endif DEBUG
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
		syslog(LOG_WARNING, "I'm a renegade server!");
		otherservers = (ZServerDesc_t *)realloc((caddr_t) otherservers, (unsigned) (++nservers * sizeof(ZServerDesc_t)));
		if (!otherservers) {
			syslog(LOG_CRIT, "renegade realloc");
			abort();
		}
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
	if (!(srv_nacklist = (ZNotAcked_t *) xmalloc(sizeof(ZNotAcked_t)))) {
		/* unrecoverable */
		syslog(LOG_CRIT, "srv_nacklist malloc");
		abort();
	}
	bzero((caddr_t) srv_nacklist, sizeof(ZNotAcked_t));
	srv_nacklist->q_forw = srv_nacklist->q_back = srv_nacklist;
}

/* note: these must match the order given in zserver.h */
static char *
srv_states[] = {
	"SERV_UP",
	"SERV_TARDY",
	"SERV_DEAD",
	"SERV_STARTING"
};

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
			server_lost(which);
		}
		auth = 0;
		break;
	default:
		syslog(LOG_ERR,"Bad server state, server 0x%x\n",which);
		abort();
	}
	/* now he's either TARDY, STARTING, or DEAD
	   We send a "hello," which increments the counter */
	zdbug((LOG_DEBUG, "srv %s is %s",inet_ntoa(which->zs_addr.sin_addr),
	       srv_states[(int) which->zs_state]));
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

	if (notice->z_kind == SERVACK) {
		srv_nack_cancel(notice, who);
		srv_responded(who);
		return;
	}
	/* XXX set up a who for the real origin */
	bzero((caddr_t) &newwho, sizeof(newwho));
	newwho.sin_family = AF_INET;
	newwho.sin_addr.s_addr = notice->z_sender_addr.s_addr;
	newwho.sin_port = notice->z_port;

	server = server_which_server(who);

	if (class_is_admin(notice)) {
		/* admins don't get acked, else we get a packet loop */
		admin_dispatch(notice, auth, who, server);
		return;
	} else if (class_is_control(notice))
		control_dispatch(notice, auth, &newwho, server);
	else if (class_is_ulogin(notice))
		ulogin_dispatch(notice, auth, &newwho, server);
	else if (class_is_ulocate(notice))
		ulocate_dispatch(notice, auth, &newwho, server);
	else
		/* shouldn't come from another server */
		syslog(LOG_WARNING, "srv_disp: pkt cls %s",notice->z_class);

	/* acknowledge it */
	ack(notice, who);
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
	zdbug((LOG_DEBUG, "srv %s is %s",
	       inet_ntoa(otherservers[nservers].zs_addr.sin_addr),
	       srv_states[(int) otherservers[nservers].zs_state]));
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
	ZServerDesc_t *server;
	char *lyst[2];
	char buf[512];

	zdbug((LOG_DEBUG,"server recover"));
	if ((server = hostm_find_server(&client->zct_sin.sin_addr))) {
		if (server == limbo_server) {
			zdbug((LOG_DEBUG, "no server to recover"));
			return;
		} else if (server == me_server) {
			/* send a ping, set up a timeout, and return */
			hostm_losing(client, hostm_find_host(&client->zct_sin.sin_addr));
			return;
		} else {
			/* some other server */
			lyst[0] = inet_ntoa(client->zct_sin.sin_addr);
			(void) sprintf(buf, "%d", ntohs(client->zct_sin.sin_port));
			lyst[1] = buf;
			send_msg_list(&server->zs_addr, ADMIN_LOST_CLT,
				      lyst, 2, 0);
			return;
		}
	} else
		syslog(LOG_ERR, "srv_recover: no host for client");
	return;
}

/*
 * Tell the other servers that this client died.
 */

void
server_kill_clt(client)
ZClient_t *client;
{
	register int i;
	char buf[512], *lyst[2];
	ZNotice_t notice;
	register ZNotAcked_t *nacked;
	register ZNotice_t *pnotice; /* speed hack */
	caddr_t pack;
	int packlen, auth;
	Code_t retval;


	zdbug((LOG_DEBUG, "server kill clt"));
	lyst[0] = inet_ntoa(client->zct_sin.sin_addr),
	(void) sprintf(buf, "%d", ntohs(client->zct_sin.sin_port));
	lyst[1] = buf;

	pnotice = &notice;

	pnotice->z_kind = ACKED;

	pnotice->z_port = sock_sin.sin_port;
	pnotice->z_class = ZEPHYR_ADMIN_CLASS;
	pnotice->z_class_inst = "";
	pnotice->z_opcode = ADMIN_KILL_CLT;
	pnotice->z_sender = myname;	/* myname is the hostname */
	pnotice->z_recipient = "";
	pnotice->z_default_format = 0;

	/* XXX */
	auth = 0;

	/* don't tell limbo to flush, start at 1*/
	for (i = 1; i < nservers; i++) {
		if (i == me_server_idx)	/* don't xmit to myself */
			continue;
		if (otherservers[i].zs_state == SERV_DEAD)
			continue;

		if (!(pack = (caddr_t) xmalloc(sizeof(ZPacket_t)))) {
			syslog(LOG_ERR, "srv_forw malloc");
			continue;	/* DON'T put on nack list */
		}

		packlen = sizeof(ZPacket_t);
		if ((retval = ZFormatNoticeList(pnotice, lyst, 2, pack, packlen, &packlen, auth ? ZAUTH : ZNOAUTH)) != ZERR_NONE) {
			syslog(LOG_WARNING, "kill_clt format: %s",
			       error_message(retval));
			return;
		}
		if ((retval = ZSetDestAddr(&otherservers[i].zs_addr))
		    != ZERR_NONE) {
			syslog(LOG_WARNING, "kill_clt set addr: %s",
			       error_message(retval));
			return;
		}
		if ((retval = ZSendPacket(pack, packlen)) != ZERR_NONE) {
			syslog(LOG_WARNING,
			       "kill_clt xmit: %s", error_message(retval));
			return;
		}

		/* now we've sent it, mark it as not ack'ed */
		
		if (!(nacked = (ZNotAcked_t *)xmalloc(sizeof(ZNotAcked_t)))) {
			/* no space: just punt */
			syslog(LOG_ERR, "srv_forw nack malloc");
			xfree(pack);
			continue;
		}

		nacked->na_rexmits = 0;
		nacked->na_packet = pack;
		nacked->na_srv_idx = i;
		nacked->na_packsz = packlen;
		nacked->na_uid = pnotice->z_uid;
		nacked->q_forw = nacked->q_back = nacked;
		nacked->na_abstimo = 0;

		/* set a timer to retransmit */
		nacked->na_timer = timer_set_rel(srv_rexmit_secs,
						 srv_rexmit,
						 (caddr_t) nacked);
		/* chain in */
		xinsque(nacked, srv_nacklist);
	}
	
}

/*
 * A client has died.  remove it
 */

static void
kill_clt(notice)
ZNotice_t *notice;
{
	struct sockaddr_in who;
	ZHostList_t *host;
	ZClient_t *client;

	zdbug((LOG_DEBUG, "kill_clt"));
	if (extract_addr(notice, &who) != ZERR_NONE)
		return;
	if (!(host = hostm_find_host(&who.sin_addr))) {
		syslog(LOG_WARNING, "no host kill_clt");
		return;
	}
	if (!(client = client_which_client(&who, notice))) {
		syslog(LOG_WARNING, "no clt kill_clt");
		return;
	}
	/* remove the locations, too */
	client_deregister(client, host, 1);
	return;
}

/*
 * Another server asked us to initiate recovery protocol with the hostmanager
 */
static void
recover_clt(notice)
register ZNotice_t *notice;
{
	struct sockaddr_in who;
	ZClient_t *client;
	ZHostList_t *host;

	if (extract_addr(notice, &who) != ZERR_NONE)
		return;
	if (!(host = hostm_find_host(&who.sin_addr))) {
		syslog(LOG_WARNING, "recover_clt h not found");
		return;
	}
	if (!(client = client_which_client(&who, notice))) {
		syslog(LOG_WARNING, "recover_clt not found");
		return;
	}
	hostm_losing(client, host);
}

/*
 * extract a sockaddr_in from a message body
 */

static Code_t
extract_addr(notice, who)
ZNotice_t *notice;
struct sockaddr_in *who;
{
	register char *cp = notice->z_message;

	if (!notice->z_message_len) {
		syslog(LOG_WARNING, "bad addr pkt");
		return(ZSRV_PKSHORT);
	}
	who->sin_addr.s_addr = inet_addr(notice->z_message);
	cp += strlen(cp) + 1;
	if (cp >= notice->z_message + notice->z_message_len) {
		syslog(LOG_WARNING, "short addr pkt");
		return(ZSRV_PKSHORT);
	}
	who->sin_port = notice->z_port = htons((u_short) atoi(cp));
	who->sin_family = AF_INET;
	zdbug((LOG_DEBUG,"ext %s/%d", inet_ntoa(who->sin_addr),
	       ntohs(who->sin_port)));
	return(ZERR_NONE);
}

/*
 * Flush all data associated with the server which
 */

static void
server_flush(which)
register ZServerDesc_t *which;
{
	register ZHostList_t *hst;

	zdbug((LOG_DEBUG, "server_flush"));
	if (!which->zs_hosts) /* no data to flush */
		return;

	for (hst = which->zs_hosts->q_forw;
	     hst != which->zs_hosts;
	     hst = which->zs_hosts->q_forw) {
		/* for each host, flush all data */
		hostm_flush(hst, which);
	}
	srv_nack_release(which);
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
	send_msg(&which->zs_addr, ADMIN_HELLO, auth);
	(which->zs_numsent)++;
	return;
}

/*
 * Handle an ADMIN message from a server
 */

/*ARGSUSED*/
static void
admin_dispatch(notice, auth, who, server)
ZNotice_t *notice;
int auth;
struct sockaddr_in *who;
ZServerDesc_t *server;
{
	register char *opcode = notice->z_opcode;

	zdbug((LOG_DEBUG, "ADMIN received"));

	if (!strcmp(opcode, ADMIN_HELLO)) {
		hello_respond(who, ADJUST, auth);
	} else if (!strcmp(opcode, ADMIN_IMHERE)) {
		srv_responded(who);
	} else if (!strcmp(opcode, ADMIN_SHUTDOWN)) {
		zdbug((LOG_DEBUG, "server shutdown"));
		/* we need to transfer all of its hosts to limbo */
		if (server) {
			server_lost(server);
			server->zs_state = SERV_DEAD;
			server->zs_timeout = timo_dead;
			/* don't worry about the timer, it will
			   be set appropriately on the next send */
			zdbug((LOG_DEBUG, "srv %s is %s",
			       inet_ntoa(server->zs_addr.sin_addr),
			       srv_states[(int) server->zs_state]));
		}
	} else if (!strcmp(opcode, ADMIN_BDUMP)) {
		bdump_get(notice, auth, who, server);
	} else if (!strcmp(opcode, ADMIN_LOST_CLT)) {
		recover_clt(notice);
	} else if (!strcmp(opcode, ADMIN_KILL_CLT)) {
		kill_clt(notice);
		ack(notice, who);
	} else
		syslog(LOG_WARNING, "ADMIN unknown opcode %s",opcode);
	return; 
}

/*
 * Transfer all the hosts on server to limbo
 */

static void
server_lost(server)
ZServerDesc_t *server;
{
	register ZHostList_t *host, *hishost;

	hishost = server->zs_hosts;
	for (host = hishost->q_forw;
	     host != hishost;
	     host = hishost->q_forw)
		/* hostm transfer remque's the host and
		   attaches it to the new server */
		hostm_transfer(host, limbo_server);
}

/*
 * Handle an ADMIN message from some random client.
 * For now, assume it's a registration-type message from some other
 * previously unknown server
 */

/*ARGSUSED*/
void
server_adispatch(notice, auth, who, server)
ZNotice_t *notice;
int auth;
struct sockaddr_in *who;
ZServerDesc_t *server;
{

	/* this had better be a HELLO message--start of acquisition
	   protocol, OR a status req packet */

	if (!strcmp(notice->z_opcode, ADMIN_STATUS)) {
		/* status packet */
		send_stats(who);
		return;
	}
#ifdef notdef
	syslog(LOG_INFO, "disp: new server?");
	if (server_register(notice, auth, who) != ZERR_NONE)
		syslog(LOG_INFO, "new server failed");
	else {
		syslog(LOG_INFO, "new server %s, %d",
		       inet_ntoa(who->sin_addr),
		       ntohs(who->sin_port));
		hello_respond(who, DONT_ADJUST, auth);
	}
#endif notdef
	return;
}

static void
send_stats(who)
struct sockaddr_in *who;
{
	register int i;
	char buf[BUFSIZ];
	char **responses;
	int num_resp;
	char *vers, *pkts, *upt;
#define	NUM_FIXED 3			/* 3 fixed fields, plus server info */

	(void) strcpy(buf,version);
	(void) strcat(buf, "/");
#ifdef vax
	(void) strcat(buf, "VAX");
#endif vax
#ifdef ibm032
	(void) strcat(buf, "IBM 032");
#endif ibm032
#ifdef sun
	(void) strcat(buf, "SUN");
#endif sun
	vers = strsave(buf);

	(void) sprintf(buf, "%d pkts", npackets);
	pkts = strsave(buf);
	(void) sprintf(buf, "%d seconds operational",NOW - uptime);
	upt = strsave(buf);

	responses = (char **) xmalloc((NUM_FIXED + nservers)*sizeof(char **));
	responses[0] = vers;
	responses[1] = pkts;
	responses[2] = upt;

	num_resp = NUM_FIXED;
	/* start at 1 and ignore limbo */
	for (i = 1; i < nservers ; i++) {
		(void) sprintf(buf, "%s/%s",
			       inet_ntoa(otherservers[i].zs_addr.sin_addr),
			       srv_states[(int) otherservers[i].zs_state]);
		responses[num_resp++] = strsave(buf);
	}

	send_msg_list(who, ADMIN_STATUS, responses, num_resp, 0);
	for (i = 0; i < num_resp; i++)
		xfree(responses[i]);
	xfree(responses);
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
hello_respond(who, adj, auth)
struct sockaddr_in *who;
int adj;
int auth;
{
	register ZServerDesc_t *which;

	send_msg(who, ADMIN_IMHERE, auth);
	if (adj != ADJUST)
		return;

	/* If we think he's down, schedule an immediate HELLO. */

	if (!(which = server_which_server(who)))
		return;

	switch (which->zs_state) {
	case SERV_DEAD:
		/* he said hello, we thought he was dead.
		   reschedule his hello for now. */
		timer_reset(which->zs_timer);
		which->zs_timer = timer_set_rel(0L, server_timo,
						(caddr_t) which);
		break;
	case SERV_STARTING:
	case SERV_TARDY:
	case SERV_UP:
	default:
		break;
	}
	return;
}    

/*
 * return the server descriptor for server at who
 */

ZServerDesc_t *
server_which_server(who)
struct sockaddr_in *who;
{
	register ZServerDesc_t *server;
	register int i;

	if (who->sin_port != sock_sin.sin_port)
		return(NULLZSDT);
		
	/* don't check limbo */
	for (server = &otherservers[1], i = 1; i < nservers; i++, server++) {
		if (server->zs_addr.sin_addr.s_addr == who->sin_addr.s_addr)
			return(server);
	}
	return(NULLZSDT);
}

/*
 * We received a response to a hello packet or an ack. Adjust server state
 * appropriately.
 */
static void
srv_responded(who)
struct sockaddr_in *who;
{
	register ZServerDesc_t *which = server_which_server(who);

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
		/* here we negotiate and set up a braindump */
		if (!bdump_socket) {
			/* XXX offer it to the other server */
			bdump_offer(who);
		}			
		break;
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
	zdbug((LOG_DEBUG, "srv %s is %s",inet_ntoa(which->zs_addr.sin_addr),
	       srv_states[(int) which->zs_state]));
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
		send_msg(&otherservers[i].zs_addr, ADMIN_SHUTDOWN, 1);
	}
	return;
}

/*
 * send a message to who with admin class and opcode and clinst as specified.
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
	pnotice->z_default_format = 0;
	pnotice->z_message = (caddr_t) NULL;
	pnotice->z_message_len = 0;

	packlen = sizeof(pack);
	
	/* XXX for now, we don't do authentication */
	auth = 0;

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
 * send a notice with a message to who with admin class and opcode and
 * message body as specified.
 * auth is set if we want to send authenticated
 */

static void
send_msg_list(who, opcode, lyst, num, auth)
struct sockaddr_in *who;
char *opcode;
char *lyst[];
int num;
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
	pnotice->z_default_format = 0;
	pnotice->z_message = (caddr_t) NULL;
	pnotice->z_message_len = 0;

	packlen = sizeof(pack);
	
	/* XXX for now, we don't do authentication */
	auth = 0;

	if ((retval = ZFormatNoticeList(pnotice, lyst, num, pack, packlen, &packlen, auth ? ZAUTH : ZNOAUTH)) != ZERR_NONE) {
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
/*ARGSUSED*/
void
server_forward(notice, auth, who)
ZNotice_t *notice;
int auth;
struct sockaddr_in *who;
{
	register int i;
	caddr_t pack;
	int packlen;
	Code_t retval;
	register ZNotAcked_t *nacked;


	if (bdumping) {
		zdbug((LOG_DEBUG,"bdumping, won't srv_forw"));
		return;
	}
	zdbug((LOG_DEBUG, "srv_forw"));
	/* don't send to limbo */
	for (i = 1; i < nservers; i++) {
		if (i == me_server_idx)	/* don't xmit to myself */
			continue;
		if (otherservers[i].zs_state == SERV_DEAD)
			continue;

		if (!(pack = (caddr_t) xmalloc(sizeof(ZPacket_t)))) {
			syslog(LOG_ERR, "srv_forw malloc");
			continue;	/* DON'T put on nack list */
		}

		packlen = sizeof(ZPacket_t);
		if ((retval = ZFormatRawNotice(notice, pack, packlen, &packlen)) != ZERR_NONE) {
			syslog(LOG_WARNING, "srv_fwd format: %s",
			       error_message(retval));
			xfree(pack);
			continue;
		}
		if ((retval = ZSetDestAddr(&otherservers[i].zs_addr)) != ZERR_NONE) {
			syslog(LOG_WARNING, "srv_fwd set addr: %s",
			       error_message(retval));
			xfree(pack);
			continue;
		}
		if ((retval = ZSendPacket(pack, packlen)) != ZERR_NONE) {
			syslog(LOG_WARNING, "srv_fwd xmit: %s", error_message(retval));
			xfree(pack);
			continue;
		}			
		/* now we've sent it, mark it as not ack'ed */
		
		if (!(nacked = (ZNotAcked_t *)xmalloc(sizeof(ZNotAcked_t)))) {
			/* no space: just punt */
			syslog(LOG_ERR, "srv_forw nack malloc");
			xfree(pack);
			continue;
		}

		nacked->na_rexmits = 0;
		nacked->na_packet = pack;
		nacked->na_srv_idx = i;
		nacked->na_packsz = packlen;
		nacked->na_uid = notice->z_uid;
		nacked->q_forw = nacked->q_back = nacked;
		nacked->na_abstimo = 0;

		/* set a timer to retransmit */
		nacked->na_timer = timer_set_rel(srv_rexmit_secs,
						 srv_rexmit,
						 (caddr_t) nacked);
		/* chain in */
		xinsque(nacked, srv_nacklist);
	}
	return;
}

/*
 * a server has acknowledged a message we sent to him; remove it from
 * server unacked queue
 */

static void
srv_nack_cancel(notice, who)
register ZNotice_t *notice;
struct sockaddr_in *who;
{
	register ZServerDesc_t *which = server_which_server(who);
	register ZNotAcked_t *nacked;

	if (!which) {
		syslog(LOG_ERR, "non-server ack?");
		return;
	}
	for (nacked = srv_nacklist->q_forw;
	     nacked != srv_nacklist;
	     nacked = nacked->q_forw)
		if (&otherservers[nacked->na_srv_idx] == which)
			if (ZCompareUID(&nacked->na_uid, &notice->z_uid)) {
				timer_reset(nacked->na_timer);
				xfree(nacked->na_packet);
				xremque(nacked);
				xfree(nacked);
				return;
			}
	zdbug((LOG_DEBUG, "srv_nack not found"));
	return;
}

/*
 * retransmit a message to another server
 */

static void
srv_rexmit(nackpacket)
register ZNotAcked_t *nackpacket;
{
	Code_t retval;
	/* retransmit the packet */
	
	zdbug((LOG_DEBUG,"srv_rexmit to %s/%d",
	       inet_ntoa(otherservers[nackpacket->na_srv_idx].zs_addr.sin_addr),
	       ntohs(otherservers[nackpacket->na_srv_idx].zs_addr.sin_port)));

	if (otherservers[nackpacket->na_srv_idx].zs_state == SERV_DEAD) {
		zdbug((LOG_DEBUG, "canceling send to dead server"));
		xremque(nackpacket);
		xfree(nackpacket->na_packet);
		srv_nack_release(&otherservers[nackpacket->na_srv_idx]);
		xfree(nackpacket);
		return;
	}
	if ((retval = ZSetDestAddr(&otherservers[nackpacket->na_srv_idx].zs_addr))	
	    != ZERR_NONE) {
		syslog(LOG_WARNING, "srv_rexmit set addr: %s",
		       error_message(retval));
		goto requeue;

	}
	if ((retval = ZSendPacket(nackpacket->na_packet,
				  nackpacket->na_packsz)) != ZERR_NONE)
		syslog(LOG_WARNING, "srv_rexmit xmit: %s", error_message(retval));

requeue:
	/* reset the timer */
	nackpacket->na_timer = timer_set_rel(srv_rexmit_secs,
					     srv_rexmit,
					     (caddr_t) nackpacket);
	return;
}

/*
 * Clean up the not-yet-acked queue and release anything destined
 * to the server.
 */

static void
srv_nack_release(server)
ZServerDesc_t *server;
{
	register ZNotAcked_t *nacked, *nack2;

	/* search the not-yet-acked list for anything destined to him, and
	   flush it. */
	for (nacked = nacklist->q_forw;
	     nacked != nacklist;)
		if (&otherservers[nacked->na_srv_idx] == server) {
			/* go back, since remque will change things */
			nack2 = nacked->q_back;
			timer_reset(nacked->na_timer);
			xremque(nacked);
			xfree(nacked->na_packet);
			xfree(nacked);
			/* now that the remque adjusted the linked list,
			   we go forward again */
			nacked = nack2->q_forw;
		} else
			nacked = nacked->q_forw;
	return;
}
