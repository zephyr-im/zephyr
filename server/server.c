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
static char rcsid_server_c[] = "$Header$";
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
 * void server_dump_servers(fp);
 *	FILE *fp;
 *
 * void server_reset();
 */

static void server_hello(), server_flush(), setup_server();
static void hello_respond(), srv_responded(), send_msg(), send_msg_list();
static void srv_alive(), srv_nack_cancel(), srv_rexmit(), srv_nack_release();
static void srv_nack_move();
static void server_lost();
static void send_stats(), server_queue(), server_forw_reliable();
static Code_t admin_dispatch(), recover_clt(), kill_clt();

#ifdef notdef
static Code_t server_register();
#endif notdef
static struct in_addr *get_server_addrs();
#ifndef HESIOD
static char **get_server_list();
static void free_server_list();
#endif !HESIOD

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
	struct in_addr *serv_addr, *server_addrs, limbo_addr;

	/* we don't need to mask SIGFPE here since when we are called,
	   the signal handler isn't set up yet. */

	/* talk to hesiod here, set nservers */
	if (!(server_addrs = get_server_addrs(&nservers))) {
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
	otherservers[0].zs_update_queue = NULLZSPT;
	otherservers[0].zs_dumping = 0;

	for (serv_addr = server_addrs, i = 1; i < nservers; serv_addr++, i++) {
		setup_server(&otherservers[i], serv_addr);
		/* is this me? */
		if (serv_addr->s_addr == my_addr.s_addr) {
			me_server_idx = i;
			otherservers[i].zs_state = SERV_UP;
			timer_reset(otherservers[i].zs_timer);
			otherservers[i].zs_timer = (timer) NULL;
			otherservers[i].zs_update_queue = NULLZSPT;
			otherservers[i].zs_dumping = 0;
			zdbug((LOG_DEBUG,"found myself"));
		}
	}

	/* free up the addresses */
	xfree(server_addrs);

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
		for (i = 1; i < nservers - 1; i++) {
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

	return;
}

/*
 * server_reset: re-initializes otherservers array by refreshing from Hesiod
 * or disk file.
 *
 * If any server is no longer named in the new list, and that server is in
 * state SERV_DEAD, it is dropped from the server list.
 * All other currently-known servers are retained.
 * Any additional servers not previously known are added to the table.
 *
 * WARNING: Don't call this routine if any of the ancestor procedures have a
 * handle on a particular server other than by indexing on otherservers[].
 */
void
server_reset()
{
	int num_servers;
	struct in_addr *server_addrs;
	register struct in_addr *serv_addr;
	register ZServerDesc_t *servers;
	register int i, j;
	int *ok_list_new, *ok_list_old;
	int num_ok, new_num;

	zdbug((LOG_DEBUG, "server_reset"));
#ifdef DEBUG
	if (zalone) {
		syslog(LOG_INFO, "server_reset while alone, punt");
		return;
	}
#endif DEBUG

	/* Find out what servers are supposed to be known. */
	if (!(server_addrs = get_server_addrs(&num_servers))) {
		syslog(LOG_ERR, "server_reset no servers. nothing done.");
		return;
	}
	if ((ok_list_new = (int *)xmalloc(num_servers * sizeof(int))) ==
	    (int *) 0) {
		syslog(LOG_ERR, "server_reset no mem new");
		return;
	}
	if ((ok_list_old = (int *)xmalloc(nservers * sizeof(int))) ==
	    (int *) 0) {
		syslog(LOG_ERR, "server_reset no mem old");
		xfree(ok_list_new);
		return;
	}

	(void) bzero((char *)ok_list_old, nservers * sizeof(int));
	(void) bzero((char *)ok_list_new, num_servers * sizeof(int));

	/* reset timers--pointers will move */
	for (j = 1; j < nservers; j++) {	/* skip limbo */
		if (j == me_server_idx)
			continue;
		timer_reset(otherservers[j].zs_timer);
		otherservers[j].zs_timer = (timer) 0;
	}

	/* check off entries on new list which are on old list.
	   check off entries on old list which are on new list.
	 */

	/* count limbo as "OK" */
	num_ok = 1;
	ok_list_old[0] = 1;	/* limbo is OK */

	for (serv_addr = server_addrs, i = 0;
	     i < num_servers;
	     serv_addr++, i++)		/* for each new server */
		for (j = 1; j < nservers; j++) /* j = 1 since we skip limbo */
			if (otherservers[j].zs_addr.sin_addr.s_addr ==
			    serv_addr->s_addr) {
				/* if server is on both lists, mark */
				ok_list_new[i] = 1;
				ok_list_old[j] = 1;
				num_ok++;
				break;	/* for j loop */
			}

	/* remove any dead servers on old list not on new list. */
	if (num_ok < nservers) {
		new_num = 1;		/* limbo */
		/* count number of servers to keep */
		for (j = 1; j < nservers; j++)
			/* since we are never SERV_DEAD, the following
			   test prevents removing ourself from the list */
			if (ok_list_old[j] ||
			    (otherservers[j].zs_state != SERV_DEAD)) {
				syslog(LOG_INFO, "keeping server %s",
				       inet_ntoa(otherservers[j].zs_addr.sin_addr));
				new_num++;
			}
		if (new_num < nservers) {
			servers = (ZServerDesc_t *) xmalloc(new_num * sizeof(ZServerDesc_t));
			if (!servers) {
				syslog(LOG_CRIT, "server_reset server malloc");
				abort();
			}
			i = 1;
			servers[0] = otherservers[0]; /* copy limbo */

			/* copy the kept servers */
			for (j = 1; j < nservers; j++) { /* skip limbo */
				if (ok_list_old[j] ||
				    otherservers[j].zs_state != SERV_DEAD) {
					servers[i] = otherservers[j];
					srv_nack_move(j,i);
					i++;
				} else {
					syslog(LOG_INFO, "flushing server %s",
					       inet_ntoa(otherservers[j].zs_addr.sin_addr));
					server_flush(&otherservers[j]);
				}

			}
			xfree(otherservers);
			otherservers = servers;
			nservers = new_num;
		}
	}
	/* add any new servers on new list not on old list. */
	new_num = 0;
	for (i = 0; i < num_servers; i++)
		if (!ok_list_new[i])
			new_num++;
	/* new_num is number of extras. */
	nservers += new_num;
	otherservers = (ZServerDesc_t *)realloc((caddr_t) otherservers, (unsigned) (nservers * sizeof(ZServerDesc_t)));
	if (!otherservers) {
		syslog(LOG_CRIT, "server_reset realloc");
		abort();
	}

	me_server_idx = 0;
	for (j = 1; j < nservers - new_num; j++)
		if (otherservers[j].zs_addr.sin_addr.s_addr ==
		    my_addr.s_addr) {
			me_server_idx = j;
			break;
		}
	if (!me_server_idx) {
		syslog(LOG_CRIT, "can't find myself");
		abort();
	}
			
	/* fill in otherservers with the new servers */
	for (i = 0; i < num_servers; i++)
		if (!ok_list_new[i]) {
			setup_server(&otherservers[nservers - (new_num--)],
				     &server_addrs[i]);
			syslog(LOG_INFO, "adding server %s",
			       inet_ntoa(server_addrs[i]));
		}
	xfree(server_addrs);
	/* reset timers, to go off now.
	   We can't get a time-left indication (bleagh!)
	   so we expire them all now.  This will generally
	   be non-destructive.  We assume that when this code is
	   entered via a SIGHUP trigger that a system wizard
	   is watching the goings-on to make sure things straighten
	   themselves out.
	   */
	for (i = 1; i < nservers; i++)	/* skip limbo */
		if (i != me_server_idx && !otherservers[i].zs_timer) {
			otherservers[i].zs_timer =
				timer_set_rel(0L, server_timo,
					      (caddr_t) &otherservers[i]);
			zdbug((LOG_DEBUG, "reset timer for %s",
			       inet_ntoa(otherservers[i].zs_addr.sin_addr)));
		}
	zdbug((LOG_DEBUG, "server_reset: %d servers now", nservers));
	return;
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
Code_t
server_dispatch(notice, auth, who)
ZNotice_t *notice;
int auth;
struct sockaddr_in *who;
{
	ZServerDesc_t *server;
	struct sockaddr_in newwho;
	Code_t status;

	zdbug((LOG_DEBUG, "server_dispatch"));

	if (notice->z_kind == SERVACK) {
		srv_nack_cancel(notice, who);
		srv_responded(who);
		return(ZERR_NONE);
	}
	/* set up a who for the real origin */
	bzero((caddr_t) &newwho, sizeof(newwho));
	newwho.sin_family = AF_INET;
	newwho.sin_addr.s_addr = notice->z_sender_addr.s_addr;
	newwho.sin_port = notice->z_port;

	server = server_which_server(who);

	/* we can dispatch to routines safely here, since they will
	   return ZSRV_REQUEUE if appropriate.  We bounce this back
	   to the caller, and the caller will re-queue the message
	   for us to process later. */

	if (class_is_admin(notice)) {
		/* admins don't get acked, else we get a packet loop */
		/* will return  requeue if bdump request and dumping */
		return(admin_dispatch(notice, auth, who, server));
	} else if (class_is_control(notice))
		status = control_dispatch(notice, auth, &newwho, server);
	else if (class_is_ulogin(notice))
		status = ulogin_dispatch(notice, auth, &newwho, server);
	else if (class_is_ulocate(notice))
		status = ulocate_dispatch(notice, auth, &newwho, server);
	else {
		/* shouldn't come from another server */
		syslog(LOG_WARNING, "srv_disp: pkt cls %s",notice->z_class);
		status = ZERR_NONE;	/* XXX */
	}
	if (status != ZSRV_REQUEUE)
		ack(notice, who);	/* acknowledge it if processed */
	return(status);
}

#ifdef notdef
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
	int omask = sigblock(sigmask(SIGFPE)); /* don't do ascii dumps */

	if (who->sin_port != sock_sin.sin_port) {
		zdbug((LOG_DEBUG, "srv_register wrong port %d",
		       ntohs(who->sin_port)));
		(void) sigsetmask(omask);
		return(1);
	}
	/* Not yet... talk to ken about authenticators */
#ifdef notdef
	if (!auth) {
		zdbug((LOG_DEBUG, "srv_register unauth"));
		(void) sigsetmask(omask);
		return(1);
	}
#endif notdef
	/* OK, go ahead and set him up. */
	temp = (ZServerDesc_t *)malloc((unsigned) ((nservers + 1) * sizeof(ZServerDesc_t)));
	if (!temp) {
		syslog(LOG_CRIT, "srv_reg malloc");
		(void) sigsetmask(omask);
		return(1);
	}
	bcopy((caddr_t) otherservers, (caddr_t) temp, nservers * sizeof(ZServerDesc_t));
	xfree(otherservers);
	otherservers = temp;
	/* don't reschedule limbo's timer, so start i=1 */
	for (i = 1; i < nservers; i++) {
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
	otherservers[nservers].zs_update_queue = NULLZSPT;
	otherservers[nservers].zs_dumping = 0;

	nservers++;
	zdbug((LOG_DEBUG, "srv %s is %s",
	       inet_ntoa(otherservers[nservers].zs_addr.sin_addr),
	       srv_states[(int) otherservers[nservers].zs_state]));
	(void) sigsetmask(omask);
	return(0);
}
#endif notdef

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
	pnotice->z_default_format = "";
	pnotice->z_num_other_fields = 0;

	/* XXX */
	auth = 0;

	/* don't tell limbo to flush, start at 1*/
	for (i = 1; i < nservers; i++) {
		if (i == me_server_idx)	/* don't xmit to myself */
			continue;
		if (otherservers[i].zs_state == SERV_DEAD)
			continue;

		if ((retval = ZFormatNoticeList(pnotice, lyst, 2, &pack, &packlen, auth ? ZAUTH : ZNOAUTH)) != ZERR_NONE) {
			syslog(LOG_WARNING, "kill_clt format: %s",
			       error_message(retval));
			return;
		}
		server_forw_reliable(&otherservers[i], pack, packlen, pnotice);
	}
}

/*
 * A client has died.  remove it
 */

static Code_t
kill_clt(notice)
ZNotice_t *notice;
{
	struct sockaddr_in who;
	ZHostList_t *host;
	ZClient_t *client;

	zdbug((LOG_DEBUG, "kill_clt"));
	if (extract_addr(notice, &who) != ZERR_NONE)
		return(ZERR_NONE);	/* XXX */
	if (!(host = hostm_find_host(&who.sin_addr))) {
		syslog(LOG_WARNING, "no host kill_clt");
		return(ZERR_NONE);	/* XXX */
	}
	if (host->zh_locked)
		return(ZSRV_REQUEUE);
	if (!(client = client_which_client(&who, notice))) {
		syslog(LOG_WARNING, "no clt kill_clt");
		return(ZERR_NONE);	/* XXX */
	}
	/* remove the locations, too */
	if (zdebug)
		syslog(LOG_DEBUG, "kill_clt clt_dereg");
	client_deregister(client, host, 1);
	return(ZERR_NONE);
}

/*
 * Another server asked us to initiate recovery protocol with the hostmanager
 */
static Code_t
recover_clt(notice, server)
register ZNotice_t *notice;
ZServerDesc_t *server;
{
	struct sockaddr_in who;
	ZClient_t *client;
	ZHostList_t *host;
	Code_t status;

	if ((status = extract_addr(notice, &who)) != ZERR_NONE)
		return(status);
	if (!(host = hostm_find_host(&who.sin_addr))) {
		syslog(LOG_WARNING, "recover_clt h not found, from %s",
		       inet_ntoa(server->zs_addr.sin_addr));
		syslog(LOG_WARNING, "%s", inet_ntoa(who.sin_addr));
		return(ZERR_NONE);	/* XXX */
	}
	if (host->zh_locked)
		return(ZSRV_REQUEUE);
	if (!(client = client_which_client(&who, notice))) {
		syslog(LOG_WARNING, "recover_clt not found, from %s",
		       inet_ntoa(server->zs_addr.sin_addr));
		syslog(LOG_WARNING, "%s/%d",inet_ntoa(who.sin_addr),
		       ntohs(who.sin_port));
		return(ZERR_NONE);	/* XXX */
	}
	hostm_losing(client, host);
	return(ZERR_NONE);
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
static Code_t
admin_dispatch(notice, auth, who, server)
ZNotice_t *notice;
int auth;
struct sockaddr_in *who;
ZServerDesc_t *server;
{
	register char *opcode = notice->z_opcode;
	Code_t status = ZERR_NONE;

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
#ifdef CONCURRENT
		if (bdumping)
			return(ZSRV_REQUEUE);
#endif CONCURRENT
		bdump_get(notice, auth, who, server);
	} else if (!strcmp(opcode, ADMIN_LOST_CLT)) {
		status = recover_clt(notice, server);
	} else if (!strcmp(opcode, ADMIN_KILL_CLT)) {
		status = kill_clt(notice);
		if (status == ZERR_NONE)
			ack(notice, who);
	} else
		syslog(LOG_WARNING, "ADMIN unknown opcode %s",opcode);
	return(status);
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
	srv_nack_release(server);
}

/*
 * Handle an ADMIN message from some random client.
 * For now, assume it's a registration-type message from some other
 * previously unknown server
 */

/*ARGSUSED*/
Code_t
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
		return(ZERR_NONE);
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
#else
	syslog(LOG_INFO, "srv_adisp: server attempt from %s",
	       inet_ntoa(who->sin_addr));
#endif /* notdef */
	return(ZERR_NONE);
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
		(void) sprintf(buf, "%s/%s%s",
			       inet_ntoa(otherservers[i].zs_addr.sin_addr),
			       srv_states[(int) otherservers[i].zs_state],
			       otherservers[i].zs_dumping ? " (DUMPING)" : "");
		responses[num_resp++] = strsave(buf);
	}

	send_msg_list(who, ADMIN_STATUS, responses, num_resp, 0);
	for (i = 0; i < num_resp; i++)
		xfree(responses[i]);
	xfree(responses);
	return;
}
#ifdef HESIOD
/*
 * get a list of server addresses, from Hesiod.  Return a pointer to an
 * array of allocated storage.  This storage is freed by the caller.
 */
#else
/*
 * get a list of server addresses, from a file.  Return a pointer to an
 * array of allocated storage.  This storage is freed by the caller.
 */
#endif HESIOD

static struct in_addr *
get_server_addrs(number)
int *number;				/* RETURN */
{
	register int i;
	char **server_hosts;
	register char **cpp;
	struct in_addr *addrs;
	register struct in_addr *addr;
	register struct hostent *hp;
#ifdef HESIOD
	char **hes_resolve();

	/* get the names from Hesiod */
	if (!(server_hosts = hes_resolve("zephyr","sloc")))
		return((struct in_addr *)NULL);
#else
	if (!(server_hosts = get_server_list(SERVER_LIST_FILE)))
		return((struct in_addr *)NULL);

#endif HESIOD
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
#ifndef HESIOD
	free_server_list(server_hosts);
#endif HESIOD
	return(addrs);
}

#ifndef HESIOD
#include <sys/param.h>

static int nhosts = 0;

/*
 * read "file" to get a list of names of hosts to peer with.
 * The file should contain a list of host names, one per line.
 */

static char **
get_server_list(file)
char *file;
{
	FILE *fp;
	char buf[MAXHOSTNAMELEN];
	char **ret_list;
	int nused = 0;
	char *newline;

	if (!(fp = fopen(file, "r")))
		return((char **)0);

	/* start with 16, realloc if necessary */
	nhosts = 16;
	ret_list = (char **)xmalloc(nhosts * sizeof(char *));

	while (fgets(buf, MAXHOSTNAMELEN, fp)) {
		/* nuke the newline, being careful not to overrun
		   the buffer searching for it with strlen() */
		buf[MAXHOSTNAMELEN - 1] = '\0';
		if (newline = index(buf, '\n'))
			*newline = '\0';

		if (nused >= nhosts) {
			/* get more pointer space if necessary */
			ret_list = (char **)realloc(ret_list,
						    (unsigned) nhosts * 2);
			nhosts = nhosts * 2;
		}
		ret_list[nused++] = strsave(buf);
	}
	(void) fclose(fp);
	return(ret_list);
}

/* 
 * free storage allocated by get_server_list
 */
static void
free_server_list(list)
char **list;
{
	register int i;

	if (!nhosts)			/* nothing allocated */
		return;
	for (i = 0; i < nhosts; i++)
		xfree(list[i]);
	xfree(list);
	return;
}
#endif !HESIOD

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

	server->zs_update_queue = NULLZSPT;
	server->zs_dumping = 0;

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

	zdbug((LOG_DEBUG, "hello from %s", inet_ntoa(who->sin_addr)));

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

	zdbug((LOG_DEBUG, "srv_responded %s", inet_ntoa(who->sin_addr)));

	if (!which) {
		syslog(LOG_ERR, "hello input from non-server?!");
		return;
	}

	switch (which->zs_state) {
	case SERV_DEAD:
		/* he responded, we thought he was dead. mark as starting
		   and negotiate */
		which->zs_state = SERV_STARTING;
		which->zs_timeout = timo_tardy;
		timer_reset(which->zs_timer);
		which->zs_timer = timer_set_rel(0L, server_timo,
						(caddr_t) which);

	case SERV_STARTING:
		/* here we negotiate and set up a braindump */
		if (bdump_socket < 0) {
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
	char *pack;
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
	pnotice->z_default_format = "";
	pnotice->z_message = (caddr_t) NULL;
	pnotice->z_message_len = 0;
	pnotice->z_num_other_fields = 0;

	/* XXX for now, we don't do authentication */
	auth = 0;

	if ((retval = ZFormatNotice(pnotice, &pack, &packlen,
				    auth ? ZAUTH : ZNOAUTH)) != ZERR_NONE) {
		syslog(LOG_WARNING, "snd_msg format: %s", error_message(retval));
		return;
	}
	if ((retval = ZSetDestAddr(who)) != ZERR_NONE) {
		syslog(LOG_WARNING, "snd_msg set addr: %s",
		       error_message(retval));
		xfree(pack);		/* free allocated storage */
		return;
	}
	/* don't wait for ack */
	if ((retval = ZSendPacket(pack, packlen, 0)) != ZERR_NONE) {
		syslog(LOG_WARNING, "snd_msg xmit: %s", error_message(retval));
		xfree(pack);		/* free allocated storage */
		return;
	}
	xfree(pack);			/* free allocated storage */
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
	char *pack;
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
	pnotice->z_default_format = "";
	pnotice->z_message = (caddr_t) NULL;
	pnotice->z_message_len = 0;
	pnotice->z_num_other_fields = 0;

	/* XXX for now, we don't do authentication */
	auth = 0;

	if ((retval = ZFormatNoticeList(pnotice, lyst, num, &pack, &packlen, auth ? ZAUTH : ZNOAUTH)) != ZERR_NONE) {
		syslog(LOG_WARNING, "snd_msg_lst format: %s", error_message(retval));
		return;
	}
	if ((retval = ZSetDestAddr(who)) != ZERR_NONE) {
		syslog(LOG_WARNING, "snd_msg_lst set addr: %s",
		       error_message(retval));
		xfree(pack);		/* free allocated storage */
		return;
	}
	if ((retval = ZSendPacket(pack, packlen, 0)) != ZERR_NONE) {
		syslog(LOG_WARNING, "snd_msg_lst xmit: %s", error_message(retval));
		xfree(pack);		/* free allocated storage */
		return;
	}
	xfree(pack);			/* free allocated storage */
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


	zdbug((LOG_DEBUG, "srv_forw"));
	/* don't send to limbo */
	for (i = 1; i < nservers; i++) {
		if (i == me_server_idx)	/* don't xmit to myself */
			continue;
		if (otherservers[i].zs_state == SERV_DEAD &&
		    otherservers[i].zs_dumping == 0)
			/* if we are dumping to him, we want to
			   queue it, even if he's dead */
			continue;

		if (!(pack = xmalloc(sizeof(ZPacket_t)))) {
			syslog(LOG_CRIT, "srv_fwd malloc");
			abort();
		}
		if ((retval = ZFormatSmallRawNotice(notice, pack, &packlen)) != ZERR_NONE) {
			syslog(LOG_WARNING, "srv_fwd format: %s",
			       error_message(retval));
			continue;
		}
		if (otherservers[i].zs_dumping) {
			server_queue(&(otherservers[i]), packlen, pack,
				     auth, who);
			continue;
		}
		server_forw_reliable(&otherservers[i], pack, packlen, notice);
	}
	return;
}

static void
server_forw_reliable(server, pack, packlen, notice)	
ZServerDesc_t *server;
caddr_t pack;
int packlen;
ZNotice_t *notice;
{
	Code_t retval;
	register ZNotAcked_t *nacked;

	if ((retval = ZSetDestAddr(&server->zs_addr)) != ZERR_NONE) {
		syslog(LOG_WARNING, "srv_fwd_rel set addr: %s",
		       error_message(retval));
		xfree(pack);
		return;
	}
	if ((retval = ZSendPacket(pack, packlen, 0)) != ZERR_NONE) {
		syslog(LOG_WARNING, "srv_fwd xmit: %s", error_message(retval));
		xfree(pack);
		return;
	}			
	/* now we've sent it, mark it as not ack'ed */
		
	if (!(nacked = (ZNotAcked_t *)xmalloc(sizeof(ZNotAcked_t)))) {
		/* no space: just punt */
		syslog(LOG_ERR, "srv_forw_rel nack malloc");
		xfree(pack);
		return;
	}

	nacked->na_rexmits = 0;
	nacked->na_packet = pack;
	nacked->na_srv_idx = server - otherservers;
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
	return;
}

#ifdef CONCURRENT
/*
 * send the queued message for the server.
 */

void
server_send_queue(server)
ZServerDesc_t *server;
{
	register ZSrvPending_t *pending;
	ZNotice_t notice;
	Code_t status;

	while(server->zs_update_queue) {
		pending = server_dequeue(server);
		if (status = ZParseNotice(pending->pend_packet,
					  pending->pend_len,
					  &notice)) {
			syslog(LOG_ERR,
			       "ssq bad notice parse (%s): %s",
			       inet_ntoa(pending->pend_who.sin_addr),
			       error_message(status));
		} else {
			server_forw_reliable(server, pending->pend_packet,
					     pending->pend_len, &notice);
			xfree(pending);
			/* ACK handling routines will free the packet */
		}
	}
}
#endif CONCURRENT

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
				  nackpacket->na_packsz, 0)) != ZERR_NONE)
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
	/* XXX release any private queue for this server */

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

/*
 * Clean up the not-yet-acked queue and release anything destined
 * to the server.
 */

static void
srv_nack_move(from, to)
register int from, to;
{
	/* XXX release any private queue for this server */

	register ZNotAcked_t *nacked;

	/* search the not-yet-acked list for anything destined to 'from', and
	   change the index to 'to'. */
	for (nacked = nacklist->q_forw;
	     nacked != nacklist;)
		if (nacked->na_srv_idx == from)
			nacked->na_srv_idx = to;
	return;
}

/*
 * Queue this notice to be transmitted to the server when it is ready.
 */
static void
server_queue(server, len, pack, auth, who)
ZServerDesc_t *server;
int len;
caddr_t pack;
int auth;
struct sockaddr_in *who;
{
	register ZSrvPending_t *pending;

	if (!server->zs_update_queue) {
		if (!(pending =
		      (ZSrvPending_t *)xmalloc(sizeof(ZSrvPending_t)))) {
			syslog(LOG_CRIT, "zs_update_queue head malloc");
			abort();
		}			
		pending->q_forw = pending->q_back = pending;
		server->zs_update_queue = pending;
	}
	if (!(pending = (ZSrvPending_t *)xmalloc(sizeof(ZSrvPending_t)))) {
		syslog(LOG_CRIT, "zs_update_queue malloc");
		abort();
	}
	pending->pend_packet = pack;
	pending->pend_len = len;
	pending->pend_auth = auth;
	pending->pend_who = *who;

	/* put it on the end of the list */
	xinsque(pending, server->zs_update_queue->q_back);
	return;
}

/*
 * Pull a notice off the hold queue.
 */

ZSrvPending_t *
server_dequeue(server)
register ZServerDesc_t *server;
{
	ZSrvPending_t *pending;
	
	if (!server->zs_update_queue)
		return(NULLZSPT);
	pending = server->zs_update_queue->q_forw;
	/* pull it off */
	xremque(pending);
	if (server->zs_update_queue->q_forw == server->zs_update_queue) {
		/* empty queue now */
		xfree(server->zs_update_queue);
		server->zs_update_queue = NULLZSPT;
	}
	return(pending);
}

/*
 * free storage used by a pending queue entry.
 */

void
server_pending_free(pending)
register ZSrvPending_t *pending;
{
	xfree(pending->pend_packet);
	xfree(pending);
	return;
}

#ifdef CONCURRENT
/*
 * Queue something to be handled later by this server.
 */

void
server_self_queue(notice, auth, who)
ZNotice_t *notice;
int auth;
struct sockaddr_in *who;
{
	caddr_t pack;
	int packlen;
	Code_t retval;

	if ((retval = ZFormatRawNotice(notice, &pack, &packlen))
	    != ZERR_NONE) {
		syslog(LOG_CRIT, "srv_self_queue format: %s",
		       error_message(retval));
		abort();
	}
	server_queue(me_server, packlen, pack, auth, who);
	return;
}
#endif CONCURRENT

/*
 * dump info about servers onto the fp.
 * assumed to be called with SIGFPE blocked
 * (true if called from signal handler)
 */
void
server_dump_servers(fp)
FILE *fp;
{
	register int i;

	for (i = 0; i < nservers ; i++) {
		(void) fprintf(fp, "%d:%s/%s%s\n",
			       i,
			       inet_ntoa(otherservers[i].zs_addr.sin_addr),
			       srv_states[(int) otherservers[i].zs_state],
			       otherservers[i].zs_dumping ? " (DUMPING)" : "");
	}

	return;
}
