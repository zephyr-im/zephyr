/* This file is part of the Project Athena Zephyr Notification System.
 * It contains functions for communication with other servers.
 *
 *	Created by:	John T. Kohl
 *
 *	$Source$
 *	$Author$
 *
 *	Copyright (c) 1987, 1991 by the Massachusetts Institute of Technology.
 *	For copying and distribution information, see the file
 *	"mit-copyright.h". 
 */

#include <zephyr/mit-copyright.h>

#ifndef lint
#ifndef SABER
static char rcsid_server_c[] = "$Id$";
#endif
#endif

#include "zserver.h"
#include <sys/socket.h>			/* for AF_INET */
#include <netdb.h>			/* for gethostbyname */
#include <sys/param.h>			/* for BSD */

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

#ifdef __STDC__
# define        P(s) s
#else
# define P(s) ()
#endif

static void
    server_flush P((ZServerDesc_t *)),
    hello_respond P((struct sockaddr_in *, int, int)),
    srv_responded P((struct sockaddr_in *)),
    send_msg P((struct sockaddr_in *, char *, int)),
    send_msg_list P((struct sockaddr_in *, char *, char **, int, int)),
    srv_nack_cancel P((ZNotice_t *, struct sockaddr_in *)),
    srv_nack_release P((ZServerDesc_t *)),
    srv_nack_renumber  P((int *)),
    server_lost P((ZServerDesc_t *)),
    send_stats P((struct sockaddr_in *)),
    server_queue P((ZServerDesc_t *, int, caddr_t, int, struct sockaddr_in *));
#define STATIC /* should be static, but is friend elsewhere */
STATIC void
    server_hello P((ZServerDesc_t *, int)),
    setup_server P((ZServerDesc_t *, struct in_addr *)),
    srv_rexmit P((void *)),
    server_forw_reliable P((ZServerDesc_t *, caddr_t, int, ZNotice_t *));
static Code_t
    admin_dispatch P((ZNotice_t *, int, struct sockaddr_in *,
		      ZServerDesc_t *)),
    recover_clt P((ZNotice_t *, ZServerDesc_t *)),
    kill_clt P((ZNotice_t *, ZServerDesc_t *)),
    extract_addr  P((ZNotice_t *, struct sockaddr_in *));


#ifdef notdef
static Code_t server_register();
#endif

static struct in_addr *get_server_addrs P((int *number));
#ifndef HESIOD
static char **get_server_list P((char *file));
static void free_server_list P((char **list));
#endif

#undef P


ZNotAcked_t *srv_nacklist;		/* not acked list for server-server
					   packets */
ZServerDesc_t *otherservers;		/* points to an array of the known
					   servers */
int nservers;				/* number of other servers */
int me_server_idx;			/* # of my entry in the array */

#define	ADJUST		(1)		/* adjust timeout on hello input */
#define	DONT_ADJUST	(0)		/* don't adjust timeout */

/* parameters controlling the transitions of the FSM's--patchable with adb */
long timo_up = TIMO_UP;
long timo_tardy = TIMO_TARDY;
long timo_dead = TIMO_DEAD;

long srv_rexmit_secs = REXMIT_SECS;

/* counters to measure old protocol use */
#ifdef OLD_COMPAT
int old_compat_count_uloc = 0;
int old_compat_count_ulocate = 0;
int old_compat_count_subscr = 0;
#endif /* OLD_COMPAT */
#ifdef NEW_COMPAT
int new_compat_count_uloc = 0;
int new_compat_count_subscr = 0;
#endif /* NEW_COMPAT */

#ifdef DEBUG
int zalone;
#endif /* DEBUG */
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
#endif /* DEBUG */
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
#if 0
			zdbug((LOG_DEBUG,"found myself"));
#endif
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
			otherservers[i].zs_timer =
			  timer_set_rel(0L, server_timo, (void *)
					&otherservers[i]);
		}
		me_server_idx = nservers - 1;
	}
	if (!(srv_nacklist = (ZNotAcked_t *) xmalloc(sizeof(ZNotAcked_t)))) {
		/* unrecoverable */
		syslog(LOG_CRIT, "srv_nacklist malloc");
		abort();
	}
	(void) memset((caddr_t) srv_nacklist, 0, sizeof(ZNotAcked_t));
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

#if 0
	zdbug((LOG_DEBUG, "server_reset"));
#endif
#ifdef DEBUG
	if (zalone) {
		syslog(LOG_INFO, "server_reset while alone, punt");
		return;
	}
#endif /* DEBUG */

	/* Find out what servers are supposed to be known. */
	if (!(server_addrs = get_server_addrs(&num_servers))) {
		syslog(LOG_ERR, "server_reset no servers. nothing done.");
		return;
	}
	ok_list_new = (int *) xmalloc (num_servers * sizeof (int));
	if (ok_list_new == (int *) 0) {
		syslog(LOG_ERR, "server_reset no mem new");
		return;
	}
	ok_list_old = (int *) xmalloc (nservers * sizeof (int));
	if (ok_list_old == (int *) 0) {
		syslog(LOG_ERR, "server_reset no mem old");
		xfree(ok_list_new);
		return;
	}

	(void) memset((char *)ok_list_old, 0, nservers * sizeof(int));
	(void) memset((char *)ok_list_new, 0, num_servers * sizeof(int));
	
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
		int *srv;
		new_num = 1;		/* limbo */
		/* count number of servers to keep */
		for (j = 1; j < nservers; j++)
			/* since we are never SERV_DEAD, the following
			   test prevents removing ourself from the list */
			if (ok_list_old[j] ||
			    (otherservers[j].zs_state != SERV_DEAD)) {
				syslog(LOG_INFO, "keeping server %s",
				       otherservers[j].addr);
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

			srv = (int*) xmalloc (nservers * sizeof (int));
			(void) memset (srv, 0, nservers * sizeof (int));
			
			/* copy the kept servers */
			for (j = 1; j < nservers; j++) { /* skip limbo */
				if (ok_list_old[j] ||
				    otherservers[j].zs_state != SERV_DEAD) {
					servers[i] = otherservers[j];
					srv[j] = i;
					i++;
				} else {
					syslog(LOG_INFO, "flushing server %s",
					       otherservers[j].addr);
					server_flush(&otherservers[j]);
					srv[j] = -1;
				}

			}
			srv_nack_renumber (srv);
			hostm_renumber_servers (srv);

			xfree(srv);
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
					      (void *) &otherservers[i]);
#if 0
			zdbug((LOG_DEBUG, "reset timer for %s",
			       otherservers[i].addr));
#endif
		}
	xfree(ok_list_old);
	xfree(ok_list_new);

#if 0
	zdbug((LOG_DEBUG, "server_reset: %d servers now", nservers));
#endif
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
#ifdef __STDC__
server_timo(void* arg)
#else
server_timo(arg)
     void* arg;
#endif
{
	ZServerDesc_t *which = (ZServerDesc_t *) arg;
	int auth = 0;

#if 0
	zdbug((LOG_DEBUG,"srv_timo: %s", which->addr));
#endif
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
#if 0
	zdbug((LOG_DEBUG, "srv %s is %s", which->addr,
	       srv_states[(int) which->zs_state]));
#endif
	server_hello(which, auth);
	/* reschedule the timer */
	which->zs_timer = timer_set_rel(which->zs_timeout, server_timo,
					(void *) which);
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
	ZSTRING *notice_class;


#if 0
	zdbug((LOG_DEBUG, "server_dispatch"));
#endif

	if (notice->z_kind == SERVACK) {
		srv_nack_cancel(notice, who);
		srv_responded(who);
		return(ZERR_NONE);
	}
	/* set up a who for the real origin */
	(void) memset((caddr_t) &newwho, 0, sizeof(newwho));
	newwho.sin_family = AF_INET;
	newwho.sin_addr.s_addr = notice->z_sender_addr.s_addr;
	newwho.sin_port = notice->z_port;

	server = server_which_server(who);

	/* we can dispatch to routines safely here, since they will
	   return ZSRV_REQUEUE if appropriate.  We bounce this back
	   to the caller, and the caller will re-queue the message
	   for us to process later. */

	notice_class = make_zstring(notice->z_class,1);

	if (class_is_admin(notice_class)) {
		/* admins don't get acked, else we get a packet loop */
		/* will return  requeue if bdump request and dumping */
		i_s_admins.val++;
		return(admin_dispatch(notice, auth, who, server));
	} else if (class_is_control(notice_class)) {
		status = control_dispatch(notice, auth, &newwho, server);
		i_s_ctls.val++;
	}
	else if (class_is_ulogin(notice_class)) {
		status = ulogin_dispatch(notice, auth, &newwho, server);
		i_s_logins.val++;
	}
	else if (class_is_ulocate(notice_class)) {
		status = ulocate_dispatch(notice, auth, &newwho, server);
		i_s_locates.val++;
	}
	else {
		/* shouldn't come from another server */
		syslog(LOG_WARNING, "srv_disp: pkt cls %s",
		       notice->z_class);
		status = ZERR_NONE;	/* XXX */
	}
	if (status != ZSRV_REQUEUE)
		ack(notice, who); /* acknowledge it if processed */
	free_zstring(notice_class);
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

	if (who->sin_port != sock_sin.sin_port) {
#if 0
		zdbug((LOG_DEBUG, "srv_register wrong port %d",
		       ntohs(who->sin_port)));
#endif
		return 1;
	}
	/* Not yet... talk to ken about authenticators */
#ifdef notdef
	if (!auth) {
#if 0
		zdbug((LOG_DEBUG, "srv_register unauth"));
#endif
		return 1;
	}
#endif /* notdef */
	/* OK, go ahead and set him up. */
	temp = (ZServerDesc_t *)xmalloc((unsigned) ((nservers + 1) * sizeof(ZServerDesc_t)));
	if (!temp) {
		syslog(LOG_CRIT, "srv_reg malloc");
		return 1;
	}

	START_CRITICAL_CODE;
	
	(void) memcpy((caddr_t) temp, (caddr_t) otherservers,
		       nservers * sizeof(ZServerDesc_t));
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
#if 0
	zdbug((LOG_DEBUG, "srv %s is %s", otherservers[nservers].addr,
	       srv_states[(int) otherservers[nservers].zs_state]));
#endif

	END_CRITICAL_CODE;

	return 0;
}
#endif

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

#if 0
	zdbug((LOG_DEBUG,"server recover"));
#endif
	if ((server = hostm_find_server(&client->zct_sin.sin_addr)) !=
	    NULLZSDT) {
		if (server == limbo_server) {
#if 0
			zdbug((LOG_DEBUG, "no server to recover"));
#endif
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

	lyst[0] = inet_ntoa(client->zct_sin.sin_addr),
	(void) sprintf(buf, "%d", ntohs(client->zct_sin.sin_port));
	lyst[1] = buf;

#if 0
	zdbug((LOG_DEBUG, "server kill clt %s/%s", lyst[0], lyst[1]));
#endif

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
kill_clt(notice, server)
     ZNotice_t *notice;
     ZServerDesc_t *server;
{
	struct sockaddr_in who;
	ZHostList_t *host;
	ZClient_t *client;

#if 0
	zdbug((LOG_DEBUG, "kill_clt"));
#endif
	if (extract_addr(notice, &who) != ZERR_NONE)
		return(ZERR_NONE);	/* XXX */
	if (!(host = hostm_find_host(&who.sin_addr))) {
		syslog(LOG_NOTICE, "kill_clt: no such host (%s, from %s)",
		       inet_ntoa (who.sin_addr), server->addr);
		return(ZERR_NONE);	/* XXX */
	}
	if (host->zh_locked)
		return(ZSRV_REQUEUE);
	if (!(client = client_which_client(&who, notice))) {
		syslog(LOG_NOTICE, "kill_clt: no such client (%s/%d) from %s",
		       inet_ntoa (who.sin_addr), ntohs (who.sin_port),
		       server->addr);
		return(ZERR_NONE);	/* XXX */
	}
#if 0
	if (zdebug || 1)
		syslog(LOG_DEBUG, "kill_clt clt_dereg %s/%d from %s",
		       inet_ntoa (who.sin_addr), ntohs (who.sin_port),
		       server->addr);
#endif

	hostm_lose_ignore(client);
	/* remove the locations, too */
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
		syslog(LOG_NOTICE,
		       "recover_clt: host not found (%s, from %s)",
		       inet_ntoa (who.sin_addr), server->addr);
		return(ZERR_NONE);	/* XXX */
	}
	if (host->zh_locked)
		return(ZSRV_REQUEUE);
	if (!(client = client_which_client(&who, notice))) {
		syslog(LOG_NOTICE,
		       "recover_clt: client not found (%s/%d, from %s)",
		       inet_ntoa (who.sin_addr), ntohs (who.sin_port),
		       server->addr);
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
#if 0
	zdbug((LOG_DEBUG,"ext %s/%d", inet_ntoa(who->sin_addr),
	       ntohs(who->sin_port)));
#endif
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

#if 0
	if (zdebug)
	    syslog (LOG_DEBUG, "server_flush %s", which->addr);
#endif
	if (!which->zs_hosts) /* no data to flush */
		return;

	for (hst = which->zs_hosts->q_forw;
	     hst != which->zs_hosts;
	     hst = which->zs_hosts->q_forw) {
		/* for each host, flush all data */
#if 0
		if (zdebug)
		    syslog (LOG_DEBUG, "... host %s",
			    inet_ntoa (hst->zh_addr.sin_addr));
#endif
		hostm_flush(hst, which);
	}
	srv_nack_release(which);
}

/*
 * send a hello to which, updating the count of hello's sent
 * Authenticate if auth is set.
 */

STATIC void
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

#if 0
	zdbug((LOG_DEBUG, "ADMIN received"));
#endif

	if (!strcmp(opcode, ADMIN_HELLO)) {
		hello_respond(who, ADJUST, auth);
	} else if (!strcmp(opcode, ADMIN_IMHERE)) {
		srv_responded(who);
	} else if (!strcmp(opcode, ADMIN_SHUTDOWN)) {
#if 0
		zdbug((LOG_DEBUG, "server shutdown"));
#endif
		/* we need to transfer all of its hosts to limbo */
		if (server) {
			server_lost(server);
			server->zs_state = SERV_DEAD;
			server->zs_timeout = timo_dead;
			/* don't worry about the timer, it will
			   be set appropriately on the next send */
#if 0
			zdbug((LOG_DEBUG, "srv %s is %s", server->addr,
			       srv_states[(int) server->zs_state]));
#endif
		}
	} else if (!strcmp(opcode, ADMIN_BDUMP)) {
#ifdef CONCURRENT
#if 0		/* If another dump is in progress, it'll likely not
		   finish in time for us to catch the server's
		   bdump-waiting period.  So don't bother.  */
		if (bdumping)
			return(ZSRV_REQUEUE);
#else
		if (bdumping)
		    return ZERR_NONE;
#endif
#endif
		bdump_get(notice, auth, who, server);
	} else if (!strcmp(opcode, ADMIN_LOST_CLT)) {
		status = recover_clt(notice, server);
		if (status == ZERR_NONE)
			ack(notice, who);
	} else if (!strcmp(opcode, ADMIN_KILL_CLT)) {
		status = kill_clt(notice, server);
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

#if defined(OLD_COMPAT) || defined(NEW_COMPAT)
	int extrafields = 0;
#endif /* OLD_ or NEW_COMPAT */
#define	NUM_FIXED 3			/* 3 fixed fields, plus server info */
					/* well, not really...but for
					   backward compatibility, we gotta
					   do it this way. */
	vers = get_version();

	(void) sprintf(buf, "%d pkts", npackets);
	pkts = strsave(buf);
	(void) sprintf(buf, "%d seconds operational",NOW - uptime);
	upt = strsave(buf);

#ifdef OLD_COMPAT
	if (old_compat_count_uloc) extrafields++;
	if (old_compat_count_ulocate) extrafields++;
	if (old_compat_count_subscr) extrafields++;
#endif /* OLD_COMPAT */
#ifdef NEW_COMPAT
	if (new_compat_count_uloc) extrafields++;
	if (new_compat_count_subscr) extrafields++;
#endif /* NEW_COMPAT */
#if defined(OLD_COMPAT) || defined(NEW_COMPAT)
	responses = (char **) xmalloc((NUM_FIXED + nservers + extrafields) *
				      sizeof(char **));
#else
	responses = (char **) xmalloc ((NUM_FIXED + nservers) * 
				       sizeof(char **));
#endif /* OLD_ or NEW_COMPAT */
	responses[0] = vers;
	responses[1] = pkts;
	responses[2] = upt;

	num_resp = NUM_FIXED;
	/* start at 1 and ignore limbo */
	for (i = 1; i < nservers ; i++) {
		(void) sprintf(buf, "%s/%s%s", otherservers[i].addr,
			       srv_states[(int) otherservers[i].zs_state],
			       otherservers[i].zs_dumping ? " (DUMPING)" : "");
		responses[num_resp++] = strsave (buf);
	}
#ifdef OLD_COMPAT
	if (old_compat_count_uloc) {
	    (void) sprintf(buf, "%d old old location requests",
			   old_compat_count_uloc);
	    responses[num_resp++] = strsave (buf);
	}
	if (old_compat_count_ulocate) {
	    (void) sprintf(buf, "%d old old loc lookup requests",
			   old_compat_count_ulocate);
	    responses[num_resp++] = strsave (buf);
	}
	if (old_compat_count_subscr) {
	    (void) sprintf(buf, "%d old old subscr requests",
			   old_compat_count_subscr);
	    responses[num_resp++] = strsave (buf);
	}
#endif /* OLD_COMPAT */
#ifdef NEW_COMPAT
	if (new_compat_count_uloc) {
	    (void) sprintf(buf, "%d new old location requests",
			   new_compat_count_uloc);
	    responses[num_resp++] = strsave (buf);
	}
	if (new_compat_count_subscr) {
	    (void) sprintf(buf, "%d new old subscr requests",
			   new_compat_count_subscr);
	    responses[num_resp++] = strsave (buf);
	}
#endif /* NEW_COMPAT */

	send_msg_list(who, ADMIN_STATUS, responses, num_resp, 0);
	/* Start at one; don't try to free static version string */
	for (i = 1; i < num_resp; i++)
	  xfree(responses[i]);
	xfree(responses);
	return;
}

/*
 * Get a list of server addresses.
#ifdef HESIOD
 * This list is retrieved from Hesiod.
#else
 * This list is read from a file.
#endif
 * Return a pointer to an array of allocated storage.  This storage is
 * freed by the caller.
 */

static struct in_addr *
get_server_addrs(number)
     int *number; /* RETURN */
{
	register int i;
	char **server_hosts;
	register char **cpp;
	struct in_addr *addrs;
	register struct in_addr *addr;
	register struct hostent *hp;

#ifdef HESIOD
	/* get the names from Hesiod */
	if (!(server_hosts = hes_resolve("zephyr","sloc")))
		return((struct in_addr *)NULL);
#else
	if (!(server_hosts = get_server_list(SERVER_LIST_FILE)))
		return((struct in_addr *)NULL);
#endif
	/* count up */
	for (cpp = server_hosts, i = 0; *cpp; cpp++, i++);
	
	addrs = (struct in_addr *) xmalloc(i * sizeof(struct in_addr));

	/* Convert to in_addr's */
	for (cpp = server_hosts, addr = addrs, i = 0; *cpp; cpp++) {
		hp = gethostbyname(*cpp);
		if (hp) {
			(void) memcpy((caddr_t) addr, (caddr_t)hp->h_addr,
				       sizeof(struct in_addr));
			addr++, i++;
		} else
			syslog(LOG_WARNING, "hostname failed, %s",*cpp);
	}
	*number = i;
#ifndef HESIOD
	free_server_list(server_hosts);
#endif
	return(addrs);
}

#ifndef HESIOD

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

		if (nused+1 >= nhosts) {
			/* get more pointer space if necessary */
			/* +1 to leave room for null pointer */
			ret_list = (char **)realloc((char *)ret_list,
						    (unsigned) nhosts * 2);
			nhosts = nhosts * 2;
		}
		ret_list[nused++] = strsave (buf);
	}
	(void) fclose(fp);
	ret_list[nused] = (char *)0;
	return(ret_list);
}

/* 
 * free storage allocated by get_server_list
 */
static void
free_server_list(list)
     register char **list;
{
	char **orig_list = list;

	if (!nhosts)			/* nothing allocated */
		return;
	for (; *list; list++)
	    xfree(*list);
	xfree(orig_list);
	return;
}
#endif

/*
 * initialize the server structure for address addr, and set a timer
 * to go off immediately to send hello's to other servers.
 */

STATIC void
setup_server(server, addr)
     register ZServerDesc_t *server;
     struct in_addr *addr;
{
	register ZHostList_t *host;

	server->zs_state = SERV_DEAD;
	server->zs_timeout = timo_dead;
	server->zs_numsent = 0;
	server->zs_addr.sin_family = AF_INET;
	/* he listens to the same port we do */
	server->zs_addr.sin_port = sock_sin.sin_port;
	server->zs_addr.sin_addr = *addr;
	strcpy (server->addr, inet_ntoa (*addr));

	/* set up a timer for this server */
	server->zs_timer = timer_set_rel(0L, server_timo, (void *) server);
	host = (ZHostList_t *) xmalloc(sizeof(ZHostList_t));
	if (!host) {
		/* unrecoverable */
		syslog(LOG_CRIT, "zs_host alloc");
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

#if 0
	zdbug((LOG_DEBUG, "hello from %s", inet_ntoa(who->sin_addr)));
#endif

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
						(void *) which);
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

#if 0
	zdbug((LOG_DEBUG, "srv_responded %s", inet_ntoa(who->sin_addr)));
#endif

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
						(void *) which);

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
						(void *) which);
		break;
	}
#if 0
	zdbug((LOG_DEBUG, "srv %s is %s", which->addr,
	       srv_states[(int) which->zs_state]));
#endif
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
		syslog(LOG_WARNING, "snd_msg format: %s",
		       error_message(retval));
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
     char **lyst;
     int num;
     int auth;
{
	ZNotice_t notice;
	register ZNotice_t *pnotice; /* speed hack */
	char *pack;
	int packlen;
	Code_t retval;
	register ZNotAcked_t *nacked;

	pnotice = &notice;

	pnotice->z_kind = UNSAFE;

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

	retval = ZFormatNoticeList (pnotice, lyst, num, &pack, &packlen,
				    auth ? ZAUTH : ZNOAUTH);
	if (retval != ZERR_NONE) {
	    syslog(LOG_WARNING, "snd_msg_lst format: %s",
		   error_message(retval));
	    return;
	}
	if ((retval = ZSetDestAddr(who)) != ZERR_NONE) {
	    syslog(LOG_WARNING, "snd_msg_lst set addr: %s",
		   error_message(retval));
	    xfree(pack);	/* free allocated storage */
	    return;
	}
	if ((retval = ZSendPacket(pack, packlen, 0)) != ZERR_NONE) {
	    syslog(LOG_WARNING, "snd_msg_lst xmit: %s", error_message(retval));
	    xfree(pack);	/* free allocated storage */
	    return;
	}

	if (!(nacked = (ZNotAcked_t *)xmalloc(sizeof(ZNotAcked_t)))) {
		/* no space: just punt */
		syslog(LOG_WARNING, "xmit nack malloc");
		xfree(pack);
		return;
	}

	nacked->na_rexmits = 0;
	nacked->na_packet = pack;
	nacked->na_addr = *who;
	nacked->na_packsz = packlen;
	nacked->na_uid = pnotice->z_uid;
	nacked->q_forw = nacked->q_back = nacked;
	nacked->na_abstimo = NOW + abs_timo;

	/* set a timer to retransmit when done */
	nacked->na_timer = timer_set_rel(rexmit_secs,
					 rexmit,
					 (void *) nacked);
	/* chain in */
	xinsque(nacked, nacklist);
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

#if 0
	zdbug((LOG_DEBUG, "srv_forw"));
#endif
	/* don't send to limbo */
	for (i = 1; i < nservers; i++) {
		if (i == me_server_idx)	/* don't xmit to myself */
			continue;
		if (otherservers[i].zs_state == SERV_DEAD &&
		    otherservers[i].zs_dumping == 0)
			/* if we are dumping to him, we want to
			   queue it, even if he's dead */
			continue;

		if (!(pack = (caddr_t) xmalloc(sizeof(ZPacket_t)))) {
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

STATIC void
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
					 (void *) nacked);
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
		if ((status = ZParseNotice(pending->pend_packet,
					  pending->pend_len,
					  &notice)) != ZERR_NONE) {
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
#endif

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
#if 0
	zdbug((LOG_DEBUG, "srv_nack not found"));
#endif
	return;
}

/*
 * retransmit a message to another server
 */

STATIC void
#ifdef __STDC__
srv_rexmit(void *arg)
#else
srv_rexmit(arg)
     void *arg;
#endif
{
	ZNotAcked_t *nackpacket = (ZNotAcked_t *) arg;
	Code_t retval;
	/* retransmit the packet */
	
#if 0
	zdbug((LOG_DEBUG,"srv_rexmit to %s/%d",
	       otherservers[nackpacket->na_srv_idx].addr,
	       ntohs(otherservers[nackpacket->na_srv_idx].zs_addr.sin_port)));
#endif
	if (otherservers[nackpacket->na_srv_idx].zs_state == SERV_DEAD) {
#if 0
		zdbug((LOG_DEBUG, "cancelling send to dead server"));
#endif
		xremque(nackpacket);
		xfree(nackpacket->na_packet);
		srv_nack_release(&otherservers[nackpacket->na_srv_idx]);
		xfree(nackpacket);
		return;
	}
	retval = ZSetDestAddr(&otherservers[nackpacket->na_srv_idx].zs_addr);
	if (retval != ZERR_NONE) {
		syslog(LOG_WARNING, "srv_rexmit set addr: %s",
		       error_message(retval));
		goto requeue;

	}
	if ((retval = ZSendPacket(nackpacket->na_packet,
				  nackpacket->na_packsz, 0)) != ZERR_NONE)
		syslog(LOG_WARNING, "srv_rexmit xmit: %s",
		       error_message(retval));

requeue:
	/* reset the timer */
	nackpacket->na_timer = timer_set_rel(srv_rexmit_secs,
					     srv_rexmit,
					     (void *) nackpacket);
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
 * Adjust indices of not-yet-acked packets sent to other servers to
 * continue to refer to the correct server.
 */

static void
srv_nack_renumber (new_idx)
     register int* new_idx;
{
    /* XXX release any private queue for this server */

    register ZNotAcked_t *nacked;

    /* search the not-yet-acked list for anything destined to 'from', and
       change the index to 'to'. */
    for (nacked = nacklist->q_forw; nacked != nacklist;) {
	int idx = new_idx[nacked->na_srv_idx];
	if (idx < 0) {
	    syslog (LOG_ERR,
		    "srv_nack_renumber error: [%d]=%d",
		    nacked->na_srv_idx, idx);
	    idx = 0;
	}
	nacked->na_srv_idx = idx;
    }
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
     ZNotice_t* notice;
     int auth;
     struct sockaddr_in * who;
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
#endif

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
			       i, otherservers[i].addr,
			       srv_states[(int) otherservers[i].zs_state],
			       otherservers[i].zs_dumping ? " (DUMPING)" : "");
	}

	return;
}
