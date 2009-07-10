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
#include "zserver.h"
#include <sys/socket.h>

#ifndef lint
#ifndef SABER
static const char rcsid_server_c[] = "$Id$";
#endif
#endif

#define SRV_NACKTAB_HASHSIZE		1023
#define SRV_NACKTAB_HASHVAL(which, uid)	((unsigned int) \
					 ((which) ^ (uid).zuid_addr.s_addr ^ \
					  (uid).tv.tv_sec ^ (uid).tv.tv_usec) \
					   % SRV_NACKTAB_HASHSIZE)
/*
 * Server manager.  Deal with  traffic to and from other servers.
 *
 * void server_init()
 *
 * void server_shutdown()
 *
 * void server_timo(which)
 * 	Server *which;
 *
 * void server_dispatch(notice, auth, who)
 *	ZNotice_t *notice;
 * 	int auth;
 *	struct sockaddr_in *who;
 *
 * void server_recover(client)
 *	Client *client;
 *
 * void server_adispatch(notice, auth, who, server)
 *	ZNotice_t *notice;
 * 	int auth;
 *	struct sockaddr_in *who;
 *	Server *server;
 *
 * void server_forward(notice, auth, who)
 *	ZNotice_t *notice;
 *	int auth;
 *	struct sockaddr_in *who;
 *
 * Server *server_which_server(who)
 *	struct sockaddr_in *who;
 *
 * void server_kill_clt(client);
 *	Client *client;
 *
 * void server_dump_servers(fp);
 *	FILE *fp;
 *
 * void server_reset();
 */

static void server_flush __P((Server *));
static void hello_respond __P((struct sockaddr_in *, int, int));
static void srv_responded __P((struct sockaddr_in *));
static void send_msg __P((struct sockaddr_in *, char *, int));
static void send_msg_list __P((struct sockaddr_in *, char *, char **, int,
			       int));
static void srv_nack_cancel __P((ZNotice_t *, struct sockaddr_in *));
static void srv_nack_release __P((Server *));
static void srv_nack_renumber  __P((int *));
static void send_stats __P((struct sockaddr_in *));
static void server_queue __P((Server *, int, void *, int,
			      struct sockaddr_in *));
static void server_hello __P((Server *, int));
static void setup_server __P((Server *, struct in_addr *));
static void srv_rexmit __P((void *));
static void server_forw_reliable __P((Server *, caddr_t, int, ZNotice_t *));
static Code_t admin_dispatch __P((ZNotice_t *, int, struct sockaddr_in *,
				  Server *));
static Code_t kill_clt __P((ZNotice_t *, Server *));
static Code_t extract_addr __P((ZNotice_t *, struct sockaddr_in *));

#ifdef notdef
static Code_t server_register();
#endif

static struct in_addr *get_server_addrs __P((int *number));
#ifndef HAVE_HESIOD
static char **get_server_list __P((char *file));
static void free_server_list __P((char **list));
#endif

static Unacked *srv_nacktab[SRV_NACKTAB_HASHSIZE];
Server *otherservers;		/* points to an array of the known
				   servers */
int nservers;			/* number of other servers */
int me_server_idx;		/* # of my entry in the array */

#define	ADJUST		(1)	/* adjust timeout on hello input */
#define	DONT_ADJUST	(0)	/* don't adjust timeout */

/* parameters controlling the transitions of the FSM's--patchable with adb */
long timo_up = TIMO_UP;
long timo_tardy = TIMO_TARDY;
long timo_dead = TIMO_DEAD;

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
    int i;
    struct in_addr *serv_addr, *server_addrs, limbo_addr;

    /* we don't need to mask SIGFPE here since when we are called,
       the signal handler isn't set up yet. */

    /* talk to hesiod here, set nservers */
    server_addrs = get_server_addrs(&nservers);
    if (!server_addrs) {
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

    otherservers = (Server *) malloc(nservers * sizeof(Server));
    me_server_idx = -1;

    /* set up limbo */
    limbo_addr.s_addr = 0;
    setup_server(otherservers, &limbo_addr);
    timer_reset(otherservers[0].timer);
    otherservers[0].timer = NULL;
    otherservers[0].queue = NULL;
    otherservers[0].dumping = 0;

    for (serv_addr = server_addrs, i = 1; i < nservers; serv_addr++, i++) {
	setup_server(&otherservers[i], serv_addr);
	/* is this me? */
	if (serv_addr->s_addr == my_addr.s_addr) {
	    me_server_idx = i;
	    otherservers[i].state = SERV_UP;
	    timer_reset(otherservers[i].timer);
	    otherservers[i].timer = NULL;
	    otherservers[i].queue = NULL;
	    otherservers[i].dumping = 0;
#if 0
	    zdbug((LOG_DEBUG,"found myself"));
#endif
	}
    }

    /* free up the addresses */
    free(server_addrs);

    if (me_server_idx == -1) {
	syslog(LOG_WARNING, "I'm a renegade server!");
	otherservers = (Server *) realloc(otherservers,
					  ++nservers * sizeof(Server));
	if (!otherservers) {
	    syslog(LOG_CRIT, "renegade realloc");
	    abort();
	}
	setup_server(&otherservers[nservers - 1], &my_addr);
	/* we are up. */
	otherservers[nservers - 1].state = SERV_UP;

	/* I don't send hello's to myself--cancel the timer */
	timer_reset(otherservers[nservers - 1].timer);
	otherservers[nservers - 1].timer = NULL;

	/* cancel and reschedule all the timers--pointers need
	   adjusting */
	/* don't reschedule limbo's timer, so start i=1 */
	for (i = 1; i < nservers - 1; i++) {
	    timer_reset(otherservers[i].timer);
	    /* all the HELLO's are due now */
	    otherservers[i].timer = timer_set_rel(0L, server_timo,
						  &otherservers[i]);
	}
	me_server_idx = nservers - 1;
    }

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
    struct in_addr *serv_addr;
    Server *servers;
    int i, j;
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
    server_addrs = get_server_addrs(&num_servers);
    if (!server_addrs) {
	syslog(LOG_ERR, "server_reset no servers. nothing done.");
	return;
    }
    ok_list_new = (int *) malloc(num_servers * sizeof(int));
    if (!ok_list_new) {
	syslog(LOG_ERR, "server_reset no mem new");
	return;
    }
    ok_list_old = (int *) malloc(nservers * sizeof(int));
    if (!ok_list_old) {
	syslog(LOG_ERR, "server_reset no mem old");
	free(ok_list_new);
	return;
    }

    memset(ok_list_old, 0, nservers * sizeof(int));
    memset(ok_list_new, 0, num_servers * sizeof(int));
	
    /* reset timers--pointers will move */
    for (j = 1; j < nservers; j++) {	/* skip limbo */
	if (j == me_server_idx)
	    continue;
	timer_reset(otherservers[j].timer);
	otherservers[j].timer = NULL;
    }

    /* check off entries on new list which are on old list.
       check off entries on old list which are on new list. */

    /* count limbo as "OK" */
    num_ok = 1;
    ok_list_old[0] = 1;	/* limbo is OK */

    for (serv_addr = server_addrs, i = 0; i < num_servers; serv_addr++, i++) {
	for (j = 1; j < nservers; j++) { /* j = 1 since we skip limbo */
	    if (otherservers[j].addr.sin_addr.s_addr == serv_addr->s_addr) {
		/* if server is on both lists, mark */
		ok_list_new[i] = 1;
		ok_list_old[j] = 1;
		num_ok++;
		break;	/* for j loop */
	    }
	}
    }

    /* remove any dead servers on old list not on new list. */
    if (num_ok < nservers) {
	int *srv;

	new_num = 1;		/* limbo */
	/* count number of servers to keep */
	for (j = 1; j < nservers; j++) {
	    /* since we are never SERV_DEAD, the following
	       test prevents removing ourself from the list */
	    if (ok_list_old[j] || (otherservers[j].state != SERV_DEAD)) {
		syslog(LOG_INFO, "keeping server %s",
		       otherservers[j].addr_str);
		new_num++;
	    }
	}
	if (new_num < nservers) {
	    servers = (Server *) malloc(new_num * sizeof(Server));
	    if (!servers) {
		syslog(LOG_CRIT, "server_reset server malloc");
		abort();
	    }
	    i = 1;
	    servers[0] = otherservers[0]; /* copy limbo */

	    srv = (int *) malloc(nservers * sizeof(int));
	    memset(srv, 0, nservers * sizeof(int));

	    /* copy the kept servers */
	    for (j = 1; j < nservers; j++) { /* skip limbo */
		if (ok_list_old[j] ||
		    otherservers[j].state != SERV_DEAD) {
		    servers[i] = otherservers[j];
		    srv[j] = i;
		    i++;
		} else {
		    syslog(LOG_INFO, "flushing server %s",
			   otherservers[j].addr_str);
		    server_flush(&otherservers[j]);
		    srv[j] = -1;
		}

	    }
	    srv_nack_renumber(srv);

	    free(srv);
	    free(otherservers);
	    otherservers = servers;
	    nservers = new_num;
	}
    }

    /* add any new servers on new list not on old list. */
    new_num = 0;
    for (i = 0; i < num_servers; i++) {
	if (!ok_list_new[i])
	    new_num++;
    }

    /* new_num is number of extras. */
    nservers += new_num;
    otherservers = (Server *) realloc(otherservers, nservers * sizeof(Server));
    if (!otherservers) {
	syslog(LOG_CRIT, "server_reset realloc");
	abort();
    }

    me_server_idx = 0;
    for (j = 1; j < nservers - new_num; j++) {
	if (otherservers[j].addr.sin_addr.s_addr == my_addr.s_addr) {
	    me_server_idx = j;
	    break;
	}
    }
    if (!me_server_idx) {
	syslog(LOG_CRIT, "can't find myself");
	abort();
    }

    /* fill in otherservers with the new servers */
    for (i = 0; i < num_servers; i++) {
	if (!ok_list_new[i]) {
	    setup_server(&otherservers[nservers - (new_num--)],
			 &server_addrs[i]);
	    syslog(LOG_INFO, "adding server %s", inet_ntoa(server_addrs[i]));
	}
    }

    free(server_addrs);
    /* reset timers, to go off now.
       We can't get a time-left indication (bleagh!)
       so we expire them all now.  This will generally
       be non-destructive.  We assume that when this code is
       entered via a SIGHUP trigger that a system wizard
       is watching the goings-on to make sure things straighten
       themselves out.
       */
    for (i = 1; i < nservers; i++) {	/* skip limbo */
	if (i != me_server_idx && !otherservers[i].timer) {
	    otherservers[i].timer =
		timer_set_rel(0L, server_timo, &otherservers[i]);
#if 0
	    zdbug((LOG_DEBUG, "reset timer for %s",
		   otherservers[i].addr_str));
#endif	
	}
    }
    free(ok_list_old);
    free(ok_list_new);

#if 0
    zdbug((LOG_DEBUG, "server_reset: %d servers now", nservers));
#endif
}

/* note: these must match the order given in zserver.h */
static char *
srv_states[] = {
    "SERV_UP",
    "SERV_TARDY",
    "SERV_DEAD",
    "SERV_STARTING"
};
static char *
rlm_states[] = {
    "REALM_UP",
    "REALM_TARDY",
    "REALM_DEAD",
    "REALM_STARTING"
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
server_timo(arg)
    void *arg;
{
    Server *which = (Server *) arg;
    int auth = 0;

#if 0
    zdbug((LOG_DEBUG,"srv_timo: %s", which->addr_str));
#endif
    /* change state and reset if appropriate */
    switch(which->state) {
      case SERV_DEAD:			/* leave him dead */
	server_flush(which);
	auth = 1;
	break;
      case SERV_UP:			/* he's now tardy */
	which->state = SERV_TARDY;
	which->num_hello_sent = 0;
	which->timeout = timo_tardy;
	auth = 0;
	break;
      case SERV_TARDY:
      case SERV_STARTING:
	if (which->num_hello_sent >= ((which->state == SERV_TARDY) ?
				      H_NUM_TARDY :
				      H_NUM_STARTING)) {
	    /* he hasn't answered, assume DEAD */
	    which->state = SERV_DEAD;
	    which->num_hello_sent = 0;
	    which->timeout = timo_dead;
	    srv_nack_release(which);
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
    zdbug((LOG_DEBUG, "srv %s is %s", which->addr_str,
	   srv_states[which->state]));
#endif
    server_hello(which, auth);
    /* reschedule the timer */
    which->timer = timer_set_rel(which->timeout, server_timo, which);
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
    Server *server;
    struct sockaddr_in newwho;
    Code_t status;
    String *notice_class;

#if 0
    zdbug((LOG_DEBUG, "server_dispatch"));
#endif

    if (notice->z_kind == SERVACK) {
	srv_nack_cancel(notice, who);
	srv_responded(who);
	return ZERR_NONE;
    }
    /* set up a who for the real origin */
    memset(&newwho, 0, sizeof(newwho));
    newwho.sin_family = AF_INET;
    newwho.sin_addr.s_addr = notice->z_sender_addr.s_addr;
    newwho.sin_port = notice->z_port;

    server = server_which_server(who);

    /* we can dispatch to routines safely here, since they will
       return ZSRV_REQUEUE if appropriate.  We bounce this back
       to the caller, and the caller will re-queue the message
       for us to process later. */

    notice_class = make_string(notice->z_class, 1);

    if (realm_which_realm(&newwho))
	status = realm_dispatch(notice, auth, &newwho, server);
    else if (class_is_admin(notice_class)) {
	/* admins don't get acked, else we get a packet loop */
	/* will return  requeue if bdump request and dumping */
	i_s_admins.val++;
	return admin_dispatch(notice, auth, who, server);
    } else if (class_is_control(notice_class)) {
	status = control_dispatch(notice, auth, &newwho, server);
	i_s_ctls.val++;
    } else if (class_is_ulogin(notice_class)) {
	status = ulogin_dispatch(notice, auth, &newwho, server);
	i_s_logins.val++;
    } else if (class_is_ulocate(notice_class)) {
	status = ulocate_dispatch(notice, auth, &newwho, server);
	i_s_locates.val++;
    } else {
	/* shouldn't come from another server */
	syslog(LOG_WARNING, "srv_disp: pkt cls %s", notice->z_class);
	status = ZERR_NONE;	/* XXX */
    }
    if (status != ZSRV_REQUEUE)
	ack(notice, who); /* acknowledge it if processed */
    free_string(notice_class);
    return status;
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
    Server *temp;
    int i;
    long timerval;

    if (who->sin_port != srv_addr.sin_port) {
#if 0
	zdbug((LOG_DEBUG, "srv_wrong port %d", ntohs(who->sin_port)));
#endif
	return 1;
    }
    /* Not yet... talk to ken about authenticators */
#ifdef notdef
    if (!auth) {
#if 0
	zdbug((LOG_DEBUG, "srv_unauth"));
#endif
	return 1;
    }
#endif /* notdef */
    /* OK, go ahead and set him up. */
    temp = (Server *) malloc((nservers + 1) * sizeof(Server));
    if (!temp) {
	syslog(LOG_CRIT, "srv_reg malloc");
	return 1;
    }

    memcpy(temp, otherservers, nservers * sizeof(Server));
    free(otherservers);
    otherservers = temp;
    /* don't reschedule limbo's timer, so start i=1 */
    for (i = 1; i < nservers; i++) {
	if (i == me_server_idx) /* don't reset myself */
	    continue;
	/* reschedule the timers--we moved otherservers */
	timerval = timer_when(otherservers[i].timer);
	timer_reset(otherservers[i].timer);
	otherservers[i].timer = timer_set_abs(timerval, server_timo,
					      &otherservers[i]);
    }
    setup_server(&otherservers[nservers], &who->sin_addr);
    otherservers[nservers].state = SERV_STARTING;
    otherservers[nservers].timeout = timo_tardy;
    otherservers[nservers].update_queue = NULL;
    otherservers[nservers].dumping = 0;

    nservers++;
#if 0
    zdbug((LOG_DEBUG, "srv %s is %s", otherservers[nservers].addr_str,
	   srv_states[otherservers[nservers].state]));
#endif

    return 0;
}
#endif

/*
 * Tell the other servers that this client died.
 */

void
server_kill_clt(client)
    Client *client;
{
    int i;
    char buf[512], *lyst[2];
    ZNotice_t notice;
    ZNotice_t *pnotice; /* speed hack */
    caddr_t pack;
    int packlen, auth;
    Code_t retval;

    lyst[0] = inet_ntoa(client->addr.sin_addr),
    sprintf(buf, "%d", ntohs(client->addr.sin_port));
    lyst[1] = buf;

#if 0
    zdbug((LOG_DEBUG, "server kill clt %s/%s", lyst[0], lyst[1]));
#endif

    pnotice = &notice;

    memset (&notice, 0, sizeof(notice));
 
    pnotice->z_kind = ACKED;

    pnotice->z_port = srv_addr.sin_port;
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
	if (otherservers[i].state == SERV_DEAD)
	    continue;

	retval = ZFormatNoticeList(pnotice, lyst, 2, &pack, &packlen,
				   auth ? ZAUTH : ZNOAUTH);
	if (retval != ZERR_NONE) {
	    syslog(LOG_WARNING, "kill_clt format: %s", error_message(retval));
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
    Server *server;
{
    struct sockaddr_in who;
    Client *client;

#if 0
    zdbug((LOG_DEBUG, "kill_clt"));
#endif
    if (extract_addr(notice, &who) != ZERR_NONE)
	return ZERR_NONE;	/* XXX */
    client = client_find(&who.sin_addr, notice->z_port);
    if (!client) {
	syslog(LOG_NOTICE, "kill_clt: no such client (%s/%d) from %s",
	       inet_ntoa(who.sin_addr), ntohs(who.sin_port),
	       server->addr_str);
	return ZERR_NONE;	/* XXX */
    }
#if 1
    if (zdebug || 1) {
	syslog(LOG_DEBUG, "kill_clt clt_dereg %s/%d from %s",
	       inet_ntoa(who.sin_addr), ntohs(who.sin_port), server->addr_str);
    }
#endif

    /* remove the locations, too */
    client_deregister(client, 1);
    return ZERR_NONE;
}

/*
 * extract a sockaddr_in from a message body
 */

static Code_t
extract_addr(notice, who)
    ZNotice_t *notice;
    struct sockaddr_in *who;
{
    char *cp = notice->z_message;

    if (!notice->z_message_len) {
	syslog(LOG_WARNING, "bad addr pkt");
	return ZSRV_PKSHORT;
    }
    who->sin_addr.s_addr = inet_addr(notice->z_message);

    cp += strlen(cp) + 1;
    if (cp >= notice->z_message + notice->z_message_len) {
	syslog(LOG_WARNING, "short addr pkt");
	return ZSRV_PKSHORT;
    }
    who->sin_port = notice->z_port = htons((u_short) atoi(cp));
    who->sin_family = AF_INET;
#if 0
    zdbug((LOG_DEBUG,"ext %s/%d", inet_ntoa(who->sin_addr),
	   ntohs(who->sin_port)));
#endif
    return ZERR_NONE;
}

/*
 * Flush all data associated with the server which
 */

static void
server_flush(which)
    Server *which;
{
#if 0
    if (zdebug)
	syslog(LOG_DEBUG, "server_flush %s", which->addr_str);
#endif
    srv_nack_release(which);
}

/*
 * send a hello to which, updating the count of hello's sent
 * Authenticate if auth is set.
 */

static void
server_hello(which, auth)
    Server *which;
    int auth;
{
    send_msg(&which->addr, ADMIN_HELLO, auth);
    which->num_hello_sent++;
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
    Server *server;
{
    char *opcode = notice->z_opcode;
    Code_t status = ZERR_NONE;

#if 0
    zdbug((LOG_DEBUG, "ADMIN received"));
#endif

    if (strcmp(opcode, ADMIN_HELLO) == 0) {
	hello_respond(who, ADJUST, auth);
    } else if (strcmp(opcode, ADMIN_IMHERE) == 0) {
	srv_responded(who);
    } else if (strcmp(opcode, ADMIN_SHUTDOWN) == 0) {
#if 0
	zdbug((LOG_DEBUG, "server shutdown"));
#endif
	if (server) {
	    srv_nack_release(server);
	    server->state = SERV_DEAD;
	    server->timeout = timo_dead;
	    /* don't worry about the timer, it will
	       be set appropriately on the next send */
#if 0
	    zdbug((LOG_DEBUG, "srv %s is %s", server->addr_str,
		   srv_states[server->state]));
#endif
		}
    } else if (strcmp(opcode, ADMIN_BDUMP) == 0) {
	/* Ignore a brain dump request if this is a brain dump packet
         * or a packet being processed concurrently during a brain
         * dump. */
	if (bdumping || bdump_concurrent)
	    return ZERR_NONE;
	bdump_get(notice, auth, who, server);
    } else if (strcmp(opcode, ADMIN_KILL_CLT) == 0) {
	status = kill_clt(notice, server);
	if (status == ZERR_NONE)
	    ack(notice, who);
    } else {
	syslog(LOG_WARNING, "ADMIN unknown opcode %s",opcode);
    }
    return status;
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
    Server *server;
{

    /* this had better be a HELLO message--start of acquisition
       protocol, OR a status req packet */

    if (strcmp(notice->z_opcode, ADMIN_STATUS) == 0) {
	/* status packet */
	send_stats(who);
	return ZERR_NONE;
    }

#ifdef notdef
    syslog(LOG_INFO, "disp: new server?");
    if (server_register(notice, auth, who) != ZERR_NONE) {
	syslog(LOG_INFO, "new server failed");
    } else {
	syslog(LOG_INFO, "new server %s, %d", inet_ntoa(who->sin_addr),
	       ntohs(who->sin_port));
	hello_respond(who, DONT_ADJUST, auth);
    }
#else
    syslog(LOG_INFO, "srv_adisp: server attempt from %s",
	   inet_ntoa(who->sin_addr));
#endif /* notdef */

    return ZERR_NONE;
}

static void
send_stats(who)
    struct sockaddr_in *who;
{
    int i;
    char buf[BUFSIZ];
    char **responses;
    int num_resp;
    char *vers, *pkts, *upt;
    ZRealm *realm;

    int extrafields = 0;
#define	NUM_FIXED 3			/* 3 fixed fields, plus server info */
					/* well, not really...but for
					   backward compatibility, we gotta
					   do it this way. */
    vers = get_version();

    sprintf(buf, "%d pkts", npackets);
    pkts = strsave(buf);
    sprintf(buf, "%d seconds operational",NOW - uptime);
    upt = strsave(buf);

#ifdef OLD_COMPAT
    if (old_compat_count_uloc)
	extrafields++;
    if (old_compat_count_ulocate)
	extrafields++;
    if (old_compat_count_subscr)
	extrafields++;
#endif /* OLD_COMPAT */
#ifdef NEW_COMPAT
    if (new_compat_count_uloc)
	extrafields++;
    if (new_compat_count_subscr)
	extrafields++;
#endif /* NEW_COMPAT */
    extrafields += nrealms;
    responses = (char **) malloc((NUM_FIXED + nservers + extrafields) *
				 sizeof(char *));
    responses[0] = vers;
    responses[1] = pkts;
    responses[2] = upt;

    num_resp = NUM_FIXED;
    /* start at 1 and ignore limbo */
    for (i = 1; i < nservers ; i++) {
	sprintf(buf, "%s/%s%s", otherservers[i].addr_str,
		srv_states[(int) otherservers[i].state],
		otherservers[i].dumping ? " (DUMPING)" : "");
	responses[num_resp++] = strsave(buf);
    }
#ifdef OLD_COMPAT
    if (old_compat_count_uloc) {
	sprintf(buf, "%d old old location requests", old_compat_count_uloc);
	responses[num_resp++] = strsave(buf);
    }
    if (old_compat_count_ulocate) {
	sprintf(buf, "%d old old loc lookup requests",
		old_compat_count_ulocate);
	responses[num_resp++] = strsave(buf);
    }
    if (old_compat_count_subscr) {
	sprintf(buf, "%d old old subscr requests", old_compat_count_subscr);
	responses[num_resp++] = strsave(buf);
    }
#endif /* OLD_COMPAT */
#ifdef NEW_COMPAT
    if (new_compat_count_uloc) {
	sprintf(buf, "%d new old location requests", new_compat_count_uloc);
	responses[num_resp++] = strsave(buf);
    }
    if (new_compat_count_subscr) {
	sprintf(buf, "%d new old subscr requests", new_compat_count_subscr);
	responses[num_resp++] = strsave(buf);
    }
#endif /* NEW_COMPAT */
    for (realm = otherrealms, i = 0; i < nrealms ; i++, realm++) {
      sprintf(buf, "%s(%s)/%s", realm->name, 
	      inet_ntoa((realm->addrs[realm->idx]).sin_addr),
	      rlm_states[(int) realm->state]);
      responses[num_resp++] = strsave(buf);
    }

    send_msg_list(who, ADMIN_STATUS, responses, num_resp, 0);

    /* Start at one; don't try to free static version string */
    for (i = 1; i < num_resp; i++)
	free(responses[i]);
    free(responses);
}

/*
 * Get a list of server addresses.
#ifdef HAVE_HESIOD
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
    int i;
    char **server_hosts;
    char **cpp;
    struct in_addr *addrs;
    struct in_addr *addr;
    struct hostent *hp;

#ifdef HAVE_HESIOD
    /* get the names from Hesiod */
    server_hosts = hes_resolve("zephyr","sloc");
    if (!server_hosts)
	return NULL;
#else
    server_hosts = get_server_list(list_file);
    if (!server_hosts)
	return NULL;
#endif
    /* count up */
    i = 0;
    for (cpp = server_hosts; *cpp; cpp++)
	i++;
	
    addrs = (struct in_addr *) malloc(i * sizeof(struct in_addr));

    /* Convert to in_addr's */
    for (cpp = server_hosts, addr = addrs, i = 0; *cpp; cpp++) {
	hp = gethostbyname(*cpp);
	if (hp) {
	    memcpy(addr, hp->h_addr, sizeof(struct in_addr));
	    addr++, i++;
	} else {
	    syslog(LOG_WARNING, "hostname failed, %s", *cpp);
	}
    }
    *number = i;
#ifndef HAVE_HESIOD
    free_server_list(server_hosts);
#endif
    return addrs;
}

#ifndef HAVE_HESIOD

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

    /* start with 16, realloc if necessary */
    nhosts = 16;
    ret_list = (char **) malloc(nhosts * sizeof(char *));

    fp = fopen(file, "r");
    if (fp) {
	while (fgets(buf, MAXHOSTNAMELEN, fp)) {
	    /* nuke the newline, being careful not to overrun
	       the buffer searching for it with strlen() */
	    buf[MAXHOSTNAMELEN - 1] = '\0';
	    newline = strchr(buf, '\n');
	    if (newline)
		*newline = '\0';

	    if (nused + 1 >= nhosts) {
		/* get more pointer space if necessary */
		/* +1 to leave room for null pointer */
		ret_list = (char **) realloc(ret_list, nhosts * 2);
		nhosts = nhosts * 2;
	    }
	    ret_list[nused++] = strsave(buf);
	}
	fclose(fp);
    } else {
	if (gethostname(buf, sizeof(buf)) < 0) {
	    free(ret_list);
	    return NULL;
	}
	ret_list[nused++] = strsave(buf);
    }
    ret_list[nused] = NULL;
    return ret_list;
}

/* 
 * free storage allocated by get_server_list
 */
static void
free_server_list(list)
    char **list;
{
    char **orig_list = list;

    if (!nhosts)			/* nothing allocated */
	return;
    for (; *list; list++)
	free(*list);
    free(orig_list);
    return;
}
#endif

/*
 * initialize the server structure for address addr, and set a timer
 * to go off immediately to send hello's to other servers.
 */

static void
setup_server(server, addr)
    Server *server;
    struct in_addr *addr;
{
    server->state = SERV_DEAD;
    server->timeout = timo_dead;
    server->num_hello_sent = 0;
    server->addr.sin_family = AF_INET;
    /* he listens to the same port we do */
    server->addr.sin_port = srv_addr.sin_port;
    server->addr.sin_addr = *addr;
    strcpy(server->addr_str, inet_ntoa(*addr));
    server->timer = timer_set_rel(0L, server_timo, server);
    server->queue = NULL;
    server->dumping = 0;
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
    Server *which;

#if 0
    zdbug((LOG_DEBUG, "hello from %s", inet_ntoa(who->sin_addr)));
#endif

    send_msg(who, ADMIN_IMHERE, auth);
    if (adj != ADJUST)
	return;

    /* If we think he's down, schedule an immediate HELLO. */

    which = server_which_server(who);
    if (!which)
	return;

    switch (which->state) {
      case SERV_DEAD:
	/* he said hello, we thought he was dead.
	   reschedule his hello for now. */
	timer_reset(which->timer);
	which->timer = timer_set_rel(0L, server_timo, which);
	break;
      case SERV_STARTING:
      case SERV_TARDY:
      case SERV_UP:
      default:
	break;
    }
}    

/*
 * return the server descriptor for server at who
 */

Server *
server_which_server(who)
    struct sockaddr_in *who;
{
    Server *server;
    int i;

    if (who->sin_port != srv_addr.sin_port)
	return NULL;

    /* don't check limbo */
    for (server = &otherservers[1], i = 1; i < nservers; i++, server++) {
	if (server->addr.sin_addr.s_addr == who->sin_addr.s_addr)
	    return server;
    }
    return NULL;
}

/*
 * We received a response to a hello packet or an ack. Adjust server state
 * appropriately.
 */
static void
srv_responded(who)
    struct sockaddr_in *who;
{
    Server *which = server_which_server(who);

#if 0
    zdbug((LOG_DEBUG, "srv_responded %s", inet_ntoa(who->sin_addr)));
#endif

    if (!which) {
	syslog(LOG_ERR, "hello input from non-server?!");
	return;
    }

    switch (which->state) {
      case SERV_DEAD:
	/* he responded, we thought he was dead. mark as starting
	   and negotiate */
	which->state = SERV_STARTING;
	which->timeout = timo_tardy;
	timer_reset(which->timer);
	which->timer = timer_set_rel(0L, server_timo, which);

      case SERV_STARTING:
	/* here we negotiate and set up a braindump */
	if (bdump_socket < 0)
	    bdump_offer(who);
	break;

      case SERV_TARDY:
	which->state = SERV_UP;
	/* Fall through. */

      case SERV_UP:
	/* reset the timer and counts */
	which->num_hello_sent = 0;
	which->timeout = timo_up;
	timer_reset(which->timer);
	which->timer = timer_set_rel(which->timeout, server_timo, which);
	break;
    }
#if 0
    zdbug((LOG_DEBUG, "srv %s is %s", which->addr_str,
	   srv_states[which->state]));
#endif
}

/*
 * Send each of the other servers a shutdown message.
 */

void
server_shutdown()
{
    int i;

    /* don't tell limbo to go away, start at 1*/
    for (i = 1; i < nservers; i++)
	send_msg(&otherservers[i].addr, ADMIN_SHUTDOWN, 1);
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
    ZNotice_t *pnotice; /* speed hack */
    char *pack;
    int packlen;
    Code_t retval;

    pnotice = &notice;

    memset (&notice, 0, sizeof(notice));

    pnotice->z_kind = ACKED;

    pnotice->z_port = srv_addr.sin_port;
    pnotice->z_class = ZEPHYR_ADMIN_CLASS;
    pnotice->z_class_inst = "";
    pnotice->z_opcode = opcode;
    pnotice->z_sender = myname;	/* myname is the hostname */
    pnotice->z_recipient = "";
    pnotice->z_default_format = "";
    pnotice->z_message = NULL;
    pnotice->z_message_len = 0;
    pnotice->z_num_other_fields = 0;

    /* XXX for now, we don't do authentication */
    auth = 0;

    retval = ZFormatNotice(pnotice, &pack, &packlen, auth ? ZAUTH : ZNOAUTH);
    if (retval != ZERR_NONE) {
	syslog(LOG_WARNING, "snd_msg format: %s", error_message(retval));
	return;
    }
    retval = ZSetDestAddr(who);
    if (retval != ZERR_NONE) {
	syslog(LOG_WARNING, "snd_msg set addr: %s", error_message(retval));
	free(pack);
	return;
    }
    /* don't wait for ack */
    retval = ZSendPacket(pack, packlen, 0);
    if (retval != ZERR_NONE)
	syslog(LOG_WARNING, "snd_msg xmit: %s", error_message(retval));
    free(pack);
}

/*
 * send a notice with a message to who with admin class and opcode and
 * message body as specified.
 * auth is set if we want to send authenticated
 * server_idx is -1 if we are sending to a client, or the server index
 *  if we are sending to a server.
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
    char *pack;
    int packlen;
    Code_t retval;
    Unacked *nacked;

    memset (&notice, 0, sizeof(notice));

    notice.z_kind = UNSAFE;
    notice.z_port = srv_addr.sin_port;
    notice.z_class = ZEPHYR_ADMIN_CLASS;
    notice.z_class_inst = "";
    notice.z_opcode = opcode;
    notice.z_sender = myname;	/* myname is the hostname */
    notice.z_recipient = "";
    notice.z_default_format = "";
    notice.z_message = NULL;
    notice.z_message_len = 0;
    notice.z_num_other_fields = 0;

    /* XXX for now, we don't do authentication */
    auth = 0;

    retval = ZFormatNoticeList(&notice, lyst, num, &pack, &packlen,
			       auth ? ZAUTH : ZNOAUTH);
    if (retval != ZERR_NONE) {
	syslog(LOG_WARNING, "snd_msg_lst format: %s", error_message(retval));
	return;
    }
    retval = ZSetDestAddr(who);
    if (retval != ZERR_NONE) {
	syslog(LOG_WARNING, "snd_msg_lst set addr: %s", error_message(retval));
	free(pack);
	return;
    }
    xmit_frag(&notice, pack, packlen, 0);
    free(pack);
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
    int i;
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
	if (otherservers[i].state == SERV_DEAD &&
	    otherservers[i].dumping == 0) {
	    /* if we are dumping to him, we want to
	       queue it, even if he's dead */
	    continue;
	}

	pack = malloc(sizeof(ZPacket_t));
	if (!pack) {
	    syslog(LOG_CRIT, "srv_fwd malloc");
	    abort();
	}
	if (realm_which_realm(who)) {
	  retval = ZNewFormatSmallRawNotice(notice, pack, &packlen);
	} else {
	  retval = ZFormatSmallRawNotice(notice, pack, &packlen);
	}
	if (retval != ZERR_NONE) {
	    syslog(LOG_WARNING, "srv_fwd format: %s", error_message(retval));
	    continue;
	}
	if (otherservers[i].dumping) {
	    server_queue(&otherservers[i], packlen, pack, auth, who);
	    continue;
	}
	server_forw_reliable(&otherservers[i], pack, packlen, notice);
    }
}

static void
server_forw_reliable(server, pack, packlen, notice)
    Server *server;
    caddr_t pack;
    int packlen;
    ZNotice_t *notice;
{
    Code_t retval;
    Unacked *nacked;
    int hashval;

    retval = ZSetDestAddr(&server->addr);
    if (retval != ZERR_NONE) {
	syslog(LOG_WARNING, "srv_fwd_rel set addr: %s", error_message(retval));
	free(pack);
	return;
    }
    retval = ZSendPacket(pack, packlen, 0);
    if (retval != ZERR_NONE) {
	syslog(LOG_WARNING, "srv_fwd xmit: %s", error_message(retval));
	free(pack);
	return;
    }			
    /* now we've sent it, mark it as not ack'ed */
		
    nacked = (Unacked *) malloc(sizeof(Unacked));
    if (!nacked) {
	/* no space: just punt */
	syslog(LOG_ERR, "srv_forw_rel nack malloc");
	free(pack);
	return;
    }

    nacked->client = NULL;
    nacked->rexmits = 0;
    nacked->packet = pack;
    nacked->dest.srv_idx = server - otherservers;
    nacked->packsz = packlen;
    nacked->uid = notice->z_uid;
    nacked->timer = timer_set_rel(rexmit_times[0], srv_rexmit, nacked);
    hashval = SRV_NACKTAB_HASHVAL(nacked->dest.srv_idx, nacked->uid);
    LIST_INSERT(&srv_nacktab[hashval], nacked);
}

/*
 * send the queued message for the server.
 */

void
server_send_queue(server)
    Server *server;
{
    Pending *pending;
    ZNotice_t notice;
    Code_t status;

    while (server->queue) {
	pending = server_dequeue(server);
	status = ZParseNotice(pending->packet, pending->len, &notice);
	if (status != ZERR_NONE) {
	    syslog(LOG_ERR, "ssq bad notice parse (%s): %s",
		   inet_ntoa(pending->who.sin_addr), error_message(status));
	} else {
	    server_forw_reliable(server, pending->packet, pending->len,
				 &notice);
	    free(pending);
	    /* ACK handling routines will free the packet */
	}
    }
}

/*
 * a server has acknowledged a message we sent to him; remove it from
 * server unacked queue
 */

static void
srv_nack_cancel(notice, who)
    ZNotice_t *notice;
    struct sockaddr_in *who;
{
    Server *server = server_which_server(who);
    Unacked *nacked;
    int hashval;

    if (!server) {
	syslog(LOG_ERR, "non-server ack?");
	return;
    }
    hashval = SRV_NACKTAB_HASHVAL(server - otherservers, notice->z_uid);
    for (nacked = srv_nacktab[hashval]; nacked; nacked = nacked->next) {
	if (nacked->dest.srv_idx == server - otherservers
	    && ZCompareUID(&nacked->uid, &notice->z_uid)) {
	    timer_reset(nacked->timer);
	    if (nacked->rexmits > 0) 
	        syslog(LOG_DEBUG, "srv_nack_cancel xmit %d of zuid %4x:%4x:%x to %s/%d",
		       nacked->rexmits,
		       nacked->uid.zuid_addr.s_addr, nacked->uid.tv.tv_sec, nacked->uid.tv.tv_usec,
		       otherservers[nacked->dest.srv_idx].addr_str,
		       ntohs(otherservers[nacked->dest.srv_idx].addr.sin_port));
	    free(nacked->packet);
	    LIST_DELETE(nacked);
	    free(nacked);
	    return;
	}
    }
#if 0
    zdbug((LOG_DEBUG, "srv_nack not found"));
#endif
}

/*
 * retransmit a message to another server
 */

static void
srv_rexmit(arg)
    void *arg;
{
    Unacked *packet = (Unacked *) arg;
    Code_t retval;
    /* retransmit the packet */
	
#if 0
    zdbug((LOG_DEBUG,"srv_rexmit to %s/%d",
	   otherservers[packet->dest.srv_idx].addr_str,
	   ntohs(otherservers[packet->dest.srv_idx].addr.sin_port)));
#endif
    if (otherservers[packet->dest.srv_idx].state == SERV_DEAD) {
#if 0
	zdbug((LOG_DEBUG, "cancelling send to dead server"));
#endif
	LIST_DELETE(packet);
	free(packet->packet);
	srv_nack_release(&otherservers[packet->dest.srv_idx]);
	free(packet);
	return;
    }
    retval = ZSetDestAddr(&otherservers[packet->dest.srv_idx].addr);
    if (retval != ZERR_NONE) {
	syslog(LOG_WARNING, "srv_rexmit set addr: %s", error_message(retval));
    } else {
	retval = ZSendPacket(packet->packet, packet->packsz, 0);
	if (retval != ZERR_NONE)
	    syslog(LOG_WARNING, "srv_rexmit xmit %d of zuid %8x:%8x:%8x to %s/%d: %s",
		   packet->rexmits,
		   packet->uid.zuid_addr.s_addr, packet->uid.tv.tv_sec, packet->uid.tv.tv_usec,
		   otherservers[packet->dest.srv_idx].addr_str,
		   ntohs(otherservers[packet->dest.srv_idx].addr.sin_port),
		   error_message(retval));
    }

    /* reset the timer */
    if (rexmit_times[packet->rexmits + 1] != -1)
	packet->rexmits++;
    packet->timer = timer_set_rel(rexmit_times[packet->rexmits], srv_rexmit,
				  packet);
}

/*
 * Clean up the not-yet-acked queue and release anything destined
 * to the server.
 */

static void
srv_nack_release(server)
    Server *server;
{
    int i;
    Unacked *nacked, *next;

    for (i = 0; i < SRV_NACKTAB_HASHSIZE; i++) {
	for (nacked = srv_nacktab[i]; nacked; nacked = next) {
	    next = nacked->next;
	    if (nacked->dest.srv_idx == server - otherservers) {
		timer_reset(nacked->timer);
		syslog(LOG_DEBUG, "srv_nack_release xmit %d to %s/%d",
		       nacked->rexmits,
		       otherservers[nacked->dest.srv_idx].addr_str,
		       ntohs(otherservers[nacked->dest.srv_idx].addr.sin_port));
		LIST_DELETE(nacked);
		free(nacked->packet);
		free(nacked);
	    }
	}
    }
}

/*
 * Adjust indices of not-yet-acked packets sent to other servers to
 * continue to refer to the correct server.
 */

static void
srv_nack_renumber (new_idx)
    int *new_idx;
{
    /* XXX release any private queue for this server */
    Unacked *nacked;
    int idx, i;

    /* search the not-yet-acked list for anything destined to 'from', and
       change the index to 'to'. */
    for (i = 0; i < SRV_NACKTAB_HASHSIZE; i++) {
	for (nacked = srv_nacktab[i]; nacked; nacked = nacked->next) {
	    idx = new_idx[nacked->dest.srv_idx];
	    if (idx < 0) {
		syslog(LOG_ERR, "srv_nack_renumber error: [%d]=%d",
		       nacked->dest.srv_idx, idx);
		idx = 0;
	    }
	    nacked->dest.srv_idx = idx;
	}
    }
}

/*
 * Queue this notice to be transmitted to the server when it is ready.
 */
static void
server_queue(server, len, pack, auth, who)
    Server *server;
    int len;
    void *pack;
    int auth;
    struct sockaddr_in *who;
{
    Pending *pending;

    pending = (Pending *) malloc(sizeof(Pending));
    if (!pending) {
	syslog(LOG_CRIT, "update_queue malloc");
	abort();
    }
    pending->packet = pack;
    pending->len = len;
    pending->auth = auth;
    pending->who = *who;
    pending->next = NULL;

    /* put it on the end of the list */
    if (server->queue)
	server->queue_last->next = pending;
    else
	server->queue = server->queue_last = pending;
}

/*
 * Pull a notice off the hold queue.
 */

Pending *
server_dequeue(server)
    Server *server;
{
    Pending *pending;
	
    if (!server->queue)
	return NULL;
    pending = server->queue;
    server->queue = pending->next;
    return pending;
}

/*
 * free storage used by a pending queue entry.
 */

void
server_pending_free(pending)
    Pending *pending;
{
    free(pending->packet);
    free(pending);
    return;
}

/*
 * Queue something to be handled later by this server.
 */

void
server_self_queue(notice, auth, who)
    ZNotice_t* notice;
    int auth;
    struct sockaddr_in * who;
{
    char *pack;
    int packlen;
    Code_t retval;

    retval = ZFormatRawNotice(notice, &pack, &packlen);
    if (retval != ZERR_NONE) {
	syslog(LOG_CRIT, "srv_self_queue format: %s", error_message(retval));
	abort();
    }
    server_queue(me_server, packlen, pack, auth, who);
}

/*
 * dump info about servers onto the fp.
 * assumed to be called with SIGFPE blocked
 * (true if called from signal handler)
 */
void
server_dump_servers(fp)
    FILE *fp;
{
    int i;

    for (i = 0; i < nservers ; i++) {
	fprintf(fp, "%d:%s/%s%s\n", i, otherservers[i].addr_str,
		srv_states[otherservers[i].state],
		otherservers[i].dumping ? " (DUMPING)" : "");
    }
}

