/* This file is part of the Project Athena Zephyr Notification System.
 * It contains functions for communicating with the HostManager.
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
static char rcsid_hostm_s_c[] = "$Header$";
#endif SABER
#endif lint

#include "zserver.h"

/*
 *
 * External functions:
 *
 * void hostm_dispatch(notice, auth, who, server)
 *	ZNotice_t *notice;
 *	int auth;
 *	struct sockaddr_in *who;
 *	ZServerDesc_t *server;
 *
 * void hostm_flush(host, server)
 *	ZHostList_t *host;
 *	ZServerDesc_t *server;
 *
 * void hostm_transfer(host, server)
 *	ZHostList_t *host;
 *	ZServerDesc_t *server;
 *
 * ZHostList_t *hostm_find_host(addr)
 *	struct in_addr *addr;
 *
 * ZServerDesc_t *hostm_find_server(addr)
 *	struct in_addr *addr;
 *
 * void hostm_shutdown()
 *
 * void hostm_losing(client, host)
 *	ZClient_t *client;
 *	ZHostList_t *host;
 *
 * void hostm_deathgram(sin, server)
 *	struct sockaddr_in *sin;
 * 	ZServerDesc_t *server;
 *
 * void hostm_dump_hosts(fp)
 *	FILE *fp;
 */

/*
 * This module maintains two important structures.
 * all_hosts is an array of all currently known hosts, and which server
 * is responsible for that host.  This list is kept sorted by IP address
 * so that lookups can be fast (binary search).  num_hosts contains the
 * number of hosts to be found in the array.
 *
 * The losing hosts list is a linked list of all the clients (and their hosts)
 * whose existence is in doubt.  Any host on this list has already been sent
 * a ping and is expected to reply immediately.
 * As usual, the first element of the list is a placeholder header so we
 * know when the list has been completely scanned.
 */

struct hostlist {
	ZHostList_t *host;		/* ptr to host struct */
	int server_index;		/* index of server in the table */
};

typedef struct _losinghost {
	struct _losinghost *q_forw;
	struct _losinghost *q_back;
	ZHostList_t *lh_host;
	timer lh_timer;
	ZClient_t *lh_client;
} losinghost;

#define	NULLLH		((struct _losinghost *) 0)
#define	NULLHLT		((struct hostlist *) 0)

static struct hostlist *all_hosts;

static int num_hosts = 0;		/* number of hosts in all_hosts */
static long lose_timo = LOSE_TIMO;

static losinghost *losing_hosts = NULLLH; /* queue of pings for hosts we
					     doubt are really there */

static void host_detach(), insert_host(), remove_host();
static void host_not_losing(), host_lost(), ping();
static Code_t host_attach();
static int cmp_hostlist();

/*
 * We received a HostManager packet.  process accordingly.
 */

/*ARGSUSED*/
Code_t
hostm_dispatch(notice, auth, who, server)
ZNotice_t *notice;
int auth;
struct sockaddr_in *who;
ZServerDesc_t *server;
{
	ZServerDesc_t *owner;
	ZHostList_t *host = NULLZHLT;
	char *opcode = notice->z_opcode;
	Code_t retval;


	zdbug((LOG_DEBUG,"hm_disp"));

	host = hostm_find_host(&who->sin_addr);
	if (host && host->zh_locked)
		return(ZSRV_REQUEUE);

	if (notice->z_kind == HMACK) {
		host_not_losing(who);
		return(ZERR_NONE);
	} else if (notice->z_kind != HMCTL) {
		zdbug((LOG_DEBUG, "bogus HM packet"));
		clt_ack(notice, who, AUTH_FAILED);
		return(ZERR_NONE);
	}
	owner = hostm_find_server(&who->sin_addr);
	if (!strcmp(opcode, HM_ATTACH)) {
		zdbug((LOG_DEBUG,"attach %s",inet_ntoa(who->sin_addr)));
		if (owner == server) {
			zdbug((LOG_DEBUG,"no change"));
			/* Same server owns him.  do nothing */
		} else if (owner) {
			/* He has switched servers.
			   he was lost but has asked server to work for him.
			   We need to transfer him to server */
			zdbug((LOG_DEBUG,"hm_disp transfer"));
			hostm_transfer(host, server);
		} else {
			/* no owner.  attach him to server. */
			if ((retval = host_attach(who, server))
			    != ZERR_NONE) {
				syslog(LOG_WARNING, "hattach failed: %s",
				       error_message(retval));
				return(retval);
			}

		}
		if (server == me_server) {
			server_forward(notice, auth, who);
			ack(notice, who);
		}
	} else if (!strcmp(opcode, HM_BOOT)) {
		zdbug((LOG_DEBUG, "boot %s",inet_ntoa(who->sin_addr)));
		/* Booting is just like flushing and attaching */
		if (owner)		/* if owned, flush */
			hostm_flush(host, owner);
		if ((retval = host_attach(who, server)) != ZERR_NONE) {
			syslog(LOG_WARNING, "hattach failed: %s",
			       error_message(retval));
			return(retval);
		}
		if (server == me_server) {
			server_forward(notice, auth, who);
			ack(notice, who);
		}
	} else if (!strcmp(opcode, HM_FLUSH)) {
		zdbug((LOG_DEBUG, "hm_flush %s",inet_ntoa(who->sin_addr)));
		if (!owner)
			return(ZERR_NONE);
		/* flush him */
		hostm_flush(host, owner);
		if (server == me_server)
			server_forward(notice, auth, who);
	} else if (!strcmp(opcode, HM_DETACH)) {
		zdbug((LOG_DEBUG, "hm_detach %s",inet_ntoa(who->sin_addr)));
		/* ignore it */
	} else {
		syslog(LOG_WARNING, "hm_disp: unknown opcode %s",opcode);
		return(ZERR_NONE);
	}
	return(ZERR_NONE);
}

/*
 * Flush all information about this host.  Remove any losing host entries,
 * deregister all the clients, flush any user locations, and remove the host
 * from its server.
 */

void
hostm_flush(host, server)
ZHostList_t *host;
ZServerDesc_t *server;
{
	register ZClientList_t *clist = NULLZCLT, *clt;
	losinghost *lhp, *lhp2;
	int omask = sigblock(sigmask(SIGFPE)); /* don't let db dumps start */

	zdbug((LOG_DEBUG,"hostm_flush"));

	if (losing_hosts)
		for (lhp = losing_hosts->q_forw;
		     lhp != losing_hosts;)
			if (lhp->lh_host == host) {
				lhp2 = lhp->q_back;
				timer_reset(lhp->lh_timer);
				xremque(lhp);
				xfree(lhp);
				lhp = lhp2->q_forw;
			} else
				lhp = lhp->q_forw;

	if ((clist = host->zh_clients))
		for (clt = clist->q_forw; clt != clist; clt = clist->q_forw) {
			/* client_deregister frees this client & subscriptions
			   & locations and remque()s the client */
			if (zdebug)
				syslog(LOG_DEBUG, "hostm_flush clt_dereg");
			client_deregister(clt->zclt_client, host, 1);
		}

	uloc_hflush(&host->zh_addr.sin_addr);
	host_detach(&host->zh_addr.sin_addr, server);
	/* XXX tell other servers */
	(void) sigsetmask(omask);
	return;
}

/*
 * send a shutdown to each of our hosts
 */

void
hostm_shutdown()
{
	register ZHostList_t *hosts = otherservers[me_server_idx].zs_hosts;
	register ZHostList_t *host;
	int newserver, i;

	zdbug((LOG_DEBUG,"hostm_shutdown"));
	if (!hosts)
		return;

	for (i = 0; i < nservers; i++){
		if (i == me_server_idx) continue;
		if (otherservers[i].zs_state == SERV_UP)
			break;
	}
	if (i == nservers)		/* no other servers are up */
		newserver = 0;
	else
		newserver = 1;

	/* kill them all */
	for (host = hosts->q_forw;
	     host != hosts;
	     host = host->q_forw) {
		/* recommend a random, known up server */
		if (newserver) {
			do
				newserver = (int) (random() % (nservers - 1)) + 1;
			while (newserver == limbo_server_idx() ||
			       (otherservers[newserver].zs_state != SERV_UP &&
				otherservers[newserver].zs_state != SERV_TARDY) ||
			       newserver == me_server_idx);
			hostm_deathgram(&host->zh_addr, &otherservers[newserver]);
		} else
			hostm_deathgram(&host->zh_addr, NULLZSDT);
	}
	return;
}


/*
 * The client on the host is not acknowledging any packets.  Ping the
 * host and set a timeout.
 */

void
hostm_losing(client, host)
ZClient_t *client;
ZHostList_t *host;
{
	losinghost *newhost;

	zdbug((LOG_DEBUG,"losing host"));
	if (!losing_hosts) {
		if (!(losing_hosts = (losinghost *) xmalloc(sizeof(losinghost)))) {
			syslog(LOG_ERR, "no mem losing host");
			return;
		}
		losing_hosts->q_forw = losing_hosts->q_back = losing_hosts;
	}
	for (newhost = losing_hosts->q_forw;
	     newhost != losing_hosts;
	     newhost = newhost->q_forw)
		if (newhost->lh_client == client) {
			zdbug((LOG_DEBUG,"clt already losing"));
			return;
		}
	if (!(newhost = (losinghost *) xmalloc(sizeof(losinghost)))) {
		syslog(LOG_ERR, "no mem losing host 2");
		return;
	}

	/* send a ping */
	ping(&host->zh_addr);
	newhost->lh_host = host;
	newhost->lh_client = client;
	newhost->lh_timer = timer_set_rel(lose_timo, host_lost, (caddr_t) newhost);
	xinsque(newhost, losing_hosts);
	return;
}

/*
 * The host did not respond to the ping, so we punt him
 */

static void
host_lost(which)
losinghost *which;
{
	ZServerDesc_t *server;
	int omask = sigblock(sigmask(SIGFPE)); /* don't start db dumps */

	zdbug((LOG_DEBUG,"lost host %s",
	       inet_ntoa(which->lh_host->zh_addr.sin_addr)));

	if (!(server = hostm_find_server(&which->lh_host->zh_addr.sin_addr))) {
		zdbug((LOG_DEBUG,"no server"));
		xremque(which);
		xfree(which);
		(void) sigsetmask(omask);
		return;
	}
	xremque(which);
	hostm_flush(which->lh_host, server);
	xfree(which);

	/* XXX tell other servers */
	(void) sigsetmask(omask);
	return;
}

/*
 * The host responded to the ping, so we flush the losing clients on this host.
 */

static void
host_not_losing(who)
struct sockaddr_in *who;
{
	losinghost *lhp, *lhp2;
	int omask;

	if (!losing_hosts)
		return;
	omask = sigblock(sigmask(SIGFPE)); /* don't start db dumps */
	for (lhp = losing_hosts->q_forw;
	     lhp != losing_hosts;)
		if (lhp->lh_host->zh_addr.sin_addr.s_addr == who->sin_addr.s_addr) {
			/* go back, since remque will change things */
			lhp2 = lhp->q_back;
			timer_reset(lhp->lh_timer);
			zdbug((LOG_DEBUG,"lost client %s/%d",
			       inet_ntoa(lhp->lh_client->zct_sin.sin_addr),
			       ntohs(lhp->lh_client->zct_sin.sin_port)));
			/* deregister all subscriptions, and flush locations
			   associated with the client. */
			if (zdebug)
				syslog(LOG_DEBUG,"h_not_lose clt_dereg");
			client_deregister(lhp->lh_client, lhp->lh_host, 1);
			server_kill_clt(lhp->lh_client);
			xremque(lhp);
			xfree(lhp);
			/* now that the remque adjusted the linked list,
			   we go forward again */
			lhp = lhp2->q_forw;
		} else
			lhp = lhp->q_forw;
	(void) sigsetmask(omask);
	return;
}


/*
 * transfer this host to server's ownership.  The caller must update the
 * other servers.
 */

void
hostm_transfer(host, server)
ZHostList_t *host;
ZServerDesc_t *server;
{
	int omask;

	/* we need to unlink and relink him, and change the table entry */

	zdbug((LOG_DEBUG, "hostm_transfer 0x%x to 0x%x", host, server));

	/* is this the same server? */
	if (hostm_find_server(&host->zh_addr.sin_addr) == server)
		return;

	omask = sigblock(sigmask(SIGFPE)); /* don't start db dumps */
	/* remove from old server's queue */
	xremque(host);

	/* switch servers in the table */
	remove_host(host);
	insert_host(host, server);

	/* insert in our queue */
	xinsque(host, server->zs_hosts);
	(void) sigsetmask(omask);
	return;
}


/*
 * attach the host with return address in who to the server.
 */

static Code_t
host_attach(who, server)
struct sockaddr_in *who;
ZServerDesc_t *server;
{
	register ZHostList_t *hlist;
	register ZClientList_t *clist;
	int omask = sigblock(sigmask(SIGFPE)); /* don't start db dumps */

	/* allocate a header */
	if (!(hlist = (ZHostList_t *)xmalloc(sizeof(ZHostList_t)))) {
		syslog(LOG_WARNING, "hm_attach malloc");
		(void) sigsetmask(omask);
		return(ENOMEM);
	}
	/* set up */
	if (!(clist = (ZClientList_t *)xmalloc(sizeof(ZClientList_t)))) {
		xfree(hlist);
		(void) sigsetmask(omask);
		return(ENOMEM);
	}
	clist->q_forw = clist->q_back = clist;

	hlist->zh_clients = clist;
	hlist->zh_addr = *who;
	hlist->q_forw = hlist->q_back = hlist;
	hlist->zh_locked = 0;

	/* add to table */
	insert_host(hlist, server);

	/* chain in to the end of the list */
	xinsque(hlist, server->zs_hosts->q_back);
	(void) sigsetmask(omask);
	return(ZERR_NONE);
}

/*
 * detach the host at addr from the server
 * Warning: this routine assumes all the clients have already been removed
 * from this host.
 */

static void
host_detach(addr, server)
struct in_addr *addr;
ZServerDesc_t *server;
{
	/* undo what we did in host_attach */
	register ZHostList_t *hlist;
	int omask = sigblock(sigmask(SIGFPE)); /* don't start db dumps */

	if (hostm_find_server(addr) != server) {
		syslog(LOG_WARNING, "host_detach: wrong server");
		(void) sigsetmask(omask);
		return;
	}

	hlist = hostm_find_host(addr);

	/* all the clients have already been freed */
	xfree(hlist->zh_clients);

	/* unchain */
	xremque(hlist);

	/* remove from table */
	remove_host(hlist);

	xfree(hlist);
	(void) sigsetmask(omask);
	return;
}

/*
 * Send a shutdown message to the HostManager at sin, recommending him to
 * use server
 */

void
hostm_deathgram(sin, server)
struct sockaddr_in *sin;
ZServerDesc_t *server;
{
	Code_t retval;
	int shutlen;
	ZNotice_t shutnotice;
	ZPacket_t shutpack;

	zdbug((LOG_DEBUG,"deathgram %s",inet_ntoa(sin->sin_addr)));

	/* fill in the shutdown notice */

	shutnotice.z_kind = HMCTL;
	shutnotice.z_port = sock_sin.sin_port; /* we are sending it */
	shutnotice.z_class = HM_CTL_CLASS;
	shutnotice.z_class_inst = HM_CTL_SERVER;
	shutnotice.z_opcode = SERVER_SHUTDOWN;
	shutnotice.z_sender = HM_CTL_SERVER;
	shutnotice.z_recipient = "hm@ATHENA.MIT.EDU";
	shutnotice.z_default_format = "";
	
	if (server) {
		shutnotice.z_message = inet_ntoa(server->zs_addr.sin_addr);
		shutnotice.z_message_len = strlen(shutnotice.z_message);
		zdbug((LOG_DEBUG, "suggesting %s",shutnotice.z_message));
	} else {
		shutnotice.z_message = NULL;
		shutnotice.z_message_len = 0;
	}

	shutlen = sizeof(shutpack);
	if ((retval = ZFormatNotice(&shutnotice,
				    shutpack,
				    shutlen,
				    &shutlen,
				    ZNOAUTH)) != ZERR_NONE) {
		syslog(LOG_ERR, "hm_shut format: %s",error_message(retval));
		return;
	}
	if ((retval = ZSetDestAddr(sin)) != ZERR_NONE) {
		syslog(LOG_WARNING, "hm_shut set addr: %s",
		       error_message(retval));
		return;
	}
	if ((retval = ZSendPacket(shutpack, shutlen)) != ZERR_NONE) {
		syslog(LOG_WARNING, "hm_shut xmit: %s", error_message(retval));
		return;
	}
	return;
}

/*
 * Send a ping to the HostManager at sin
 */

static void
ping(sin)
struct sockaddr_in *sin;
{
	Code_t retval;
	int shutlen;
	ZNotice_t shutnotice;
	ZPacket_t shutpack;

	zdbug((LOG_DEBUG,"ping %s",inet_ntoa(sin->sin_addr)));

	/* fill in the shutdown notice */

	shutnotice.z_kind = HMCTL;
	shutnotice.z_port = sock_sin.sin_port;
	shutnotice.z_class = HM_CTL_CLASS;
	shutnotice.z_class_inst = HM_CTL_SERVER;
	shutnotice.z_opcode = SERVER_PING;
	shutnotice.z_sender = HM_CTL_SERVER;
	shutnotice.z_recipient = "hm@ATHENA.MIT.EDU";
	shutnotice.z_message = NULL;
	shutnotice.z_message_len = 0;
	shutnotice.z_default_format = "";
	
	shutlen = sizeof(shutpack);
	if ((retval = ZFormatNotice(&shutnotice,
				    shutpack,
				    shutlen,
				    &shutlen,
				    ZNOAUTH)) != ZERR_NONE) {
		syslog(LOG_ERR, "hm_ping format: %s",error_message(retval));
		return;
	}
	if ((retval = ZSetDestAddr(sin)) != ZERR_NONE) {
		syslog(LOG_WARNING, "hm_ping set addr: %s",
		       error_message(retval));
		return;
	}
	if ((retval = ZSendPacket(shutpack, shutlen)) != ZERR_NONE) {
		syslog(LOG_WARNING, "hm_ping xmit: %s", error_message(retval));
		return;
	}
	return;
}

/*
 * Routines for maintaining the host array.
 */

/*
 * Binary search on the host table to find this host.
 */

ZHostList_t *
hostm_find_host(addr)
struct in_addr *addr;
{
	register int i, rlo, rhi;

	if (!all_hosts)
		return(NULLZHLT);

	/* i is the current host we are checking */
	/* rlo is the lowest we will still check, rhi is the highest we will
	   still check */

	i = num_hosts >> 1;		/* start in the middle */
	rlo = 0;
	rhi = num_hosts - 1;		/* first index is 0 */

	while ((all_hosts[i].host)->zh_addr.sin_addr.s_addr != addr->s_addr) {
		if ((all_hosts[i].host)->zh_addr.sin_addr.s_addr < addr->s_addr)
			rlo = i + 1;
		else
			rhi = i - 1;
		if (rhi - rlo < 0)
			return(NULLZHLT);
		i = (rhi + rlo) >> 1; /* split the diff */
	}
	return(all_hosts[i].host);
}

/*
 * Binary search on the host table to find this host's server.
 */

ZServerDesc_t *
hostm_find_server(addr)
struct in_addr *addr;
{
	register int i, rlo, rhi;

	if (!all_hosts)
		return(NULLZSDT);

	/* i is the current host we are checking */
	/* rlo is the lowest we will still check, rhi is the highest we will
	   still check */

	i = num_hosts >> 1;		/* start in the middle */
	rlo = 0;
	rhi = num_hosts - 1;		/* first index is 0 */

	while ((all_hosts[i].host)->zh_addr.sin_addr.s_addr != addr->s_addr) {
		if ((all_hosts[i].host)->zh_addr.sin_addr.s_addr < addr->s_addr)
			rlo = i + 1;
		else
			rhi = i - 1;
		if (rhi - rlo < 0)
			return(NULLZSDT);
		i = (rhi + rlo) >> 1; /* split the diff */
	}
	return(&otherservers[all_hosts[i].server_index]);
}

/*
 * Insert the host and server into the sorted array of hosts.
 */

static void
insert_host(host, server)
ZHostList_t *host;
ZServerDesc_t *server;
{
	struct hostlist *oldlist;
	register int i = 0;
	int omask;

#ifdef DEBUG
	char buf[512];
	if (zdebug) {
		(void) strcpy(buf, inet_ntoa(host->zh_addr.sin_addr));
		syslog(LOG_DEBUG,"insert_host %s %s",
		       buf,
		       inet_ntoa(server->zs_addr.sin_addr));
	}
#endif DEBUG
	if (hostm_find_host(&host->zh_addr.sin_addr))
		return;

	omask = sigblock(sigmask(SIGFPE)); /* don't start db dumps */

	num_hosts++;
	oldlist = all_hosts;

	if (!(all_hosts = (struct hostlist *) xmalloc(num_hosts * sizeof(struct hostlist)))) {
		syslog(LOG_CRIT, "insert_host: nomem");
		abort();
	}

	if (!oldlist) {			/* this is the first */
		all_hosts[0].host = host;
		all_hosts[0].server_index = server - otherservers;
		(void) sigsetmask(omask);
		return;
	}

	/* copy old pointers */
	while ((i < (num_hosts - 1)) &&
	       ((oldlist[i].host)->zh_addr.sin_addr.s_addr < host->zh_addr.sin_addr.s_addr)) {
		all_hosts[i] = oldlist[i];
		i++;
	}
	/* add this one */
	all_hosts[i].host = host;
	all_hosts[i++].server_index = server - otherservers;

	/* copy the rest */
	while (i < num_hosts) {
		all_hosts[i] = oldlist[i - 1];
		i++;
	}
	xfree(oldlist);
	(void) sigsetmask(omask);
#ifdef DEBUG
        if (zdebug) {
                register int i = 0;
                char buf[512];
                for (i = 0; i < num_hosts; i++) {
                        (void) strcpy(buf,inet_ntoa((all_hosts[i].host)->zh_addr.sin_addr));
                        syslog(LOG_DEBUG, "%d: %s %s",i,buf,
                               inet_ntoa(otherservers[all_hosts[i].server_index].zs_addr.sin_addr));
                }
        }
#endif DEBUG
	return;
}

/*
 * remove the host from the array of known hosts.
 */

static void
remove_host(host)
ZHostList_t *host;
{
	struct hostlist *oldlist;
	register int i = 0;
	int omask;

	zdbug((LOG_DEBUG,"remove_host %s", inet_ntoa(host->zh_addr.sin_addr)));
	if (!hostm_find_host(&host->zh_addr.sin_addr))
		return;

	omask = sigblock(sigmask(SIGFPE)); /* don't start db dumps */
	if (--num_hosts == 0) {
		zdbug((LOG_DEBUG,"last host"));
		xfree(all_hosts);
		all_hosts = NULLHLT;
		(void) sigsetmask(omask);
		return;
	}

	oldlist = all_hosts;

	if (!(all_hosts = (struct hostlist *) xmalloc(num_hosts * sizeof(struct hostlist)))) {
		syslog(LOG_CRIT, "remove_host: nomem");
		abort();
	}

	/* copy old pointers */
	while (i < num_hosts && (oldlist[i].host)->zh_addr.sin_addr.s_addr < host->zh_addr.sin_addr.s_addr) {
		all_hosts[i] = oldlist[i];
		i++;
	}

	i++;				/* skip over this one */

	/* copy the rest */
	while (i <= num_hosts) {
		all_hosts[i - 1] = oldlist[i];
		i++;
	}
	xfree(oldlist);
	(void) sigsetmask(omask);
	return;
}

/*
 * Assumes that SIGFPE is blocked when called; this is true if called from a
 * signal handler
 */

void
hostm_dump_hosts(fp)
FILE *fp;
{
	register int i;
	for (i = 0; i < num_hosts; i++) {
		(void) fprintf(fp, "%s/%d:\n", 
			       inet_ntoa((all_hosts[i].host)->zh_addr.sin_addr),
			       all_hosts[i].server_index);
		client_dump_clients(fp,(all_hosts[i].host)->zh_clients);
	}
	return;
}
