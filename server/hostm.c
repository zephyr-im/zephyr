/* This file is part of the Project Athena Zephyr Notification System.
 * It contains functions for communicating with the HostManager.
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
static char rcsid_hostm_s_c[] = "$Header$";
#endif SABER
#endif lint

#include "zserver.h"

/*
 *
 * External functions:
 *
 * void hostm_dispatch(notice, auth, who)
 *	ZNotice_t *notice;
 *	int auth;
 *	struct sockaddr_in *who;
 *
 * void hostm_flush(host)
 *	ZHostList_t *host;
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
	ZHostList_t *host;
	ZServerDesc_t *server;
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

static int num_hosts;			/* number of hosts in all_hosts */
static long lose_timo = LOSE_TIMO;

static losinghost *losing_hosts = NULLLH; /* queue of pings for hosts we
					     doubt are really there */

static void host_detach(), flush(), deathgram(), insert_host(), remove_host();
static void host_not_losing(), host_lost(), ping();
static Code_t host_attach();
static int cmp_hostlist();

/*
 * We received a HostManager packet.  process accordingly.
 */

/*ARGSUSED*/
void
hostm_dispatch(notice, auth, who)
ZNotice_t *notice;
int auth;
struct sockaddr_in *who;
{
	ZServerDesc_t *owner;
	ZHostList_t *host;
	char *opcode = notice->z_opcode;
	Code_t retval;


	zdbug((LOG_DEBUG,"hm_disp"));
	if (notice->z_kind == HMACK) {
		host_not_losing(who);
		return;
	}
	owner = hostm_find_server(&who->sin_addr);
	if (!strcmp(opcode, HM_BOOT)) {
		zdbug((LOG_DEBUG,"boot %s",inet_ntoa(who->sin_addr)));
		if (owner == &otherservers[me_server_idx]) {
			zdbug((LOG_DEBUG,"hm_disp flushing"));
			/* I own him.  Just cancel any subscriptions */
			flush(who, me_server);
		
		} else if (!owner) {
			zdbug((LOG_DEBUG,"acquiring"));
			/* no owner.  Acquire him. */
			if ((retval = host_attach(who, me_server))
			    != ZERR_NONE) {
				syslog(LOG_WARNING, "hattach failed: %s",
				       error_message(retval));
				return;
			}
		} else {
			zdbug((LOG_DEBUG,"hostm_flush'ing"));
			/* He has switched servers.  Take him, then
			   tell the owner and other hosts to flush. */
			hostm_flush(hostm_find_host(&who->sin_addr), owner);
			/* XXX tell other servers */

			if ((retval = host_attach(who, me_server))
			    != ZERR_NONE)
				syslog(LOG_WARNING, "hattach failed: %s",
				       error_message(retval));
		}
		ack(notice, who);
	} else if (!strcmp(opcode, HM_FLUSH)) {
		zdbug((LOG_DEBUG,"hm_disp flush %s", inet_ntoa(who->sin_addr)));
		if (!owner ||
		    !(host = hostm_find_host(&who->sin_addr)))
			return;
		hostm_flush(host, owner);
		return;
	} else {
		syslog(LOG_WARNING, "hm_disp: unknown opcode %s",opcode);
		return;
	}
	return;
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
		for (clt = clist->q_forw; clt != clist; clt = clist->q_forw)
			/* client_deregister frees this client & subscriptions
			   and remque()s the client */
			client_deregister(clt->zclt_client, host);

	uloc_hflush(&host->zh_addr.sin_addr);
	host_detach(&host->zh_addr.sin_addr, server);
	/* XXX tell other servers */
	return;
}

/*
 * send a shutdown to each of our hosts, then tell the other servers
 */

void
hostm_shutdown()
{
	register ZHostList_t *hosts = otherservers[me_server_idx].zs_hosts;
	register ZHostList_t *host;

	zdbug((LOG_DEBUG,"hostm_shutdown"));
	if (!hosts)
		return;

	/* kill them all */
	for (host = hosts->q_forw;
	     host != hosts;
	     host = host->q_forw)
		deathgram(&host->zh_addr);
	
	/* XXX tell other servers */

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

	zdbug((LOG_DEBUG,"lost host %s",
	       inet_ntoa(which->lh_host->zh_addr.sin_addr)));

	if (!(server = hostm_find_server(&which->lh_host->zh_addr.sin_addr))) {
		zdbug((LOG_DEBUG,"no server"));
		xremque(which);
		xfree(which);
		return;
	}
	xremque(which);
	hostm_flush(which->lh_host, server);
	xfree(which);

	/* XXX tell other servers */
	return;
}

/*
 * The host responded to the ping, so we flush any clients on this host.
 */

static void
host_not_losing(who)
struct sockaddr_in *who;
{
	losinghost *lhp, *lhp2;

	if (!losing_hosts)
		return;
	for (lhp = losing_hosts->q_forw;
	     lhp != losing_hosts;)
		if (lhp->lh_host->zh_addr.sin_addr.s_addr == who->sin_addr.s_addr) {
			/* go back, since remque will change things */
			lhp2 = lhp->q_back;
			timer_reset(lhp->lh_timer);
			zdbug((LOG_DEBUG,"lost client %s/%d",
			       inet_ntoa(lhp->lh_client->zct_sin.sin_addr),
			       ntohs(lhp->lh_client->zct_sin.sin_port)));
			client_deregister(lhp->lh_client, lhp->lh_host);
			xremque(lhp);
			xfree(lhp);
			/* now that the remque adjusted the linked list,
			   we go forward again */
			lhp = lhp2->q_forw;
		} else
			lhp = lhp->q_forw;
}


/*
 * Flush the info for this host, but maintain ownership.
 */

static void
flush(who, server)
struct sockaddr_in *who;
ZServerDesc_t *server;
{
	register ZHostList_t *hlp = server->zs_hosts;
	register ZHostList_t *hlp2;
	Code_t retval;

	zdbug((LOG_DEBUG,"flush %s",inet_ntoa(who->sin_addr)));

	for (hlp2 = hlp->q_forw; hlp2 != hlp; hlp2 = hlp2->q_forw) {
		if (hlp2->zh_addr.sin_addr.s_addr == who->sin_addr.s_addr)
			/* here he is */
			break;
	}
	if (hlp2 == hlp) {		/* not here */
		syslog(LOG_WARNING, "(h)flush: wrong server");
		return;
	}
	hostm_flush(hlp2, server);
	if ((retval = host_attach(who, server)) != ZERR_NONE)
		syslog(LOG_ERR, "flush h_attach: %s",
		       error_message(retval));
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

	/* allocate a header */
	if (!(hlist = (ZHostList_t *)xmalloc(sizeof(ZHostList_t)))) {
		syslog(LOG_WARNING, "hm_attach malloc");
		return(ENOMEM);
	}
	/* set up */
	if (!(clist = (ZClientList_t *)xmalloc(sizeof(ZClientList_t)))) {
		xfree(hlist);
		return(ENOMEM);
	}
	clist->q_forw = clist->q_back = clist;

	hlist->zh_clients = clist;
	hlist->zh_addr = *who;
	hlist->q_forw = hlist->q_back = hlist;

	/* add to table */
	insert_host(hlist, server);

	/* chain in */
	xinsque(hlist, server->zs_hosts);
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

	for (hlist = server->zs_hosts->q_forw;
	     hlist != server->zs_hosts;
	     hlist = hlist->q_forw)
		if (hlist->zh_addr.sin_addr.s_addr == addr->s_addr)
			/* found him */
			break;
	if (hlist == server->zs_hosts) {
		syslog(LOG_WARNING, "host_detach: wrong server");
		return;
	}

	/* all the clients have already been freed */
	xfree(hlist->zh_clients);

	/* unchain */
	xremque(hlist);

	/* remove from table */
	remove_host(hlist);

	xfree(hlist);
	return;
}

/*
 * Send a shutdown message to the HostManager at sin
 */

static void
deathgram(sin)
struct sockaddr_in *sin;
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
	shutnotice.z_message = NULL;
	shutnotice.z_message_len = 0;
	
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
	return(all_hosts[i].server);
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

	zdbug((LOG_DEBUG,"insert_host %s",inet_ntoa(host->zh_addr.sin_addr)));

	if (hostm_find_host(&host->zh_addr.sin_addr))
		return;

	num_hosts++;
	oldlist = all_hosts;

	if (!oldlist) {			/* this is the first */
		if (!(all_hosts = (struct hostlist *) xmalloc(num_hosts * sizeof(struct hostlist)))) {
			syslog(LOG_CRIT, "insert_host: nomem");
			abort();
		}
		all_hosts[0].host = host;
		all_hosts[0].server = server;
		return;
	}

	if (!(all_hosts = (struct hostlist *) realloc((caddr_t) oldlist, (unsigned) num_hosts * sizeof(struct hostlist)))) {
		syslog(LOG_CRIT, "insert_host: nomem");
		abort();
	}

	all_hosts[num_hosts - 1].host = host;
	all_hosts[num_hosts - 1].server = server;

	/* sort it */

	qsort((caddr_t) all_hosts, num_hosts, sizeof(struct hostlist), cmp_hostlist);

#ifdef DEBUG
	if (zdebug) {
		register int i = 0;
		char buf[512];
		for (i = 0; i < num_hosts; i++)
			syslog(LOG_DEBUG, "%d: %s %s",i,
			       strcpy(buf,inet_ntoa((all_hosts[i].host)->zh_addr.sin_addr)),
			       inet_ntoa((all_hosts[i].server)->zs_addr.sin_addr));
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

	zdbug((LOG_DEBUG,"remove_host"));
	if (!hostm_find_host(&host->zh_addr.sin_addr))
		return;

	if (--num_hosts == 0) {
		zdbug((LOG_DEBUG,"last host"));
		xfree(all_hosts);
		all_hosts = NULLHLT;
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
#ifdef DEBUG
	if (zdebug) {
		char buf[512];
		for (i = 0; i < num_hosts; i++)
			syslog(LOG_DEBUG, "%d: %s %s",i,
			       strcpy(buf,inet_ntoa((all_hosts[i].host)->zh_addr.sin_addr)),
			       inet_ntoa((all_hosts[i].server)->zs_addr.sin_addr));
	}
#endif DEBUG
	return;
}

/*
 * routine for qsort().
 *
 * return -1, 0, 1 if the IP address of the host el1 is <, = or > the IP
 * address of the host el2
 */

static int
cmp_hostlist(el1, el2)
struct hostlist *el1, *el2;
{
	if (el1->host->zh_addr.sin_addr.s_addr <
	    el2->host->zh_addr.sin_addr.s_addr) return (-1);
	else if (el1->host->zh_addr.sin_addr.s_addr ==
		 el2->host->zh_addr.sin_addr.s_addr) return (0);
	else return(1);
}
