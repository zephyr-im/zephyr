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
static char rcsid_hostm_c[] = "$Header$";
#endif
#endif

#include "zserver.h"
#include <sys/socket.h>			/* for AF_INET */

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

static void host_detach(register ZHostList_t *host, ZServerDesc_t *server),
    insert_host(ZHostList_t *host, ZServerDesc_t *server),
    remove_host(ZHostList_t *host);
static void host_not_losing(struct sockaddr_in *who),
    host_lost(void *which),
    ping(struct sockaddr_in *sin);
static Code_t host_attach(struct sockaddr_in *who, ZServerDesc_t *server);

/*
 * We received a HostManager packet.  process accordingly.
 */

/*ARGSUSED*/
Code_t
hostm_dispatch(ZNotice_t *notice, int auth, struct sockaddr_in *who, ZServerDesc_t *server)
{
	ZServerDesc_t *owner;
	ZHostList_t *host = NULLZHLT;
	char *opcode = notice->z_opcode;
	Code_t retval;

#if 0
	zdbug((LOG_DEBUG,"hm_disp"));
#endif

	host = hostm_find_host(&who->sin_addr);
	if (host && host->zh_locked)
		return(ZSRV_REQUEUE);

	if (notice->z_kind == HMACK) {
		host_not_losing(who);
		return(ZERR_NONE);
	} else if (notice->z_kind != HMCTL) {
#if 0
		zdbug((LOG_DEBUG, "bogus HM packet"));
#endif
		clt_ack(notice, who, AUTH_FAILED);
		return(ZERR_NONE);
	}
	owner = hostm_find_server(&who->sin_addr);
	if (!strcmp(opcode, HM_ATTACH)) {
#if 0
		zdbug((LOG_DEBUG,"attach %s",inet_ntoa(who->sin_addr)));
#endif
		if (owner == server) {
#if 0
			zdbug((LOG_DEBUG,"no change"));
#endif
			/* Same server owns him.  do nothing */
		} else if (owner) {
			/* He has switched servers.
			   he was lost but has asked server to work for him.
			   We need to transfer him to server */
#if 0
			zdbug((LOG_DEBUG,"hm_disp transfer"));
#endif
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
#if 0
		zdbug((LOG_DEBUG, "boot %s",inet_ntoa(who->sin_addr)));
#endif
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
#if 0
		zdbug((LOG_DEBUG, "hm_flush %s",inet_ntoa(who->sin_addr)));
#endif
		if (!owner)
			return(ZERR_NONE);
		/* flush him */
		hostm_flush(host, owner);
		if (server == me_server)
			server_forward(notice, auth, who);
	} else if (!strcmp(opcode, HM_DETACH)) {
#if 0
		zdbug((LOG_DEBUG, "hm_detach %s",inet_ntoa(who->sin_addr)));
#endif
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
 * The caller is responsible for informing other servers of this flush
 * (if appropriate).
 */

void
hostm_flush(ZHostList_t *host, ZServerDesc_t *server)
{
	register ZClientList_t *clist = NULLZCLT, *clt;
	losinghost *lhp, *lhp2;
	int omask = sigblock(sigmask(SIGFPE)); /* don't let db dumps start */

	if (!host) {
	    syslog(LOG_WARNING, "null host flush");
	    return;
	}

#if 0
	zdbug((LOG_DEBUG,"hostm_flush"));
#endif

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
#if 0
			if (zdebug)
				syslog(LOG_DEBUG, "hostm_flush clt_dereg");
#endif
			client_deregister(clt->zclt_client, host, 1);
		}

	uloc_hflush(&host->zh_addr.sin_addr);
	host_detach(host, server);
	(void) sigsetmask(omask);
	return;
}

/*
 * send a shutdown to each of our hosts
 */

void
hostm_shutdown(void)
{
	register ZHostList_t *hosts = otherservers[me_server_idx].zs_hosts;
	register ZHostList_t *host;
	int newserver, i;

#if 0
	zdbug((LOG_DEBUG,"hostm_shutdown"));
#endif
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
hostm_losing(ZClient_t *client, ZHostList_t *host)
{
	losinghost *newhost;

#if 0
	zdbug((LOG_DEBUG,"losing host"));
#endif
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
#if 0
			zdbug((LOG_DEBUG,"clt already losing"));
#endif
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
host_lost(void* arg)
{
	losinghost *which = (losinghost *) arg;
	ZServerDesc_t *server;
	ZNotice_t notice;
	struct sockaddr_in who;
	Code_t retval;
	char *buffer;
	int len;

	int omask = sigblock(sigmask(SIGFPE)); /* don't start db dumps */

#if 0
	zdbug((LOG_DEBUG,"lost host %s",
	       inet_ntoa(which->lh_host->zh_addr.sin_addr)));
#endif

	if (!(server = hostm_find_server(&which->lh_host->zh_addr.sin_addr))) {
#if 0
		zdbug((LOG_DEBUG,"no server"));
#endif
		xremque(which);
		xfree(which);
		(void) sigsetmask(omask);
		return;
	}
	xremque(which);
	hostm_flush(which->lh_host, server);

	bzero((caddr_t)&notice, sizeof(notice));

	/* tell other servers to flush this host */
	notice.z_kind = HMCTL;
	notice.z_auth = 0;
	notice.z_port = hm_port;
	notice.z_class = ZEPHYR_CTL_CLASS;
	notice.z_class_inst = ZEPHYR_CTL_HM;
	notice.z_opcode = HM_FLUSH;
	notice.z_sender = "HM";
	notice.z_recipient = "";
	notice.z_default_format = "";
	notice.z_num_other_fields = 0;
	notice.z_message_len = 0;

	/* generate the other fields */
	retval = ZFormatNotice(&notice, &buffer, &len, ZNOAUTH);
	if (retval != ZERR_NONE)
	    return;
	xfree(buffer);

	/* forge a from address */
	bzero((char *) &who, sizeof(who));
	who.sin_addr.s_addr = which->lh_host->zh_addr.sin_addr.s_addr;
	who.sin_port = hm_port;
	who.sin_family = AF_INET;

	server_forward(&notice, 0, &who); /* unauthentic */

	xfree(which);
	(void) sigsetmask(omask);
	return;
}

/*
 * The host responded to the ping, so we flush the losing clients on this host.
 */

static void
host_not_losing(struct sockaddr_in *who)
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
#if 0
			zdbug((LOG_DEBUG,"lost client %s/%d",
			       inet_ntoa(lhp->lh_client->zct_sin.sin_addr),
			       ntohs(lhp->lh_client->zct_sin.sin_port)));
#endif
			/* deregister all subscriptions, and flush locations
			   associated with the client. */
#if 0
			if (zdebug)
				syslog(LOG_DEBUG,"h_not_lose clt_dereg");
#endif
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
 * A client is being de-registered, so remove it from the losing_host list,
 * if it is there.
 */

void
hostm_lose_ignore(ZClient_t *client)
{
	losinghost *lhp, *lhp2;
	int omask;
	if (!losing_hosts)
		return;

	omask = sigblock(sigmask(SIGFPE)); /* don't start db dumps */
	for (lhp = losing_hosts->q_forw;
	     lhp != losing_hosts;)
		/* if client matches, remove it */
		if (lhp->lh_client == client) {
			/* go back, since remque will change things */
			lhp2 = lhp->q_back;
			timer_reset(lhp->lh_timer);
#if 0
			zdbug((LOG_DEBUG,"hm_l_ign client %s/%d",
			       inet_ntoa(client->zct_sin.sin_addr),
			       ntohs(client->zct_sin.sin_port)));
#endif
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
hostm_transfer(ZHostList_t *host, ZServerDesc_t *server)
{
	int omask;

	/* we need to unlink and relink him, and change the table entry */

#if 0
	zdbug((LOG_DEBUG, "hostm_transfer 0x%x to 0x%x", host, server));
#endif

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
host_attach(struct sockaddr_in *who, ZServerDesc_t *server)
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
host_detach(register ZHostList_t *host, ZServerDesc_t *server)
{
	/* undo what we did in host_attach */
	int omask = sigblock(sigmask(SIGFPE)); /* don't start db dumps */

	if (hostm_find_server(&host->zh_addr.sin_addr) != server) {
		syslog(LOG_WARNING, "host_detach: wrong server");
		(void) sigsetmask(omask);
		return;
	}


	/* all the clients have already been freed */
	xfree(host->zh_clients);

	/* unchain */
	xremque(host);

	/* remove from table */
	remove_host(host);

	xfree(host);
	(void) sigsetmask(omask);
	return;
}

/*
 * Send a shutdown message to the HostManager at sin, recommending him to
 * use server
 */

void
hostm_deathgram(struct sockaddr_in *sin, ZServerDesc_t *server)
{
	Code_t retval;
	int shutlen;
	ZNotice_t shutnotice;
	char *shutpack;

#if 0
	zdbug((LOG_DEBUG,"deathgram %s",inet_ntoa(sin->sin_addr)));
#endif

	/* fill in the shutdown notice */

	shutnotice.z_kind = HMCTL;
	shutnotice.z_port = sock_sin.sin_port; /* we are sending it */
	shutnotice.z_class = HM_CTL_CLASS;
	shutnotice.z_class_inst = HM_CTL_SERVER;
	shutnotice.z_opcode = SERVER_SHUTDOWN;
	shutnotice.z_sender = HM_CTL_SERVER;
	shutnotice.z_recipient = "hm@ATHENA.MIT.EDU";
	shutnotice.z_default_format = "";
	shutnotice.z_num_other_fields = 0;

	if (server) {
		shutnotice.z_message = inet_ntoa(server->zs_addr.sin_addr);
		shutnotice.z_message_len = strlen(shutnotice.z_message) + 1;
#if 0
		zdbug((LOG_DEBUG, "suggesting %s",shutnotice.z_message));
#endif
	} else {
		shutnotice.z_message = NULL;
		shutnotice.z_message_len = 0;
	}

	if ((retval = ZFormatNotice(&shutnotice,
				    &shutpack,
				    &shutlen,
				    ZNOAUTH)) != ZERR_NONE) {
		syslog(LOG_ERR, "hm_shut format: %s",error_message(retval));
		return;
	}
	if ((retval = ZSetDestAddr(sin)) != ZERR_NONE) {
		syslog(LOG_WARNING, "hm_shut set addr: %s",
		       error_message(retval));
		xfree(shutpack);	/* free allocated storage */
		return;
	}
	/* don't wait for ack! */
	if ((retval = ZSendPacket(shutpack, shutlen, 0)) != ZERR_NONE) {
		syslog(LOG_WARNING, "hm_shut xmit: %s", error_message(retval));
		xfree(shutpack);	/* free allocated storage */
		return;
	}
	xfree(shutpack);		/* free allocated storage */
	return;
}

/*
 * Send a ping to the HostManager at sin
 */

static void
ping(struct sockaddr_in *sin)
{
	Code_t retval;
	int shutlen;
	ZNotice_t shutnotice;
	char *shutpack;

#if 0
	zdbug((LOG_DEBUG,"ping %s",inet_ntoa(sin->sin_addr)));
#endif

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
	shutnotice.z_num_other_fields = 0;

	if ((retval = ZFormatNotice(&shutnotice,
				    &shutpack,
				    &shutlen,
				    ZNOAUTH)) != ZERR_NONE) {
		syslog(LOG_ERR, "hm_ping format: %s",error_message(retval));
		return;
	}
	if ((retval = ZSetDestAddr(sin)) != ZERR_NONE) {
		syslog(LOG_WARNING, "hm_ping set addr: %s",
		       error_message(retval));
		xfree(shutpack);	/* free allocated storage */
		return;
	}
	/* don't wait for ack */
	if ((retval = ZSendPacket(shutpack, shutlen, 0)) != ZERR_NONE) {
		syslog(LOG_WARNING, "hm_ping xmit: %s", error_message(retval));
		xfree(shutpack);	/* free allocated storage */
		return;
	}
	xfree(shutpack);	/* free allocated storage */
	return;
}

/*
 * Routines for maintaining the host array.
 */

/*
 * Binary search on the host table to find this host.
 */

ZHostList_t *
hostm_find_host(struct in_addr *addr)
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
hostm_find_server(struct in_addr *addr)
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
insert_host(ZHostList_t *host, ZServerDesc_t *server)
{
	struct hostlist *oldlist;
	register int i = 0;
	int omask;

#if defined (DEBUG) && 0
	char buf[512];
	if (zdebug) {
		(void) strcpy(buf, inet_ntoa(host->zh_addr.sin_addr));
		syslog(LOG_DEBUG,"insert_host %s %s",
		       buf,
		       inet_ntoa(server->zs_addr.sin_addr));
	}
#endif
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
#if defined (DEBUG) && 0
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
remove_host(ZHostList_t *host)
{
	struct hostlist *oldlist;
	register int i = 0;
	int omask;

#if 0
	zdbug((LOG_DEBUG,"remove_host %s", inet_ntoa(host->zh_addr.sin_addr)));
#endif
	if (!hostm_find_host(&host->zh_addr.sin_addr))
		return;

	omask = sigblock(sigmask(SIGFPE)); /* don't start db dumps */
	if (--num_hosts == 0) {
#if 0
		zdbug((LOG_DEBUG,"last host"));
#endif
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
hostm_dump_hosts(FILE *fp)
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

/*
 * Readjust server-array indices according to the supplied new vector.
 */

void
hostm_renumber_servers (int *srv)
{
    int i;
    for (i = 0; i < num_hosts; i++) {
	int idx = srv[all_hosts[i].server_index];
	if (idx < 0) {
	    syslog (LOG_ERR, "hostm_renumber_servers error: [%d] = %d",
		    all_hosts[i].server_index, idx);
	    idx = 0;
	}
	all_hosts[i].server_index = idx;
    }
}
