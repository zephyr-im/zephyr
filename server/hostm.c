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
 */

struct hostlist {
	ZHostList_t *host;
	ZServerDesc_t *server;
};

#define	NULLHLT		((struct hostlist *) 0)

static struct hostlist *all_hosts;

static int num_hosts;			/* number of hosts in all_hosts */


static void host_detach(), flush(), deathgram(), insert_host(), remove_host();
static Code_t host_attach();
static int cmp_hostlist();

/*
 * We received a HostManager packet.  process accordingly.
 */
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


	zdbug1("hm_disp");
	owner = hostm_find_server(&who->sin_addr);
	if (!strcmp(opcode, HM_BOOT)) {
		zdbug2("boot %s",inet_ntoa(who->sin_addr));
		if (owner == &otherservers[me_server_idx]) {
			zdbug1("hm_disp flushing");
			/* I own him.  Just cancel any subscriptions */
			flush(who, me_server);
		
		} else if (owner == NULLZSDT) {
			zdbug1("acquiring");
			/* no owner.  Acquire him. */
			if ((retval = host_attach(who, me_server)) != ZERR_NONE) {
				syslog(LOG_WARNING, "hattach failed: %s",
				       error_message(retval));
				return;
			}
		} else {
			zdbug1("hostm_flush'ing");
			/* He has switched servers.  Take him, then
			   tell the owner and other hosts to flush. */
			hostm_flush(hostm_find_host(&who->sin_addr), owner);
			/* XXX tell other servers */

			if ((retval = host_attach(who, me_server)) != ZERR_NONE)
				syslog(LOG_WARNING, "hattach failed: %s",
				       error_message(retval));
		}
		ack(notice, who);
	} else if (!strcmp(opcode, HM_FLUSH)) {
		zdbug2("hm_disp flush %s", inet_ntoa(who->sin_addr));
		if (owner == NULLZSDT || (host = hostm_find_host(&who->sin_addr)) == NULLZHLT)
			return;
		hostm_flush(host, owner);
		return;
	} else {
		syslog(LOG_WARNING, "hm_disp: unknown opcode %s",opcode);
		return;
	}
	return;
}

void
hostm_flush(host, server)
ZHostList_t *host;
ZServerDesc_t *server;
{
	register ZClientList_t *clist = NULLZCLT, *clt;

	zdbug1("hostm_flush");
	if ((clist = host->zh_clients) != NULLZCLT)
		for (clt = clist->q_forw; clt != clist; clt = clist->q_forw)
			/* client_deregister frees this client & subscriptions */
			/* and remque()s the client */
			client_deregister(clt->zclt_client, host);

	uloc_hflush(&host->zh_addr);
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

	zdbug1("hostm_shutdown");
	if (hosts == NULLZHLT)
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
 * Binary search on the host table to find this host.
 */

ZHostList_t *
hostm_find_host(addr)
struct in_addr *addr;
{
	register int i, rlo, rhi;

	if (all_hosts == NULLHLT)
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

ZServerDesc_t *
hostm_find_server(addr)
struct in_addr *addr;
{
	register int i, rlo, rhi;

	if (all_hosts == NULLHLT)
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

static void
insert_host(host, server)
ZHostList_t *host;
ZServerDesc_t *server;
{
	struct hostlist *oldlist;
	register int i = 0;

	zdbug2("insert_host %s",inet_ntoa(host->zh_addr.sin_addr));

	if (hostm_find_host(&host->zh_addr.sin_addr) != NULLZHLT)
		return;

	num_hosts++;
	oldlist = all_hosts;

	if (!oldlist) {			/* this is the first */
		if ((all_hosts = (struct hostlist *) xmalloc(num_hosts * sizeof(struct hostlist))) == NULLHLT) {
			syslog(LOG_CRIT, "insert_host: nomem");
			abort();
		}
		all_hosts[0].host = host;
		all_hosts[0].server = server;
		return;
	}

	if ((all_hosts = (struct hostlist *) realloc((caddr_t) oldlist, (unsigned) num_hosts * sizeof(struct hostlist))) == NULLHLT) {
		syslog(LOG_CRIT, "insert_host: nomem");
		abort();
	}

	all_hosts[num_hosts - 1].host = host;
	all_hosts[num_hosts - 1].server = server;

	/* sort it */

	qsort((caddr_t) all_hosts, num_hosts, sizeof(struct hostlist), cmp_hostlist);

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

static void
remove_host(host)
ZHostList_t *host;
{
	struct hostlist *oldlist;
	register int i = 0;

	zdbug1("remove_host");
	if (hostm_find_host(&host->zh_addr.sin_addr) == NULLZHLT)
		return;

	if (--num_hosts == 0) {
		zdbug1("last host");
		xfree(all_hosts);
		all_hosts = NULLHLT;
		return;
	}

	oldlist = all_hosts;

	if ((all_hosts = (struct hostlist *) xmalloc(num_hosts * sizeof(struct hostlist))) == NULLHLT) {
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

	zdbug2("flush %s",inet_ntoa(who->sin_addr));

	for (hlp2 = hlp->q_forw; hlp2 != hlp; hlp2 = hlp2->q_forw) {
		if (hlp2->zh_addr.sin_addr.s_addr == who->sin_addr.s_addr)
			/* already here */
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
	if ((hlist = (ZHostList_t *)xmalloc(sizeof(ZHostList_t))) == NULLZHLT) {
		syslog(LOG_WARNING, "hm_attach malloc");
		return(ENOMEM);
	}
	/* set up */
	if ((clist = (ZClientList_t *)xmalloc(sizeof(ZClientList_t))) == NULLZCLT) {
		xfree(hlist);
		return(ENOMEM);
	}
	clist->q_forw = clist->q_back = clist;

	hlist->zh_clients = clist;
	hlist->zh_addr = *who;
	hlist->q_forw = hlist->q_back = hlist;

	/* chain in */
	insert_host(hlist, server);
	xinsque(hlist, server->zs_hosts);
	return(ZERR_NONE);
}

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

	xfree(hlist->zh_clients);
	xremque(hlist);
	remove_host(hlist);
	xfree(hlist);
	return;
}

static void
deathgram(sin)
struct sockaddr_in *sin;
{
	Code_t retval;
	int shutlen;
	ZNotice_t shutnotice;
	ZPacket_t shutpack;

	zdbug2("deathgram %s",inet_ntoa(sin->sin_addr));

	/* fill in the shutdown notice */

	shutnotice.z_kind = HMCTL;
	shutnotice.z_port = sock_sin.sin_port;
	shutnotice.z_class = HM_CTL_CLASS;
	shutnotice.z_class_inst = HM_CTL_SERVER;
	shutnotice.z_opcode = SERVER_SHUTDOWN;
	shutnotice.z_sender = HM_CTL_SERVER;
	shutnotice.z_recipient = "foo";
	shutnotice.z_message = NULL;
	shutnotice.z_message_len = 0;
	
	shutlen = sizeof(shutpack);
	if ((retval = ZFormatNotice(&shutnotice, shutpack, shutlen, &shutlen, 0)) != ZERR_NONE) {
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
