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
#define	NULLZHLTP	((ZHostList_t **) 0)
#define	NULLZSDTP	((ZServerDesc_t **) 0)

static ZHostList_t **all_hosts = NULLZHLTP;
static ZServerDesc_t **all_hosts_servers = NULLZSDTP;

static int num_hosts;			/* number of hosts in all_hosts */


static void host_detach(), flush(), deathgram(), insert_host(), remove_host();
static Code_t host_attach();

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
	char *opcode = notice->z_opcode;
	Code_t retval;

	if (!strcmp(opcode, HM_BOOT)) {
		if ((owner = hostm_find_server(&who->sin_addr)) == me_server) {
			zdbug1("hm_disp flushing");
			/* I own him.  Just cancel any subscriptions */
			flush(who, me_server);
		
		} else if (owner == NULLZSDT) {
			zdbug1("hm_disp acquiring");
			/* no owner.  Acquire him. */
			if ((retval = host_attach(who, me_server)) != ZERR_NONE)
				syslog(LOG_WARNING, "hattach failed: %s",
				       error_message(retval));
				return;
		} else {
			zdbug1("hm_disp hostm_flush'ing");
			/* He has switched servers.  Take him, then
			   tell the owner and other hosts to flush. */
			hostm_flush(hostm_find_host(&who->sin_addr), owner);
			/* XXX tell other servers */

			if ((retval = host_attach(who, me_server)) != ZERR_NONE)
				syslog(LOG_WARNING, "hattach failed: %s",
				       error_message(retval));
		}
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

	if (all_hosts == (ZHostList_t **) 0)
		return(NULLZHLT);

	/* i is the current host we are checking */
	/* rlo is the lowest we will still check, rhi is the highest we will
	   still check */

	i = num_hosts >> 1;		/* start in the middle */
	rlo = 0;
	rhi = num_hosts - 1;		/* first index is 0 */

	while (all_hosts[i]->zh_addr.sin_addr.s_addr != addr->s_addr) {
		if (all_hosts[i]->zh_addr.sin_addr.s_addr < addr->s_addr)
			rlo = i + 1;
		else
			rhi = i - 1;
		if (rhi - rlo < 0)
			return(NULLZHLT);
		i = (rhi + rlo) >> 1; /* split the diff */
	}
	return(all_hosts[i]);
}

ZServerDesc_t *
hostm_find_server(addr)
struct in_addr *addr;
{
	register int i, rlo, rhi;

	if (all_hosts == (ZHostList_t **) 0)
		return(NULLZSDT);

	/* i is the current host we are checking */
	/* rlo is the lowest we will still check, rhi is the highest we will
	   still check */

	i = num_hosts >> 1;		/* start in the middle */
	rlo = 0;
	rhi = num_hosts - 1;		/* first index is 0 */

	while (all_hosts[i]->zh_addr.sin_addr.s_addr != addr->s_addr) {
		if (all_hosts[i]->zh_addr.sin_addr.s_addr < addr->s_addr)
			rlo = i + 1;
		else
			rhi = i - 1;
		if (rhi - rlo < 0)
			return(NULLZSDT);
		i = (rhi + rlo) >> 1; /* split the diff */
	}
	return(all_hosts_servers[i]);
}

static void
insert_host(host, server)
ZHostList_t *host;
ZServerDesc_t *server;
{
	ZHostList_t **oldlist;
	ZServerDesc_t **oldservs;
	register int i = 0;

	if (hostm_find_host(&host->zh_addr.sin_addr) != NULLZHLT)
		return;

	num_hosts++;
	oldlist = all_hosts;
	oldservs = all_hosts_servers;

	if ((all_hosts = (ZHostList_t **) malloc(num_hosts * sizeof(ZHostList_t *))) == NULLZHLTP) {
		syslog(LOG_CRIT, "insert_host: nomem");
		abort();
	}

	if ((all_hosts_servers = (ZServerDesc_t **) malloc(num_hosts * sizeof(ZServerDesc_t *))) == NULLZSDTP) {
		syslog(LOG_CRIT, "insert_host: nomem servers");
		abort();
	}

	if (!oldlist) {			/* this is the first */
		all_hosts[0] = host;
		all_hosts_servers[0] = server;
		return;
	}

	/* copy old pointers */
	while (i < (num_hosts - 1) && oldlist[i]->zh_addr.sin_addr.s_addr < host->zh_addr.sin_addr.s_addr) {
		all_hosts[i] = oldlist[i];
		all_hosts_servers[i] = oldservs[i];
		i++;
	}

	/* add this one */
	all_hosts[i] = host;
	all_hosts_servers[i++] = server;

	/* copy the rest */
	while (i < num_hosts) {
		all_hosts[i] = oldlist[i - 1];
		all_hosts_servers[i] = oldservs[i - 1];
		i++;
	}
	free(oldlist);
	free(oldservs);
	return;
}

static void
remove_host(host)
ZHostList_t *host;
{
	ZHostList_t **oldlist;
	ZServerDesc_t **oldservs;
	register int i = 0;

	if (hostm_find_host(&host->zh_addr.sin_addr) == NULLZHLT)
		return;

	num_hosts--;
	oldlist = all_hosts;
	oldservs = all_hosts_servers;

	if ((all_hosts = (ZHostList_t **) malloc(num_hosts * sizeof(ZHostList_t *))) == NULLZHLTP) {
		syslog(LOG_CRIT, "remove_host: nomem");
		abort();
	}
	if ((all_hosts_servers = (ZServerDesc_t **) malloc(num_hosts * sizeof(ZServerDesc_t *))) == NULLZSDTP) {
		syslog(LOG_CRIT, "remove_host: nomem servers");
		abort();
	}

	/* copy old pointers */
	while (i < num_hosts && oldlist[i]->zh_addr.sin_addr.s_addr < host->zh_addr.sin_addr.s_addr) {
		all_hosts[i] = oldlist[i];
		all_hosts_servers[i] = oldservs[i];
		i++;
	}

	i++;				/* skip over this one */

	/* copy the rest */
	while (i < num_hosts) {
		all_hosts[i - 1] = oldlist[i];
		all_hosts_servers[i - 1] = oldservs[i];
		i++;
	}
	free(oldlist);
	free(oldservs);
	return;
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
	host_attach(who, server);
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
	if ((hlist = (ZHostList_t *)malloc(sizeof(ZHostList_t))) == NULLZHLT) {
		syslog(LOG_WARNING, "hm_attach malloc");
		return(ENOMEM);
	}
	/* set up */
	if ((clist = (ZClientList_t *)malloc(sizeof(ZClientList_t))) == NULLZCLT) {
		free(hlist);
		return(ENOMEM);
	}
	clist->q_forw = clist->q_back = clist;

	hlist->zh_clients = clist;
	hlist->zh_addr = *who;
	hlist->q_forw = hlist->q_back = hlist;

	/* chain in */
	insert_host(hlist, server);
	insque(hlist, server->zs_hosts);
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

	free(hlist->zh_clients);
	remque(hlist);
	remove_host(hlist);
	free(hlist);
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

	/* fill in the shutdown notice */

	shutnotice.z_kind = HMCTL;
	shutnotice.z_port = sock_sin.sin_port;
	shutnotice.z_class = HM_CLASS;
	shutnotice.z_class_inst = ZEPHYR_CTL_SERVER;
	shutnotice.z_opcode = SERVER_SHUTDOWN;
	shutnotice.z_sender = ZEPHYR_CTL_SERVER;
	shutnotice.z_recipient = ZEPHYR_CTL_HM;
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
