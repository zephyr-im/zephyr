/* This file is part of the Project Athena Zephyr Notification System.
 * It contains functions for the Client Manager subsystem of the Zephyr server.
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
static char rcsid_client_s_c[] = "$Header$";
#endif SABER
#endif lint

/*
 * External functions:
 *
 * Code_t client_register(notice, who, client, server)
 *	ZNotice_t *notice;
 *	struct sockaddr_in *who;
 *	ZClient_t **client; (RETURN)
 *	ZServerDesc_t *server;
 *
 * Code_t client_deregister(client, host)
 *	ZClient_t *client;
 *	ZHostList_t *host;
 *
 * ZClient_t *client_which_client(who, notice)
 *	struct sockaddr_in *who;
 *	ZNotice_t *notice;
 */

#include "zserver.h"
#include <sys/socket.h>

static void clt_free();

/*
 * register a client: allocate space, find or insert the address in the
 * 	server's list of hosts, initialize and insert the client into
 *	the host's list of clients.
 *
 * This routine assumes that the client has not been registered yet.
 * The caller should check by calling client_which_client
 */

Code_t
client_register(notice, who, client, server)
ZNotice_t *notice;
struct sockaddr_in *who;
register ZClient_t **client;		/* RETURN */
ZServerDesc_t *server;
{
	register ZHostList_t *hlp = server->zs_hosts;
	register ZHostList_t *hlp2;
	register ZClientList_t *clist;

	/* chain the client's host onto this server's host list */

	if (!hlp) {			/* bad host list */
		syslog(LOG_ERR, "cl_register: bad server host list");
		abort();
	}

	if (!(hlp2 = hostm_find_host(&who->sin_addr))) {
		/* not here */
		return(ZSRV_HNOTFOUND);
	}

	/* hlp2 is now pointing to the client's host's address struct */

	if (!hlp2->zh_clients) {
		return(EINVAL);
	}

	/* allocate a client struct */
	if (!(*client = (ZClient_t *) xmalloc(sizeof(ZClient_t))))
		return(ENOMEM);

	if (!(clist = (ZClientList_t *) xmalloc(sizeof(ZClientList_t)))) {
		xfree(*client);
		return(ENOMEM);
	}

	clist->q_forw = clist->q_back = clist;
	clist->zclt_client = *client;

	/* initialize the struct */
	bzero((caddr_t) &(*client)->zct_sin, sizeof(struct sockaddr_in));
	(*client)->zct_sin.sin_addr.s_addr = who->sin_addr.s_addr;
	(*client)->zct_sin.sin_port = notice->z_port;
	(*client)->zct_sin.sin_family = AF_INET;
	(*client)->zct_subs = NULLZST;
	(*client)->zct_subs = NULLZST;
	(*client)->zct_principal = strsave(notice->z_sender);

	/* chain him in to the clients list in the host list*/

	xinsque(clist, hlp2->zh_clients);

	return(ZERR_NONE);
}

/*
 * Deregister the client, freeing resources.  
 * Remove any packets in the nack queue, release subscriptions, and
 * dequeue him from the host.
 */

void
client_deregister(client, host)
ZClient_t *client;
ZHostList_t *host;
{
	ZClientList_t *clients;

	/* release any not-acked packets in the rexmit queue */
	nack_release(client);

	/* release subscriptions */
	(void) subscr_cancel_client(client);

	/* unthread and release this client */

	if (host->zh_clients)
		for (clients = host->zh_clients->q_forw;
		     clients != host->zh_clients;
		     clients = clients->q_forw)
			if (clients->zclt_client == client) {
				xremque(clients);
				clt_free(client);
				xfree(clients);
				return;
			}
	syslog(LOG_CRIT, "clt_dereg: clt not in host list");
	abort();
	/*NOTREACHED*/
}

/*
 * find the client which sent the notice
 */

ZClient_t *
client_which_client(who, notice)
struct sockaddr_in *who;
ZNotice_t *notice;
{
	register ZHostList_t *hlt;
	register ZClientList_t *clients;

	if (!(hlt = hostm_find_host(&who->sin_addr))) {
		zdbug((LOG_DEBUG,"cl_wh_clt: host not found"));
		return(NULLZCNT);
	}

	if (!hlt->zh_clients) {
		zdbug((LOG_DEBUG,"cl_wh_clt: no clients"));
		return(NULLZCNT);
	}

	for (clients = hlt->zh_clients->q_forw;
	     clients != hlt->zh_clients;
	     clients = clients->q_forw)
		if (clients->zclt_client->zct_sin.sin_port == notice->z_port) {
			return(clients->zclt_client);
		}

	zdbug((LOG_DEBUG, "cl_wh_clt: no port"));
	return(NULLZCNT);
}

/*
 * Free storage in use by client
 */

static void
clt_free(client)
ZClient_t *client;
{
	xfree(client->zct_principal);
	xfree(client);
}
