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
static char rcsid_client_s_c[] = "$Header$";
#endif lint
/*
 * External functions:
 *
 * Code_t client_register(notice, client, server)
 * ZNotice_t *notice;
 * ZClient_t **client; (RETURN)
 * ZServerDesc_t *server;
 *
 * Code_t client_deregister(client)
 * ZClient_t *client;
 *
 * ZClient_t *client_which_client(notice)
 * ZNotice_t *notice;
 */

#include "zserver.h"

/*
 * register a client: allocate space, find or insert the address in the
 * 	server's list of hosts, initialize and insert the client into
 *	the host's list of clients.
 *
 * This routine assumes that the client has not been registered yet.
 * The caller should check by calling client_which_client
 */
Code_t
client_register(notice, client, server)
ZNotice_t *notice;
register ZClient_t **client;		/* RETURN */
ZServerDesc_t *server;
{
	register ZHostList_t *hlp = server->zs_hosts;
	register ZHostList_t *hlp2;
	register ZClientList_t *clist, *clist2;

	/* allocate a client struct */
	if ((*client = (ZClient_t *) malloc(sizeof(ZClient_t))) == NULLZCNT)
		return(ENOMEM);

	/* chain the client's host onto this server's host list */

	if (!hlp)			/* bad host list */
		return(EINVAL);

	for (hlp2 = hlp->q_forw; hlp2 != hlp; hlp2 = hlp2->q_forw) {
		if (bcmp(&hlp2->zh_addr, &notice->z_sender_addr, sizeof(struct in_addr)))
			/* already here */
			break;
	}
	if (hlp2 == hlp) {		/* not here */
		if (!(hlp2 = (ZHostList_t *) malloc(sizeof(ZHostList_t)))) {
			free(*client);
			return(ENOMEM);
		}
		hlp2->zh_addr = notice->z_sender_addr;
		hlp2->zh_clients = NULLZCLT;
		insque(hlp2, hlp);
	}

	/* hlp2 is now pointing to the client's host's address struct */

	if ((clist = hlp2->zh_clients) == NULLZCLT) {
		/* doesn't already have a client on this ip addr */
		if ((clist2 = (ZClientList_t *)malloc(sizeof(ZClientList_t))) == NULLZCLT) {
			free(*client);
			return(ENOMEM);
		}
		clist2->q_forw = clist2->q_back = clist;

		hlp2->zh_clients = clist2;
	}

	if ((clist = (ZClientList_t *)malloc(sizeof(ZClientList_t))) == NULLZCLT) {
		free(*client);
		return(ENOMEM);
	}

	clist->q_forw = clist->q_back = clist;
	clist->zclt_client = *client;

	/* initialize the struct */
	bzero(&(*client)->zct_sin, sizeof(struct sockaddr_in));
	(*client)->zct_sin.sin_port = notice->z_port;
	(*client)->zct_sin.sin_addr = notice->z_sender_addr;
	(*client)->zct_subs = NULLZST;

	/* chain him in */

	insque(clist2, clist);

	return(ZERR_NONE);
}

/*
 * Deregister the client, freeing resources.
 */

Code_t
client_deregister(client)
ZClient_t *client;
{
}

ZClient_t *
client_which_client(notice)
ZNotice_t *notice;
{
}
