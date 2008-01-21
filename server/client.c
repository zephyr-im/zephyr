/* This file is part of the Project Athena Zephyr Notification System.
 * It contains functions for the Client Manager subsystem of the Zephyr server.
 *
 *	Created by:	John T. Kohl
 *
 *	$Id$
 *
 *	Copyright (c) 1987,1988,1991 by the Massachusetts Institute of Technology.
 *	For copying and distribution information, see the file
 *	"mit-copyright.h". 
 */

#include <zephyr/mit-copyright.h>
#include "zserver.h"
#include <sys/socket.h>

#if !defined (lint) && !defined (SABER)
static const char rcsid_client_c[] =
"$Id$";
#endif

/*
 * External functions:
 *
 * Code_t client_register(notice, who, client, server, wantdefaults)
 *	ZNotice_t *notice;
 *	struct sockaddr_in *who;
 *	Client **client; (RETURN)
 *	Server *server;
 *	int wantdefaults;
 *
 * Code_t client_deregister(client, host, flush)
 *	Client *client;
 *	Host *host;
 *	int flush;
 *
 * Client *client_find(who, unsigned int port)
 *	struct in_addr *host;
 *	unsigned int port;
 *
 * void client_dump_clients(fp, clist)
 *	FILE *fp;
 *	Client *clist;
 */

/*
 * a client: allocate space, find or insert the address in the
 * 	server's list of hosts, initialize and insert the client into
 *	the host's list of clients.
 *
 * This routine assumes that the client has not been registered yet.
 * The caller should check by calling client_find.
 */

#define HASHSIZE 1024
static Client *client_bucket[HASHSIZE];

#define INET_HASH(host, port) ((htonl((host)->s_addr) + \
				htons((unsigned short) (port))) % HASHSIZE)

Code_t
client_register(ZNotice_t *notice,
		struct in_addr *host,
		Client **client_p,
		int wantdefaults)
{
    Client *client;

    /* chain the client's host onto this server's host list */

#if 1
    zdbug((LOG_DEBUG, "client_register: adding %s at %s/%d",
	   notice->z_sender, inet_ntoa(*host), ntohs(notice->z_port)));
#endif

    if (!notice->z_port)
	return ZSRV_BADSUBPORT;

    *client_p = client = client_find(host, notice->z_port);
    if (!client) {
	*client_p = client = (Client *) malloc(sizeof(Client));
	if (!client)
	    return ENOMEM;
	memset(&client->addr, 0, sizeof(struct sockaddr_in));
#ifdef HAVE_KRB5
        client->session_keyblock = NULL;
#else
#ifdef HAVE_KRB4
	memset(&client->session_key, 0, sizeof(client->session_key));
#endif
#endif
	client->last_send = 0;
	client->last_ack = NOW;
	client->addr.sin_family = AF_INET;
	client->addr.sin_addr.s_addr = host->s_addr;
	client->addr.sin_port = notice->z_port;
	client->subs = NULL;
	client->realm = NULL;
	client->principal = make_string(notice->z_sender, 0);
	Client_insert(&client_bucket[INET_HASH(&client->addr.sin_addr,
					       notice->z_port)], client);
    }

    /* Add default subscriptions only if this is not resulting from a brain
     * dump, AND this request wants defaults. */
    if (!bdumping && wantdefaults)
	return subscr_def_subs(client);
    else
	return ZERR_NONE;
}

/*
 * Deregister the client, freeing resources.  
 * Remove any packets in the nack queue, release subscriptions, release
 * locations, and dequeue him from the host.
 */

void
client_deregister(Client *client,
		  int flush)
{
    Client_delete(client);
    nack_release(client);
    subscr_cancel_client(client);
    free_string(client->principal);
#ifdef HAVE_KRB5
    if (client->session_keyblock)
         krb5_free_keyblock(Z_krb5_ctx, client->session_keyblock);
#endif
    if (flush)
	uloc_flush_client(&client->addr);
    free(client);
}

void
client_flush_host(struct in_addr *host)
{
    int i;
    Client *client, *next;

    for (i = 0; i < HASHSIZE; i++) {
	for (client = client_bucket[i]; client; client = next) {
	    next = client->next;
	    if (client->addr.sin_addr.s_addr == host->s_addr)
		client_deregister(client, 1);
	}
    }
    uloc_hflush(host);
}

Code_t
client_send_clients(void)
{
    int i;
    Client *client;
    Code_t retval;

    for (i = 0; i < HASHSIZE; i++) {
	/* Allow packets to be processed between rows of the hash table. */
	if (packets_waiting()) {
	    bdumping = 0;
	    bdump_concurrent = 1;
	    handle_packet();
	    bdump_concurrent = 0;
	    bdumping = 1;
	}
	for (client = client_bucket[i]; client; client = client->next) {
	    if (client->subs) {
		retval = subscr_send_subs(client);
		if (retval != ZERR_NONE)
		    return retval;
	    }
	}
    }
    return ZERR_NONE;
}

/*
 * dump info about clients in this clist onto the fp.
 * assumed to be called with SIGFPE blocked
 * (true if called from signal handler)
 */

void
client_dump_clients(FILE *fp)
{
    Client *client;
    int i;

    for (i = 0; i < HASHSIZE; i++) {
	for (client = client_bucket[i]; client; client = client->next) {
	    fprintf(fp, "%s/%d (%s):\n", inet_ntoa(client->addr.sin_addr),
		    ntohs(client->addr.sin_port), client->principal->string);
	    subscr_dump_subs(fp, client->subs);
	}
    }
}

/*
 * find a client by host and port
 */

Client *
client_find(struct in_addr *host,
	    unsigned int port)
{
    Client *client;
    long hashval;

    hashval = INET_HASH(host, port);
    for (client = client_bucket[hashval]; client; client = client->next) {
	if (client->addr.sin_addr.s_addr == host->s_addr
	    && client->addr.sin_port == port)
	    return client;
    }
    return NULL;
}

