/* This file is part of the Project Athena Zephyr Notification System.
 * It contains functions for communication with other servers.
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
static char rcsid_server_s_c[] = "$Header$";
#endif SABER
#endif lint

#include "zserver.h"
#include <sys/socket.h>			/* for AF_INET */

/*
 * Server manager.  Deal with  traffic to and from other servers.
 *
 * void server_timo(which)
 * 	ZServerDesc_t *which;
 *
 * void server_dispatch(notice, auth, who)
 *	ZNotice_t *notice;
 * 	int auth;
 *	struct sockaddr_in *who;
 *
 * Code_t server_register(notice, who)
 *	ZNotice_t *notice;
 *	struct sockaddr_in *who;
 *
 * void server_recover(client)
 *	ZClient_t *client;
 *
 */

static void server_hello(), server_flush(), admin_handle();

/* 
 * A server timout has expired.  If enough hello's have been unanswered,
 * change state and act accordingly. Send a "hello" and reset the timer,
 * incrementing the number of hello's sent.
 *
 * See the FSM in the Zephyr document for a better picture of what's
 * happening here. 
 */

int timo_up = TIMO_UP;
int timo_tardy = TIMO_TARDY;
int timo_dead = TIMO_DEAD;

void
server_timo(which)
ZServerDesc_t *which;
{
	zdbug2("srv_timo: %s", inet_ntoa(which->zs_addr.sin_addr));
	/* change state and reset if appropriate */
	switch(which->zs_state) {
	case SERV_DEAD:			/* leave him dead */
		server_flush(which);
		break;
	case SERV_UP:			/* he's now tardy */
		which->zs_state = SERV_TARDY;
		which->zs_numsent = 0;
		which->zs_timeout = timo_tardy;
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
			server_flush(which);
		}
		break;
	default:
		syslog(LOG_ERR,"Bad server state, server 0x%x\n",which);
		abort();
	}
	/* now he's either TARDY, STARTING, or DEAD
	   We send a "hello," which increments the counter */
	server_hello(which);
	/* reschedule the timer */
	which->zs_timer = timer_set_rel(which->zs_timeout, server_timo,
					(caddr_t) which);
}

/*
 * Deal with incoming data on the socket
 */

void
server_dispatch(notice, auth, who)
ZNotice_t *notice;
int auth;
struct sockaddr_in *who;
{
	struct sockaddr_in newwho;
	if (class_is_admin(notice))
		admin_handle(notice, auth);
	else if (class_is_control(notice)) {
		/* XXX set up a who for the real origin */
		newwho.sin_family = AF_INET;
/* XXX wait till robby fixes this
		newwho.sin_addr.s_addr = notice->z_sender_addr.s_addr;
*/
		newwho.sin_port = notice->z_port;
		control_dispatch(notice, auth, &newwho);
	} else
		/* shouldn't come from another server */
		syslog(LOG_WARNING, "srv_disp: pkt cls %s",notice->z_class);
	return;
}

Code_t
server_register(notice, who)
ZNotice_t *notice;
struct sockaddr_in *who;
{
	return(1);
}

void
server_recover(client)
ZClient_t *client;
{
	ZHostList_t *host;

	zdbug1("server recover");
	/* XXX */
	if ((host = hostm_find_host(&client->zct_sin.sin_addr)) != NULLZHLT)
		client_deregister(client, host);
	else
		syslog(LOG_ERR, "srv_recover: no host for client");
	return;
}
/* flush all data associated with the server which */
static void
server_flush(which)
register ZServerDesc_t *which;
{
	register ZHostList_t *hst;

	if (which->zs_hosts == NULLZHLT) /* no data to flush */
		return;

	for (hst = which->zs_hosts->q_forw;
	     hst != which->zs_hosts;
	     hst = which->zs_hosts->q_forw) {
		/* for each host, flush all data */
		hostm_flush(hst, which);
	}

}

/* send a hello to which, updating the count of hello's sent */

static void
server_hello(which)
ZServerDesc_t *which;
{
	ZNotice_t hellonotice;
	register ZNotice_t *phelonotice; /* speed hack */
	ZPacket_t hellopack;
	int packlen;
	Code_t retval;

	phelonotice = &hellonotice;

	phelonotice->z_kind = ACKED;

	phelonotice->z_port = sock_sin.sin_port;
	phelonotice->z_class = ZEPHYR_ADMIN_CLASS;
	phelonotice->z_class_inst = "RUthere";
	phelonotice->z_opcode = "HELLO";
	phelonotice->z_sender = myname;	/* myname is the hostname */
	phelonotice->z_recipient = "you";
	phelonotice->z_message = (caddr_t) NULL;
	phelonotice->z_message_len = 0;

	packlen = sizeof(hellopack);
	
	/* hello's are not authenticated (overhead not needed) */
	if ((retval = ZFormatNotice(phelonotice, hellopack, packlen, &packlen, 0)) != ZERR_NONE) {
		syslog(LOG_WARNING, "hello format: %s", error_message(retval));
		return;
	}
	if ((retval = ZSetDestAddr(&which->zs_addr)) != ZERR_NONE) {
		syslog(LOG_WARNING, "hello set addr: %s",
		       error_message(retval));
		return;
	}
	if ((retval = ZSendPacket(hellopack, packlen)) != ZERR_NONE) {
		syslog(LOG_WARNING, "hello xmit: %s", error_message(retval));
		return;
	}
	(which->zs_numsent)++;
	return;
}

static void
admin_handle(notice, auth)
ZNotice_t *notice;
int auth;
{
	syslog(LOG_INFO, "ADMIN received\n");
	return;
}
