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
static char rcsid_server_s_c[] = "$Header$";
#endif lint

#include "zserver.h"

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
 * ZServerDesc_t *server_owner(who)
 *	struct sockaddl_in *who;
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

void
server_timo(which)
ZServerDesc_t *which;
{
	/* change state and reset if appropriate */
	switch(which->zs_state) {
	case SERV_DEAD:			/* leave him dead */
		server_flush(which);
		break;
	case SERV_UP:			/* he's now tardy */
		which->zs_state = SERV_TARDY;
		which->zs_numsent = 0;
		which->zs_timeout = TIMO_TARDY;
		break;
	case SERV_TARDY:
	case SERV_STARTING:
		if (which->zs_numsent >= ((which->zs_state == SERV_TARDY) ?
					  H_NUM_TARDY :
					  H_NUM_STARTING)) {
			/* he hasn't answered, assume DEAD */
			which->zs_state = SERV_DEAD;
			which->zs_numsent = 0;
			which->zs_timeout = TIMO_DEAD;
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
		bcopy (&notice->z_sender_addr, &newwho.sin_addr, sizeof (struct in_addr));
		newwho.sin_port = notice->z_port;
		control_handle(notice, auth, &newwho);
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

ZServerDesc_t *
server_owner(who)
struct sockaddr_in *who;
{
	register ZServerDesc_t *servs;
	register int i;
	register ZHostList_t *hlt;

	for (i = 0, servs = otherservers; i < nservers; i++, servs++ )
		/* for each server */
		for (hlt = servs->zs_hosts->q_forw;
		     hlt != servs->zs_hosts;
		     hlt = hlt->q_forw)
			/* for each host */
			if (!bcmp(&hlt->zh_addr, &who->sin_addr, sizeof(struct in_addr)))
				return(servs);
	/* unowned */
	return(NULLZSDT);
}
	
/* flush all data associated with the server which */
static void
server_flush(which)
register ZServerDesc_t *which;
{
	register ZHostList_t *hst;
	register ZClientList_t *clist = NULLZCLT, *clt;
	register int status;

	if (which->zs_hosts == NULLZHLT) /* no data to flush */
		return;

	for (hst = which->zs_hosts->q_forw;
	     hst != which->zs_hosts;
	     hst = which->zs_hosts->q_forw) {
		/* for each host, flush all data */

		remque(hst);		/* unlink */
		hst->q_forw = hst->q_back = hst; /* clean up */

		if ((status = subscr_cancel_host(&hst->zh_addr, which)) != ZERR_NONE)
			syslog(LOG_WARNING, "srv_flush: host cancel %s: %s",
			       inet_ntoa(hst->zh_addr),
			       error_message());

		clist = hst->zh_clients;

		for (clt = clist->q_forw; clt != clist; clt = clt->q_forw)
			/* client_deregister frees this client */
			if ((status = client_deregister(clt)) != ZERR_NONE)
				syslog(LOG_WARNING, "srv_flush: bad deregister: %s",
				       error_message(status));

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
	int packlen, tolen;
	Code_t retval;

	phelonotice = &hellonotice;

	phelonotice->z_kind = ACKED;

	phelonotice->z_checksum[0] = 0;	/* filled in by the library */
	phelonotice->z_checksum[1] = 0;

	phelonotice->z_uid.zuid_addr = my_addr;
	phelonotice->z_uid.tv.tv_sec = NOW;
	phelonotice->z_uid.tv.tv_usec = 0;
	phelonotice->z_port = sock_sin.sin_port;
	phelonotice->z_class = ZEPHYR_ADMIN_CLASS;
	phelonotice->z_class_inst = NULL;
	phelonotice->z_opcode = "HELLO";
	phelonotice->z_sender = myname;	/* myname is the hostname */
	phelonotice->z_recipient = NULL;
	phelonotice->z_message = (caddr_t) NULL;
	phelonotice->z_message_len = 0;

	packlen = sizeof(hellopack);
	
	if ((retval = ZFormatNotice(phelonotice, hellopack, packlen, &packlen)) != ZERR_NONE) {
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
