/* This file is part of the Project Athena Zephyr Notification System.
 * It contains functions for dispatching a notice.
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
static char rcsid_dispatch_c[] = "$Header$";
#endif lint

#include "zserver.h"

/*
 *
 * External Routines:
 *
 * void dispatch(notice, auth)
 *	ZNotice_t *notice;
 *	int auth;
 *
 * void clt_ack(notice, who, sent)
 *	ZNotice_t *notice;
 *	struct sockaddr_in *who;
 *	ZSentType sent;
 *
 */

static void xmit(), rexmit();
static int is_server();

int num_rexmits = NUM_REXMITS;		/* patchable... */
long rexmit_secs = REXMIT_SECS;

/*
 * Dispatch a notice.
 */
void
dispatch(notice, auth, who)
ZNotice_t *notice;
int auth;
struct sockaddr_in *who;
{
	register ZClientList_t *clientlist, *ptr;
	int acked = 0;

	if (is_server(who)) {
		server_dispatch(notice, auth, who);
		return;
	}
	if (class_is_control(notice)) {
		control_handle(notice, auth, who);
		return;
	} else if (class_is_admin(notice)) {
		/* this had better be a HELLO message--start of acquisition
		   protocol */
		syslog(LOG_INFO, "disp: new server?");
		if (server_register(notice, who) != ZERR_NONE)
			syslog(LOG_INFO, "new server failed");
		else
			syslog(LOG_INFO, "new server %s, %d",
			       inet_ntoa(who->sin_addr),
			       ntohs(who->sin_port));
		return;
	} else if (class_is_restricted(notice) &&
		   !access_check(notice, XMIT)) {
		syslog(LOG_WARNING, "disp unauthorized %s", notice->z_class);
		return;
	}
	
	/* oh well, do the dirty work */
	if ((clientlist = subscr_match_list(notice)) == NULLZCLT) {
		clt_ack(notice, who, NOT_SENT);
		return;
	}
	for (ptr = clientlist->q_forw; ptr != clientlist; ptr = ptr->q_forw) {
		/* for each client who gets this notice,
		   send it along */
		xmit(notice, ptr->zclt_client);
		if (!acked) {
			acked = 1;
			clt_ack(notice, who, SENT);
		}
	}
	if (!acked)
		clt_ack(notice, who, NOT_SENT);
}

/*
 * Is this from a server?
 */
static int
is_server(who)
struct sockaddr_in *who;
{
	register ZServerDesc_t *servs;
	register int num;

	if (who->sin_port != sock_sin.sin_port)
		return(0);
		
	/* just look over the server list */
	for (servs = otherservers, num = 0; num < nservers; num++, servs++)
		if (!bcmp(&servs->zs_addr.sin_addr, who->sin_addr,
			  sizeof(struct in_addr)))
			return(1);
	return(0);
}
/*
 * Send the notice to the client.  After transmitting, put it onto the
 * not ack'ed list.
 */

static void
xmit(notice, client)
register ZNotice_t *notice;
ZClient_t *client;
{
	ZPacket_t *noticepack;
	register ZNotAcked_t *nack;
	int packlen;
	Code_t retval;

	if ((noticepack = (ZPacket_t *) malloc(sizeof(ZPacket_t))) == NULLZPT){
		syslog(LOG_ERR, "xmit malloc");
		return;			/* DON'T put on nack list */
	}

	packlen = sizeof(ZPacket_t);

	if ((retval = ZFormatNotice(notice, noticepack, packlen, &packlen)) != ZERR_NONE) {
		syslog(LOG_ERR, "xmit format: %s", error_message(retval));
		return;			/* DON'T put on nack list */
	}
	if ((retval = ZSetDestAddr(&client->zct_sin)) != ZERR_NONE) {
		syslog(LOG_WARNING, "xmit set addr: %s",
		       error_message(retval));
		return;
	}
	if ((retval = ZSendPacket(noticepack, packlen)) != ZERR_NONE) {
		syslog(LOG_WARNING, "xmit xmit: %s", error_message(retval));
		return;
	}

	/* now we've sent it, mark it as not ack'ed */

	if ((nack = (ZNotAcked_t *)malloc(sizeof(ZNotAcked_t))) == NULLZNAT) {
		/* no space: just punt */
		syslog(LOG_WARNING, "xmit nack malloc");
		return;
	}

	nack->na_rexmits = 0;
	nack->na_packet = noticepack;
	nack->na_client = client;

	/* chain in */
	insque(nacklist, nack);

	/* set a timer */
	nack->na_timer = timer_set_rel (rexmit_secs, rexmit, (caddr_t) nack);
}

static void
rexmit(nackpacket)
register ZNotAcked_t *nackpacket;
{
	ZClient_t *client;
	int retval;

	if (++(nackpacket->na_rexmits) > num_rexmits) {
		/* possibly dead client */
		/* remove timer */
		timer_reset(nackpacket->na_timer);
		/* unlink & free packet */
		remque(nackpacket);
		free(nackpacket->na_packet);
		client = nackpacket->na_client;
		free(nackpacket);

		/* initiate recovery */
		server_recover(client);
		return;
	}

	/* retransmit the packet */
	
	if ((retval = ZSetDestAddr(&nackpacket->na_client->zct_sin)) != ZERR_NONE) {
		syslog(LOG_WARNING, "rexmit set addr: %s",
		       error_message(retval));
		return;
	}
	if ((retval = ZSendPacket(nackpacket->na_packet,
				  nackpacket->na_packsz)) != ZERR_NONE)
		syslog(LOG_WARNING, "rexmit xmit: %s", error_message(retval));

	return;

}

void
clt_ack(notice, who, sent)
ZNotice_t *notice;
struct sockaddr_in *who;
ZSentType sent;
{
	ZNotice_t acknotice;
	ZPacket_t ackpack;
	int packlen;
	Code_t retval;

	acknotice = *notice;

	acknotice.z_kind = SERVACK;
	if (sent == SENT)
		acknotice.z_message = ZSRVACK_SENT;
	else
		acknotice.z_message = ZSRVACK_NOTSENT;

	/* Don't forget room for the null */
	acknotice.z_message_len = strlen(acknotice.z_message) + 1;

	packlen = sizeof(ackpack);

	if ((retval = ZFormatRawNotice(&acknotice, ackpack, packlen, &packlen)) != ZERR_NONE) {
		syslog(LOG_ERR, "clt_ack format: %s",error_message(retval));
		return;
	}
	if ((retval = ZSetDestAddr(who)) != ZERR_NONE) {
		syslog(LOG_WARNING, "clt_ack set addr: %s",
		       error_message(retval));
		return;
	}
	if ((retval = ZSendPacket(ackpack, packlen)) != ZERR_NONE) {
		syslog(LOG_WARNING, "clt_ack xmit: %s", error_message(retval));
		return;
	}
	return;
}
