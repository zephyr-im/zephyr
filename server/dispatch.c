/* This file is part of the Project Athena Zephyr Notification System.
 * It contains functions for dispatching a notice.
 *
 *	Created by:	John T. Kohl
 *
 *	$Source$
 *	$Author$
 *
 *	Copyright (c) 1987, 1991 by the Massachusetts Institute of Technology.
 *	For copying and distribution information, see the file
 *	"mit-copyright.h". 
 */

#include <zephyr/mit-copyright.h>

#ifndef lint
#ifndef SABER
static char rcsid_dispatch_c[] =
    "$Id$";
#endif
#endif

#include "zserver.h"
#include <sys/socket.h>

#ifdef DEBUG
Zconst char *ZNoticeKinds[9] = {"UNSAFE", "UNACKED", "ACKED", "HMACK",
				"HMCTL", "SERVACK", "SERVNAK", "CLIENTACK",
				"STAT"};
#endif
/*
 *
 * External Routines:
 *
 * void dispatch(notice, auth, who)
 *	ZNotice_t *notice;
 *	int auth;
 *	struct sockaddr_in *who;
 *
 * void clt_ack(notice, who, sent)
 *	ZNotice_t *notice;
 *	struct sockaddr_in *who;
 *	ZSentType sent;
 *
 * void nack_release(client)
 *	ZClient_t *client;
 *
 * void sendit(notice, auth, who)
 *	ZNotice_t *notice;
 *	int auth;
 *	struct sockaddr_in *who;
 *
 * void xmit(notice, dest, auth, client)
 *	ZNotice_t *notice;
 *	struct sockaddr_in *dest;
 *	int auth;
 *	ZClient_t *client;
 */


/* patchable magic numbers controlling the retransmission rate and count */
int num_rexmits = NUM_REXMITS;
long rexmit_secs = REXMIT_SECS;
long abs_timo = REXMIT_SECS*NUM_REXMITS + 10;

ZSTRING *class_control, *class_admin, *class_hm, *class_ulogin,
  *class_ulocate;

#ifdef __STDC__
# define        P(s) s
#else
# define P(s) ()
#endif

static void nack_cancel P((register ZNotice_t *, struct sockaddr_in *));
static void dispatch P((ZNotice_t *, int, struct sockaddr_in *, int));

#undef P

ZStatistic interserver_notices = {0, "inter-server notices"};
ZStatistic hm_packets = {0, "hostmanager packets"};
ZStatistic control_notices = {0, "client control notices"};
ZStatistic message_notices = {0, "message notices"};
ZStatistic login_notices = {0, "login notices"};
ZStatistic i_s_ctls = {0, "inter-server control notices"};
ZStatistic i_s_logins = {0, "inter-server login notices"};
ZStatistic i_s_admins = {0, "inter-server admin notices"};
ZStatistic i_s_locates = {0, "inter-server locate notices"};
ZStatistic locate_notices = {0, "locate notices"};
ZStatistic admin_notices = {0, "admin notices"};

static void
#ifdef __STDC__
dump_stats (void *arg)
#else
dump_stats (arg)
void *arg;
#endif
{
  syslog(LOG_INFO, "stats: %s: %d", hm_packets.str, hm_packets.val);
  syslog(LOG_INFO, "stats: %s: %d", control_notices.str,
	 control_notices.val);
  syslog(LOG_INFO, "stats: %s: %d", message_notices.str,
	 message_notices.val);
  syslog(LOG_INFO, "stats: %s: %d", login_notices.str,
	 login_notices.val);
  syslog(LOG_INFO, "stats: %s: %d", locate_notices.str,
	 locate_notices.val);
  syslog(LOG_INFO, "stats: %s: %d", admin_notices.str,
	 admin_notices.val);
  syslog(LOG_INFO, "stats: %s: %d", interserver_notices.str,
	 interserver_notices.val);
  syslog(LOG_INFO, "stats: %s: %d", i_s_ctls.str, i_s_ctls.val);
  syslog(LOG_INFO, "stats: %s: %d", i_s_logins.str, i_s_logins.val);
  syslog(LOG_INFO, "stats: %s: %d", i_s_admins.str, i_s_admins.val);
  syslog(LOG_INFO, "stats: %s: %d", i_s_locates.str, i_s_locates.val);
  /* log stuff once an hour */
  (void) timer_set_rel ((long) 6*60*60, dump_stats, arg);
}

/*
 * Handle an input packet.
 * Warning: this function may be called from within a brain dump.
 */

void
handle_packet()
{
	Code_t status;
	ZPacket_t input_packet;		/* from the network */
	ZNotice_t new_notice;		/* parsed from input_packet */
	int input_len;			/* len of packet */
	struct sockaddr_in input_sin;	/* Zconstructed for authent */
	struct sockaddr_in whoisit;	/* for holding peer's address */
	int authentic;			/* authentic flag */
	ZSrvPending_t *pending;		/* pending packet */
	ZHostList_t *host;		/* host ptr */
	int from_server;		/* packet is from another server */
#ifdef DEBUG
	static int first_time = 1;
#endif

#ifdef DEBUG
	/* Dump statistics five minutes after startup */
	if (first_time) {
	  first_time = 0;
	  (void) timer_set_rel (5*60, dump_stats, (void *) 0);
	}
#endif
	/* handle traffic */
				
	if (otherservers[me_server_idx].zs_update_queue) {
		/* something here for me; take care of it */
#if 1
	  zdbug((LOG_DEBUG, "internal queue process"));
#endif

   		pending = otherservers[me_server_idx].zs_update_queue->q_forw;
		host = hostm_find_host(&(pending->pend_who.sin_addr));
		if (host && host->zh_locked) {
			/* can't deal with it now. to preserve ordering,
			   we can't process other packets, esp. since we
			   may block since we don't really know if there
			   are things in the real queue. */
#if 1
			zdbug((LOG_DEBUG,"host %s is locked",
			       inet_ntoa(host->zh_addr.sin_addr)));
#endif
			return;
		}
		pending = server_dequeue(me_server); /* we can do it, remove */

		if ((status = ZParseNotice(pending->pend_packet,
					  pending->pend_len,
					  &new_notice)) != ZERR_NONE) {
			syslog(LOG_ERR,
			       "bad notice parse (%s): %s",
			       inet_ntoa(pending->pend_who.sin_addr),
			       error_message(status));
		} else
			dispatch(&new_notice, pending->pend_auth,
				 &pending->pend_who, 1);
		server_pending_free(pending);
		return;
	}
	/* 
	 * nothing in internal queue, go to the external library
	 * queue/socket
	 */
	if ((status = ZReceivePacket(input_packet,
				    &input_len,
				    &whoisit)) != ZERR_NONE) {
		syslog(LOG_ERR,
		       "bad packet receive: %s from %s",
		       error_message(status), inet_ntoa(whoisit.sin_addr));
		return;
	}
	npackets++;
	if ((status = ZParseNotice(input_packet,
				  input_len,
				  &new_notice)) != ZERR_NONE) {
		syslog(LOG_ERR,
		       "bad notice parse (%s): %s",
		       inet_ntoa(whoisit.sin_addr),
		       error_message(status));
		return;
	}
	if (server_which_server(&whoisit)) {
		/* we need to parse twice--once to get
		   the source addr, second to check
		   authentication */
		bzero((caddr_t) &input_sin,
		      sizeof(input_sin));
		input_sin.sin_addr.s_addr = new_notice.z_sender_addr.s_addr;
		input_sin.sin_port = new_notice.z_port;
		input_sin.sin_family = AF_INET;
		authentic = ZCheckAuthentication(&new_notice,
						 &input_sin);
		from_server = 1;
	} else {
		from_server = 0;
		authentic = ZCheckAuthentication(&new_notice,
						 &whoisit);
	}
	switch (authentic) {
	case ZAUTH_YES:
		authentic = 1;
		break;
	case ZAUTH_FAILED:
	case ZAUTH_NO:
	default:
		authentic = 0;
		break;
	}
	if (whoisit.sin_port != hm_port &&
	    strcasecmp (new_notice.z_class,ZEPHYR_ADMIN_CLASS) &&
	    whoisit.sin_port != sock_sin.sin_port &&
	    new_notice.z_kind != CLIENTACK) {
		syslog(LOG_ERR,
		       "bad port %s/%d",
		       inet_ntoa(whoisit.sin_addr),
		       ntohs(whoisit.sin_port));
		return;
	}
	message_notices.val++;
	dispatch(&new_notice, authentic, &whoisit, from_server);
	return;
}
/*
 * Dispatch a notice.
 */

static void
dispatch(notice, auth, who, from_server)
     ZNotice_t *notice;
     int auth;
     struct sockaddr_in *who;
     int from_server;
{
	Code_t status;
	ZSTRING *notice_class;
	struct sockaddr_in who2;
#ifdef DEBUG
	char dbg_buf[BUFSIZ];
#endif

	if ((int) notice->z_kind < (int) UNSAFE ||
	    (int) notice->z_kind > (int) CLIENTACK) {
		syslog(LOG_NOTICE, "bad notice kind 0x%x from %s",
		       (int) notice->z_kind,
		       inet_ntoa(who->sin_addr));
		return;
	}
#if 0
	if (zdebug) {
	    (void) sprintf (dbg_buf,
		    "disp:%s '%s' '%s' '%s' notice to '%s' from '%s' %s/%d/%d",
			ZNoticeKinds[(int) notice->z_kind],
			notice->z_class,
			notice->z_class_inst,
			notice->z_opcode,
			notice->z_recipient,
			notice->z_sender,
			inet_ntoa(who->sin_addr),
			ntohs(who->sin_port),
			    ntohs(notice->z_port));
	    syslog (LOG_DEBUG, "%s", dbg_buf);
	}
#endif

	if (notice->z_kind == CLIENTACK) {
		nack_cancel(notice, who);
		return;
	}

	who2 = *who;
#if 0
	if (0 && from_server) {
	    /* incorporate server_dispatch here */
	}
#endif
	notice_class = make_zstring(notice->z_class,1);

	if (from_server) {
	    interserver_notices.val++;
	    status = server_dispatch(notice, auth, who);
	} else if (class_is_hm(notice_class)) {
	    hm_packets.val++;
	    status = hostm_dispatch(notice, auth, who, me_server);
	} else if (class_is_control(notice_class)) {
	    control_notices.val++;
	    status = control_dispatch(notice, auth, who, me_server);
	} else if (class_is_ulogin(notice_class)) {
	    login_notices.val++;
	    status = ulogin_dispatch(notice, auth, who, me_server);
	} else if (class_is_ulocate(notice_class)) {
	    locate_notices.val++;
	    status = ulocate_dispatch(notice, auth, who, me_server);
	} else if (class_is_admin(notice_class)) {
	    admin_notices.val++;
	    status = server_adispatch(notice, auth, who, me_server);
	} else {
	    sendit (notice, auth, who);
	    free_zstring(notice_class);
	    return;
	}

	if (status == ZSRV_REQUEUE) {
#ifdef CONCURRENT
	    server_self_queue(notice, auth, who);
#else
	    syslog(LOG_ERR, "requeue while not concurr");
	    abort();
#endif
	}
	free_zstring(notice_class);
}

/*
 * Send a notice off to those clients who have subscribed to it.
 */

void
sendit(notice, auth, who)
     ZNotice_t *notice;
     int auth;
     struct sockaddr_in *who;
{
	int acked = 0;
	ZAcl_t *acl;
	register ZClientList_t *clientlist, *ptr;
	ZSTRING *z;

	z = make_zstring(notice->z_class,1);
	if ((acl = class_get_acl(z)) != NULLZACLT) {
	  free_zstring(z);
	    /* if controlled and not auth, fail */
	    if (!auth) {
		syslog(LOG_WARNING, "sendit unauthentic %s from %s",
		       notice->z_class, notice->z_sender);
		clt_ack(notice, who, AUTH_FAILED);
		return;
	    }
	    /* if not auth to transmit, fail */
	    if (!access_check(notice->z_sender, acl, TRANSMIT)) {
		syslog(LOG_WARNING, "sendit unauthorized %s from %s",
		       notice->z_class, notice->z_sender);
		clt_ack(notice, who, AUTH_FAILED);
		return;
	    }
	  /* sender != inst and not auth to send to others --> fail */
	  if ((strcmp (notice->z_sender, notice->z_class_inst)) &&
	      (!access_check(notice->z_sender, acl, INSTUID))) {
	    syslog(LOG_WARNING,
		   "sendit unauth uid %s %s.%s",
		   notice->z_sender,
		   notice->z_class,
		   notice->z_class_inst);
	    clt_ack(notice, who, AUTH_FAILED);
	    return;
	  }
	}
	if (bcmp(&notice->z_sender_addr.s_addr, &who->sin_addr.s_addr,
		 sizeof(notice->z_sender_addr.s_addr))) {
	    /* someone is playing games... */
	    /* inet_ntoa returns pointer to static area */
	    /* max size is 255.255.255.255 */
	    char buffer[16];
	    (void) strcpy(buffer, inet_ntoa(who->sin_addr));
	    if (!auth) {
		syslog(LOG_WARNING, "sendit unauthentic fake packet: claimed %s, real %s",
		       inet_ntoa(notice->z_sender_addr), buffer);
		clt_ack(notice, who, AUTH_FAILED);
		return;
	    }
	    if (ntohl(notice->z_sender_addr.s_addr) != 0) {
		syslog(LOG_WARNING, "sendit invalid address: claimed %s, real %s",
		       inet_ntoa(notice->z_sender_addr), buffer);
		clt_ack(notice, who, AUTH_FAILED);
		return;
	    }
	    syslog(LOG_WARNING, "sendit addr mismatch: claimed %s, real %s",
		   inet_ntoa(notice->z_sender_addr), buffer);
	}
	if ((clientlist = subscr_match_list(notice)) != NULLZCLT) {
		for (ptr = clientlist->q_forw;
		     ptr != clientlist;
		     ptr = ptr->q_forw) {
			/* for each client who gets this notice,
			   send it along */
			xmit(notice, &(ptr->zclt_client->zct_sin), auth,
			     ptr->zclt_client);
			if (!acked) {
				acked = 1;
				ack(notice, who);
			}
		}
		subscr_free_list(clientlist);
	}

	if (!acked)
		nack(notice, who);
}

/*
 * Clean up the not-yet-acked queue and release anything destined
 * for the client.
 */

void
nack_release(client)
     ZClient_t *client;
{
	register ZNotAcked_t *nacked, *nack2;

	/* search the not-yet-acked list for anything destined to him, and
	   flush it. */
	for (nacked = nacklist->q_forw;
	     nacked != nacklist;)
		if ((nacked->na_addr.sin_addr.s_addr == client->zct_sin.sin_addr.s_addr) &&
		     (nacked->na_addr.sin_port == client->zct_sin.sin_port)) {
			/* go back, since remque will change things */
			nack2 = nacked->q_back;
			timer_reset(nacked->na_timer);
			xremque(nacked);
			xfree(nacked->na_packet);
			xfree(nacked);
			/* now that the remque adjusted the linked list,
			   we go forward again */
			nacked = nack2->q_forw;
		} else
			nacked = nacked->q_forw;
	return;
}

/*
 * Send one packet of a fragmented message to a client.  After transmitting,
 * put it onto the not ack'ed list.
 */

/* the arguments must be the same as the arguments to Z_XmitFragment */
/*ARGSUSED*/
Code_t
xmit_frag(notice, buf, len, waitforack)
     ZNotice_t *notice;
     char *buf;
     int len;
     int waitforack;
{
	char *savebuf;
	register ZNotAcked_t *nacked;
	Code_t retval;

	if ((retval = ZSendPacket(buf, len, 0)) != ZERR_NONE) {
		syslog(LOG_WARNING, "xmit_frag send: %s",
		       error_message(retval));
		return(retval);
	}

	/* now we've sent it, mark it as not ack'ed */

	if (!(nacked = (ZNotAcked_t *)xmalloc(sizeof(ZNotAcked_t)))) {
		/* no space: just punt */
		syslog(LOG_WARNING, "xmit_frag nack malloc");
		return(ENOMEM);
	}

	if (!(savebuf = (char *)xmalloc(len))) {
		/* no space: just punt */
		syslog(LOG_WARNING, "xmit_frag pack malloc");
		return(ENOMEM);
	}

	(void) bcopy(buf, savebuf, len);

	nacked->na_rexmits = 0;
	nacked->na_packet = savebuf;
	nacked->na_srv_idx = 0;
	nacked->na_addr = ZGetDestAddr();
	nacked->na_packsz = len;
	nacked->na_uid = notice->z_uid;
	nacked->q_forw = nacked->q_back = nacked;
	nacked->na_abstimo = NOW + abs_timo;

	/* set a timer to retransmit when done */
	nacked->na_timer = timer_set_rel(rexmit_secs,
					 rexmit,
					 (void *) nacked);
	/* chain in */
	xinsque(nacked, nacklist);
	return(ZERR_NONE);
}

/*
 * Send the notice to the client.  After transmitting, put it onto the
 * not ack'ed list.
 */

void
xmit(notice, dest, auth, client)
     ZNotice_t *notice;
     struct sockaddr_in *dest;
     int auth;
     ZClient_t *client;
{
	caddr_t noticepack;
	register ZNotAcked_t *nacked;
	int packlen;
	Code_t retval;

#if 0
	zdbug((LOG_DEBUG,"xmit"));
#endif

	if (!(noticepack = (caddr_t) xmalloc(sizeof(ZPacket_t)))) {
		syslog(LOG_ERR, "xmit malloc");
		return;			/* DON'T put on nack list */
	}

	packlen = sizeof(ZPacket_t);

	if (auth && client) {		/*
					  we are distributing authentic and
					  we have a pointer to auth info
					 */
#ifdef KERBEROS

		if ((retval = ZFormatAuthenticNotice(notice,
						     noticepack,
						     packlen,
						     &packlen,
						     client->zct_cblock))
		    != ZERR_NONE) {
			syslog(LOG_ERR, "xmit auth format: %s",
			       error_message(retval));
			xfree(noticepack);
			return;
		}
#else /* !KERBEROS */
		notice->z_auth = 1;
		if ((retval = ZFormatSmallRawNotice(notice,
						    noticepack,
						    &packlen))
		    != ZERR_NONE) {
			syslog(LOG_ERR, "xmit auth/raw format: %s",
			       error_message(retval));
			xfree(noticepack);
			return;
		}
#endif /* KERBEROS */
	} else {
		notice->z_auth = 0;
		notice->z_authent_len = 0;
		notice->z_ascii_authent = (char *)"";
		if ((retval = ZFormatSmallRawNotice(notice,
						    noticepack,
						    &packlen)) != ZERR_NONE) {
			syslog(LOG_ERR, "xmit format: %s",
			       error_message(retval));
			xfree(noticepack);
			return;			/* DON'T put on nack list */
		}
	}
#if 0
	zdbug((LOG_DEBUG," to %s/%d",inet_ntoa(dest->sin_addr),
	       ntohs(dest->sin_port)));
#endif
	if ((retval = ZSetDestAddr(dest)) != ZERR_NONE) {
		syslog(LOG_WARNING, "xmit set addr: %s",
		       error_message(retval));
		xfree(noticepack);
		return;
	}
	if ((retval = ZSendPacket(noticepack, packlen, 0)) != ZERR_NONE) {
		syslog(LOG_WARNING, "xmit xmit: (%s/%d) %s",
		       inet_ntoa(dest->sin_addr), ntohs(dest->sin_port),
		       error_message(retval));
		xfree(noticepack);
		return;
	}

	/* now we've sent it, mark it as not ack'ed */

	if (!(nacked = (ZNotAcked_t *)xmalloc(sizeof(ZNotAcked_t)))) {
		/* no space: just punt */
		syslog(LOG_WARNING, "xmit nack malloc");
		xfree(noticepack);
		return;
	}

	nacked->na_rexmits = 0;
	nacked->na_packet = noticepack;
	nacked->na_srv_idx = 0;  /* XXX */
	nacked->na_addr = *dest;
	nacked->na_packsz = packlen;
	nacked->na_uid = notice->z_uid;
	nacked->q_forw = nacked->q_back = nacked;
	nacked->na_abstimo = NOW + abs_timo;

	/* set a timer to retransmit when done */
	nacked->na_timer = timer_set_rel(rexmit_secs,
					 rexmit,
					 (void *) nacked);
	/* chain in */
	xinsque(nacked, nacklist);

}


/*
 * Retransmit the packet specified.  If we have timed out or retransmitted
 * too many times, punt the packet and initiate the host recovery algorithm
 * Else, increment the count and re-send the notice packet.
 */

void
#ifdef __STDC__
rexmit(void *arg)
#else
rexmit(arg)
     void *arg;
#endif
{
	register ZNotAcked_t *nackpacket = (ZNotAcked_t*) arg;
	int retval;
	ZNotice_t dummy_notice;
	register ZClient_t *client;

#if 1
	zdbug((LOG_DEBUG,"rexmit"));
#endif

	if (++(nackpacket->na_rexmits) > num_rexmits ||
	    NOW > nackpacket->na_abstimo) {
		/* possibly dead client */

		dummy_notice.z_port = nackpacket->na_addr.sin_port;
		
		client = client_which_client(&nackpacket->na_addr,
					     &dummy_notice);

		/* unlink & free packet */
		xremque(nackpacket);
		xfree(nackpacket->na_packet);
		xfree(nackpacket);

		/* initiate recovery */
		if (client)
			server_recover(client);
		return;
	}

	/* retransmit the packet */
	
#if 0
	zdbug((LOG_DEBUG," to %s/%d",
	       inet_ntoa(nackpacket->na_addr.sin_addr),
	       ntohs(nackpacket->na_addr.sin_port)));
#endif
	if ((retval = ZSetDestAddr(&nackpacket->na_addr))
	    != ZERR_NONE) {
		syslog(LOG_WARNING, "rexmit set addr: %s",
		       error_message(retval));
		goto requeue;

	}
	if ((retval = ZSendPacket(nackpacket->na_packet,
				  nackpacket->na_packsz, 0)) != ZERR_NONE)
		syslog(LOG_WARNING, "rexmit xmit: %s", error_message(retval));

requeue:
	/* reset the timer */
	nackpacket->na_timer = timer_set_rel(rexmit_secs,
					     rexmit,
					     (void *) nackpacket);
	return;

}

/*
 * Send an acknowledgement to the sending client, by sending back the
 * header from the original notice with the z_kind field changed to either
 * SERVACK or SERVNAK, and the contents of the message either SENT or
 * NOT_SENT, depending on the value of the sent argument.
 */

void
clt_ack(notice, who, sent)
     ZNotice_t *notice;
     struct sockaddr_in *who;
     ZSentType sent;
{
	ZNotice_t acknotice;
	ZPacket_t ackpack;
	int packlen;
	int notme = 0;
	char *sent_name;
	Code_t retval;

	if (bdumping)	{		/* don't ack while dumping */
#if 1
		zdbug((LOG_DEBUG,"bdumping, no ack"));
#endif
		return;
	}

	acknotice = *notice;

	acknotice.z_kind = SERVACK;
	switch (sent) {
	case SENT:
		acknotice.z_message = ZSRVACK_SENT;
		sent_name = "sent";
		break;
	case NOT_FOUND:
		acknotice.z_message = ZSRVACK_FAIL;
		acknotice.z_kind = SERVNAK;
		sent_name = "fail";
		break;
	case AUTH_FAILED:
		acknotice.z_kind = SERVNAK;
		acknotice.z_message = ZSRVACK_NOTSENT;
		sent_name = "nak/not_sent";
		break;
	case NOT_SENT:
		acknotice.z_message = ZSRVACK_NOTSENT;
		sent_name = "not_sent";
		break;
	default:
		abort ();
	}

#if 0
	zdbug((LOG_DEBUG,"clt_ack type %s for %d to %s/%d",
	       sent_name,
	       ntohs(notice->z_port),
	       inet_ntoa(who->sin_addr),
	       ntohs(who->sin_port)));
#endif

	if (!server_which_server(who) &&
	    (hostm_find_server(&who->sin_addr) != me_server)) {
#if 0
		zdbug((LOG_DEBUG,"not me"));
#endif
		notme = 1;
	}

	acknotice.z_multinotice = "";

	/* leave room for the trailing null */
	acknotice.z_message_len = strlen(acknotice.z_message) + 1;

	packlen = sizeof(ackpack);

	if ((retval = ZFormatSmallRawNotice(&acknotice,
					    ackpack,
					    &packlen)) != ZERR_NONE) {
		syslog(LOG_ERR, "clt_ack format: %s",error_message(retval));
		return;
	}
	if ((retval = ZSetDestAddr(who)) != ZERR_NONE) {
		syslog(LOG_WARNING, "clt_ack set addr: %s",
		       error_message(retval));
		return;
	}
	if ((retval = ZSendPacket(ackpack, packlen, 0)) != ZERR_NONE) {
		syslog(LOG_WARNING, "clt_ack xmit: %s", error_message(retval));
		return;
	}
	else
	    zdbug ((LOG_DEBUG, "packet sent"));
	if (notme)
		hostm_deathgram(who, me_server);
	return;
}

/*
 * An ack has arrived.
 * remove the packet matching this notice from the not-yet-acked queue
 */

static void
nack_cancel(notice, who)
     register ZNotice_t *notice;
     struct sockaddr_in *who;
{
	register ZNotAcked_t *nacked;

	/* search the not-yet-acked list for this packet, and
	   flush it. */
#if 0
	zdbug((LOG_DEBUG, "nack_cancel: %s:%08X,%08X",
	       inet_ntoa (notice->z_uid.zuid_addr),
	       notice->z_uid.tv.tv_sec, notice->z_uid.tv.tv_usec));
#endif
	for (nacked = nacklist->q_forw;
	     nacked != nacklist;
	     nacked = nacked->q_forw)
		if ((nacked->na_addr.sin_addr.s_addr == who->sin_addr.s_addr) &&
		     (nacked->na_addr.sin_port == who->sin_port))
			if (ZCompareUID(&nacked->na_uid, &notice->z_uid)) {
				timer_reset(nacked->na_timer);
				xfree(nacked->na_packet);
				xremque(nacked);
				xfree(nacked);
				return;
			}
#if 1
	zdbug((LOG_DEBUG,"nack_cancel: nack not found %s:%08X,%08X",
	       inet_ntoa (notice->z_uid.zuid_addr),
	       notice->z_uid.tv.tv_sec, notice->z_uid.tv.tv_usec));
#endif
	return;
}

/* for compatibility when sending subscription information to old clients */
#ifdef OLD_COMPAT
#define	OLD_ZEPHYR_VERSION	"ZEPH0.0"
#endif /* OLD_COMPAT */

/*
 * Dispatch a ZEPHYR_CTL notice.
 */

Code_t
control_dispatch(notice, auth, who, server)
     ZNotice_t *notice;
     int auth;
     struct sockaddr_in *who;
     ZServerDesc_t *server;
{
	register char *opcode = notice->z_opcode;
	ZClient_t *client;
	ZHostList_t *host;
	Code_t retval;
	int wantdefs;

	/*
	 * ZEPHYR_CTL Opcodes expected are:
	 *	BOOT (inst HM): host has booted; flush data.
	 *	CLIENT_SUBSCRIBE: process with the subscription mananger.
	 *	CLIENT_UNSUBSCRIBE: ""
	 *	CLIENT_CANCELSUB:   ""
	 */

	zdbug ((LOG_DEBUG, "ctl_disp: opc=%s", opcode));

	if (!strcasecmp (notice->z_class_inst, ZEPHYR_CTL_HM))
		return(hostm_dispatch(notice, auth, who, server));
	else if (!strcmp (opcode, CLIENT_GIMMESUBS) ||
		 !strcmp (opcode, CLIENT_GIMMEDEFS)) {
		/* this special case is before the auth check so that
		   someone who has no subscriptions does NOT get a SERVNAK
		   but rather an empty list.  Note we must therefore
		   check authentication inside subscr_sendlist */
#ifdef OLD_COMPAT
		/* only acknowledge if *not* old version; the old version
		   acknowledges the packet with the reply */
		if (strcmp (notice->z_version, OLD_ZEPHYR_VERSION))
			ack(notice, who);
#else /* !OLD_COMPAT */
		ack(notice, who);
#endif /* OLD_COMPAT */
		subscr_sendlist(notice, auth, who);
		return(ZERR_NONE);
	} else if (!auth) {
#if 0
		zdbug((LOG_DEBUG,"unauth ctrl_disp"));
#endif
		if (server == me_server)
			clt_ack(notice, who, AUTH_FAILED);
		return(ZERR_NONE);
	}

	/* the rest of the expected opcodes modify state; check for
	   unlocked host first */
	host = hostm_find_host(&who->sin_addr);
	if (host && host->zh_locked)
		return(ZSRV_REQUEUE);

	wantdefs = strcmp (opcode, CLIENT_SUBSCRIBE_NODEFS);
	if (!wantdefs || !strcmp (opcode, CLIENT_SUBSCRIBE)) {
		/* subscription notice */
		if (!(client = client_which_client(who, notice))) {
			if ((retval = client_register(notice,
						      who,
						      &client,
						      server,
						      wantdefs)) != ZERR_NONE)
			{
				syslog(LOG_NOTICE,
				       "subscr. register %s/%s/%d failed: %s",
				       notice->z_sender,
				       inet_ntoa(who->sin_addr),
				       ntohs(notice->z_port),
				       error_message(retval));
				if (server == me_server) {
				    if (retval == ZSRV_BADSUBPORT) {
					clt_ack(notice, who, AUTH_FAILED);
				    } else
					hostm_deathgram(who, me_server);
				}
				return(ZERR_NONE);
			}
			if (!(client = client_which_client(who, notice))) {
				syslog(LOG_CRIT, "subscr reg. failure");
				abort();
			}
		}
		if (strcmp (client->zct_principal->string, notice->z_sender)) {
			/* you may only subscribe for your own clients */
			if (server == me_server)
				clt_ack(notice, who, AUTH_FAILED);
			return(ZERR_NONE);
		}
#ifdef KERBEROS
		bcopy((caddr_t) ZGetSession(), /* in case it's changed */
		      (caddr_t) client->zct_cblock,
		      sizeof(C_Block));
#endif /* KERBEROS */
		if ((retval = subscr_subscribe(client,notice)) != ZERR_NONE) {
			syslog(LOG_WARNING, "subscr failed: %s",
			       error_message(retval));
			if (server == me_server)
				nack(notice, who);
			return(ZERR_NONE);
		}
	} else if (!strcmp(opcode, CLIENT_UNSUBSCRIBE)) {
		if ((client = client_which_client(who,notice)) != NULLZCNT) {
			if (strcmp(client->zct_principal->string, notice->z_sender)) {
				/* you may only cancel for your own clients */
				if (server == me_server)
					clt_ack(notice, who, AUTH_FAILED);
				return(ZERR_NONE);
			}
#if 0
			if (zdebug) {
			    if (server == me_server)
				syslog (LOG_DEBUG,
					"subscription cancel for %s/%d\n",
					inet_ntoa (who->sin_addr),
					ntohs (who->sin_port));
			    else
				syslog (LOG_DEBUG,
				"subscription cancel for %s/%d from %s\n",
					inet_ntoa (who->sin_addr),
					ntohs (who->sin_port),
					server->addr);
			}
#endif
			(void) subscr_cancel(who, notice);
		} else {
			nack(notice, who);
			return(ZERR_NONE);
		}
	} else if (!strcmp(opcode, CLIENT_CANCELSUB)) {
		/* canceling subscriptions implies I can punt info about
		 this client */
		if ((client = client_which_client(who,notice)) != NULLZCNT) {
			if (strcmp(client->zct_principal->string, notice->z_sender)) {
				/* you may only cancel for your own clients */
				if (server == me_server)
					clt_ack(notice, who, AUTH_FAILED);
				return(ZERR_NONE);
			}
			if (host) {
				/* don't flush locations here, let him
				   do it explicitly */
#if 0
				zdbug((LOG_DEBUG, "cancelsub clt_dereg %s/%d",
					inet_ntoa (who->sin_addr),
					ntohs (who->sin_port)));
#endif
				hostm_lose_ignore(client);
				(void) client_deregister(client, host, 0);
			}

		} 
		if (!client || !host) {
#if 0
			zdbug((LOG_DEBUG,"can_sub not found client"));
#endif
			if (server == me_server)
				nack(notice, who);
			return(ZERR_NONE);
		}
	} else {
		syslog(LOG_WARNING, "unknown ctl opcode %s", opcode);
		if (server == me_server)
			nack(notice, who);
		return(ZERR_NONE);
	}

	if (server == me_server) {
		ack(notice, who);
		server_forward(notice, auth, who);
	}
	return(ZERR_NONE);
}

 
