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
#include "zserver.h"
#include <sys/socket.h>

#ifndef lint
#ifndef SABER
static const char rcsid_dispatch_c[] =
"$Id$";
#endif
#endif

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
 *	Sent_type sent;
 *
 * void nack_release(client)
 *	Client *client;
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
 *	Client *client;
 */


String *class_control, *class_admin, *class_hm, *class_ulogin, *class_ulocate;

int rexmit_times[] = REXMIT_TIMES;

static void nack_cancel __P((ZNotice_t *, struct sockaddr_in *));
static void dispatch __P((ZNotice_t *, int, struct sockaddr_in *, int));
static int send_to_dest __P((ZNotice_t *, int, Destination *dest, int));

Statistic interserver_notices = {0, "inter-server notices"};
Statistic hm_packets = {0, "hostmanager packets"};
Statistic control_notices = {0, "client control notices"};
Statistic message_notices = {0, "message notices"};
Statistic login_notices = {0, "login notices"};
Statistic i_s_ctls = {0, "inter-server control notices"};
Statistic i_s_logins = {0, "inter-server login notices"};
Statistic i_s_admins = {0, "inter-server admin notices"};
Statistic i_s_locates = {0, "inter-server locate notices"};
Statistic locate_notices = {0, "locate notices"};
Statistic admin_notices = {0, "admin notices"};

static void
dump_stats (arg)
    void *arg;
{
    syslog(LOG_INFO, "stats: %s: %d", hm_packets.str, hm_packets.val);
    syslog(LOG_INFO, "stats: %s: %d", control_notices.str,
	   control_notices.val);
    syslog(LOG_INFO, "stats: %s: %d", message_notices.str,
	   message_notices.val);
    syslog(LOG_INFO, "stats: %s: %d", login_notices.str, login_notices.val);
    syslog(LOG_INFO, "stats: %s: %d", locate_notices.str, locate_notices.val);
    syslog(LOG_INFO, "stats: %s: %d", admin_notices.str, admin_notices.val);
    syslog(LOG_INFO, "stats: %s: %d", interserver_notices.str,
	   interserver_notices.val);
    syslog(LOG_INFO, "stats: %s: %d", i_s_ctls.str, i_s_ctls.val);
    syslog(LOG_INFO, "stats: %s: %d", i_s_logins.str, i_s_logins.val);
    syslog(LOG_INFO, "stats: %s: %d", i_s_admins.str, i_s_admins.val);
    syslog(LOG_INFO, "stats: %s: %d", i_s_locates.str, i_s_locates.val);

    /* log stuff once an hour */
    timer_set_rel ((long) 6*60*60, dump_stats, arg);
}

/*
 * Handle an input packet.
 * Warning: this function may be called from within a brain dump.
 */

void
handle_packet()
{
    Code_t status;
    ZPacket_t input_packet;	/* from the network */
    ZNotice_t new_notice;	/* parsed from input_packet */
    int input_len;		/* len of packet */
    struct sockaddr_in input_sin; /* Zconstructed for authent */
    struct sockaddr_in whoisit;	/* for holding peer's address */
    int authentic;		/* authentic flag */
    Pending *pending;		/* pending packet */
    int from_server;		/* packet is from another server */
#ifdef DEBUG
    static int first_time = 1;
#endif

#ifdef DEBUG
    /* Dump statistics five minutes after startup */
    if (first_time) {
	first_time = 0;
	timer_set_rel(5*60, dump_stats, NULL);
    }
#endif
    /* handle traffic */

    if (otherservers[me_server_idx].queue) {
	/* something here for me; take care of it */
#if 1
	zdbug((LOG_DEBUG, "internal queue process"));
#endif

	pending = server_dequeue(me_server);

	status = ZParseNotice(pending->packet, pending->len, &new_notice);
	if (status != ZERR_NONE) {
	    syslog(LOG_ERR, "bad notice parse (%s): %s",
		   inet_ntoa(pending->who.sin_addr), error_message(status));
	} else {
	    dispatch(&new_notice, pending->auth, &pending->who, 1);
	}
	server_pending_free(pending);
	return;
    }

    /* 
     * nothing in internal queue, go to the external library
     * queue/socket
     */
    status = ZReceivePacket(input_packet, &input_len, &whoisit);
    if (status != ZERR_NONE) {
	syslog(LOG_ERR, "bad packet receive: %s from %s",
	       error_message(status), inet_ntoa(whoisit.sin_addr));
	return;
    }
    npackets++;
    status = ZParseNotice(input_packet, input_len, &new_notice);
    if (status != ZERR_NONE) {
	syslog(LOG_ERR, "bad notice parse (%s): %s",
	       inet_ntoa(whoisit.sin_addr), error_message(status));
	return;
    }
    if (server_which_server(&whoisit)) {
	/* we need to parse twice--once to get
	   the source addr, second to check
	   authentication */
	memset(&input_sin, 0, sizeof(input_sin));
	input_sin.sin_addr.s_addr = new_notice.z_sender_addr.s_addr;
	input_sin.sin_port = new_notice.z_port;
	input_sin.sin_family = AF_INET;
	authentic = ZCheckAuthentication(&new_notice, &input_sin);
	from_server = 1;
    } else {
	from_server = 0;
	authentic = ZCheckAuthentication(&new_notice, &whoisit);
    }

    if (whoisit.sin_port != hm_port && whoisit.sin_port != hm_srv_port &&
	strcasecmp(new_notice.z_class, ZEPHYR_ADMIN_CLASS) != 0 &&
	whoisit.sin_port != srv_addr.sin_port &&
	new_notice.z_kind != CLIENTACK) {
	syslog(LOG_ERR, "bad port %s/%d", inet_ntoa(whoisit.sin_addr),
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
    String *notice_class;
    struct sockaddr_in who2;
    int authflag;
#ifdef DEBUG
    char dbg_buf[BUFSIZ];
#endif

    /* Set "authflag" to 1 or 0 for handler functions.  Treat
     * ZAUTH_CKSUM_FAILED as authentic except for sendit(), which is
     * handled below. */
    switch (auth) {
      case ZAUTH_YES:
      case ZAUTH_CKSUM_FAILED:
	authflag = 1;
	break;
      case ZAUTH_FAILED:
      case ZAUTH_NO:
      default:
	authflag = 0;
	break;
    }

    if ((int) notice->z_kind < (int) UNSAFE ||
	(int) notice->z_kind > (int) CLIENTACK) {
	syslog(LOG_NOTICE, "bad notice kind 0x%x from %s", notice->z_kind,
	       inet_ntoa(who->sin_addr));
	return;
    }
#if 0
    if (zdebug) {
	sprintf(dbg_buf,
		"disp:%s '%s' '%s' '%s' notice to '%s' from '%s' %s/%d/%d",
		ZNoticeKinds[(int) notice->z_kind], notice->z_class,
		notice->z_class_inst, notice->z_opcode, notice->z_recipient,
		notice->z_sender, inet_ntoa(who->sin_addr),
		ntohs(who->sin_port), ntohs(notice->z_port));
	syslog(LOG_DEBUG, "%s", dbg_buf);
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
    notice_class = make_string(notice->z_class,1);

    if (from_server) {
	interserver_notices.val++;
	status = server_dispatch(notice, authflag, who);
    } else if (class_is_hm(notice_class)) {
	hm_packets.val++;
	status = hostm_dispatch(notice, authflag, who, me_server);
    } else if (class_is_control(notice_class)) {
	control_notices.val++;
	status = control_dispatch(notice, authflag, who, me_server);
    } else if (class_is_ulogin(notice_class)) {
	login_notices.val++;
	status = ulogin_dispatch(notice, authflag, who, me_server);
    } else if (class_is_ulocate(notice_class)) {
	locate_notices.val++;
	status = ulocate_dispatch(notice, authflag, who, me_server);
    } else if (class_is_admin(notice_class)) {
	admin_notices.val++;
	status = server_adispatch(notice, authflag, who, me_server);
    } else {
	if (auth == ZAUTH_CKSUM_FAILED)
	    authflag = 0;
	sendit(notice, authflag, who);
	free_string(notice_class);
	return;
    }

    if (status == ZSRV_REQUEUE)
	server_self_queue(notice, authflag, who);
    free_string(notice_class);
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
    static int send_counter = 0;
    int any = 0;
    Acl *acl;
    Destination dest;
    String *class;

    class = make_string(notice->z_class, 1);
    acl = class_get_acl(class);
    if (acl != NULL) {
	/* if controlled and not auth, fail */
	if (!auth) {
	    syslog(LOG_WARNING, "sendit unauthentic %s from %s",
		   notice->z_class, notice->z_sender);
	    clt_ack(notice, who, AUTH_FAILED);
	    free_string(class);
	    return;
	}
	/* if not auth to transmit, fail */
	if (!access_check(notice->z_sender, acl, TRANSMIT)) {
	    syslog(LOG_WARNING, "sendit unauthorized %s from %s",
		   notice->z_class, notice->z_sender);
	    clt_ack(notice, who, AUTH_FAILED);
	    free_string(class);
	    return;
	}
	/* sender != inst and not auth to send to others --> fail */
	if (strcmp(notice->z_sender, notice->z_class_inst) != 0 &&
	    !access_check(notice->z_sender, acl, INSTUID)) {
	    syslog(LOG_WARNING, "sendit unauth uid %s %s.%s", notice->z_sender,
		   notice->z_class, notice->z_class_inst);
	    clt_ack(notice, who, AUTH_FAILED);
	    free_string(class);
	    return;
	}
    }
    if (memcmp(&notice->z_sender_addr.s_addr, &who->sin_addr.s_addr,
	       sizeof(notice->z_sender_addr.s_addr))) {
	/* someone is playing games... */
	/* inet_ntoa returns pointer to static area */
	/* max size is 255.255.255.255 */
	char buffer[16];
	strcpy(buffer, inet_ntoa(who->sin_addr));
	if (!auth) {
	    syslog(LOG_WARNING,
		   "sendit unauthentic fake packet: claimed %s, real %s",
		   inet_ntoa(notice->z_sender_addr), buffer);
	    clt_ack(notice, who, AUTH_FAILED);
	    free_string(class);
	    return;
	}
	if (ntohl(notice->z_sender_addr.s_addr) != 0) {
	    syslog(LOG_WARNING, "sendit invalid address: claimed %s, real %s",
		   inet_ntoa(notice->z_sender_addr), buffer);
	    clt_ack(notice, who, AUTH_FAILED);
	    free_string(class);
	    return;
	}
	syslog(LOG_WARNING, "sendit addr mismatch: claimed %s, real %s",
	       inet_ntoa(notice->z_sender_addr), buffer);
    }

    /* Increment the send counter, used to prevent duplicate sends to
     * clients.  On the off-chance that we wrap around to 0, skip over
     * it to prevent missing clients which have never had a packet
     * sent to them. */
    send_counter++;
    if (send_counter == 0)
	send_counter = 1;

    /* Send to clients subscribed to the triplet itself. */
    dest.classname = class;
    dest.inst = make_string(notice->z_class_inst, 1);
    dest.recip = make_string(notice->z_recipient, 0);
    if (send_to_dest(notice, auth, &dest, send_counter))
	any = 1;

    /* Send to clients subscribed to the triplet with the instance
     * substituted with the wildcard instance. */
    free_string(dest.inst);
    dest.inst = wildcard_instance;
    if (send_to_dest(notice, auth, &dest, send_counter))
	any = 1;

    free_string(class);
    free_string(dest.recip);
    if (any)
	ack(notice, who);
    else
	nack(notice, who);
}

/*
 * Send to each client in the list.  Avoid duplicates by setting
 * last_send on each client to send_counter, a nonce which is updated
 * by sendit() above.
 */

static int
send_to_dest(notice, auth, dest, send_counter)
    ZNotice_t *notice;
    int auth;
    Destination *dest;
    int send_counter;
{
    Client **clientp;
    int any = 0;

    clientp = triplet_lookup(dest);
    if (!clientp)
	return 0;

    for (; *clientp; clientp++) {
	if ((*clientp)->last_send == send_counter)
	    continue;
	(*clientp)->last_send = send_counter;
	xmit(notice, &((*clientp)->addr), auth, *clientp);
	any = 1;
    }

    return any;
}

/*
 * Clean up the not-yet-acked queue and release anything destined
 * for the client.
 */

void
nack_release(client)
    Client *client;
{
    Unacked *nacked, *next;

    /* search the not-yet-acked list for anything destined to him, and
       flush it. */
    for (nacked = nacklist; nacked; nacked = next) {
	next = nacked->next;
	if ((nacked->dest.addr.sin_addr.s_addr
	     == client->addr.sin_addr.s_addr) &&
	    (nacked->dest.addr.sin_port == client->addr.sin_port)) {
	    timer_reset(nacked->timer);
	    LIST_DELETE(nacked);
	    free(nacked->packet);
	    free(nacked);
	}
    }
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
    Unacked *nacked;
    Code_t retval;

    retval = ZSendPacket(buf, len, 0);
    if (retval != ZERR_NONE) {
	syslog(LOG_WARNING, "xmit_frag send: %s", error_message(retval));
	return retval;
    }

    /* now we've sent it, mark it as not ack'ed */

    nacked = (Unacked *) malloc(sizeof(Unacked));
    if (!nacked) {
	/* no space: just punt */
	syslog(LOG_WARNING, "xmit_frag nack malloc");
	return ENOMEM;
    }

    savebuf = (char *) malloc(len);
    if (!savebuf) {
	/* no space: just punt */
	syslog(LOG_WARNING, "xmit_frag pack malloc");
	return ENOMEM;
    }

    memcpy(savebuf, buf, len);

    nacked->rexmits = 0;
    nacked->packet = savebuf;
    nacked->dest.addr = ZGetDestAddr();
    nacked->packsz = len;
    nacked->uid = notice->z_uid;
    nacked->timer = timer_set_rel(rexmit_times[0], rexmit, nacked);
    LIST_INSERT(nacklist, nacked);
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
    Client *client;
{
    char *noticepack;
    Unacked *nacked;
    int packlen;
    Code_t retval;

#if 0
    zdbug((LOG_DEBUG,"xmit"));
#endif

    noticepack = (char *) malloc(sizeof(ZPacket_t));
    if (!noticepack) {
	syslog(LOG_ERR, "xmit malloc");
	return;			/* DON'T put on nack list */
    }
	
    packlen = sizeof(ZPacket_t);

    if (auth && client) {	/*
				   we are distributing authentic and
				   we have a pointer to auth info
				   */
#ifdef ZEPHYR_USES_KERBEROS

	retval = ZFormatAuthenticNotice(notice, noticepack, packlen, &packlen,
					client->session_key);
	if (retval != ZERR_NONE) {
	    syslog(LOG_ERR, "xmit auth format: %s", error_message(retval));
	    free(noticepack);
	    return;
	}
#else /* !ZEPHYR_USES_KERBEROS */
	notice->z_auth = 1;
	retval = ZFormatSmallRawNotice(notice, noticepack, &packlen);
	if (retval != ZERR_NONE) {
	    syslog(LOG_ERR, "xmit auth/raw format: %s", error_message(retval));
	    free(noticepack);
	    return;
	}
#endif /* ZEPHYR_USES_KERBEROS */
    } else {
	notice->z_auth = 0;
	notice->z_authent_len = 0;
	notice->z_ascii_authent = (char *)"";
	retval = ZFormatSmallRawNotice(notice, noticepack, &packlen);
	if (retval != ZERR_NONE) {
	    syslog(LOG_ERR, "xmit format: %s", error_message(retval));
	    free(noticepack);
	    return;			/* DON'T put on nack list */
	}
    }
#if 0
    zdbug((LOG_DEBUG," to %s/%d", inet_ntoa(dest->sin_addr),
	   ntohs(dest->sin_port)));
#endif
    retval = ZSetDestAddr(dest);
    if (retval != ZERR_NONE) {
	syslog(LOG_WARNING, "xmit set addr: %s", error_message(retval));
	free(noticepack);
	return;
    }
    retval = ZSendPacket(noticepack, packlen, 0);
    if (retval != ZERR_NONE) {
	syslog(LOG_WARNING, "xmit xmit: (%s/%d) %s", inet_ntoa(dest->sin_addr),
	       ntohs(dest->sin_port), error_message(retval));
	free(noticepack);
	return;
    }

    /* now we've sent it, mark it as not ack'ed */

    nacked = (Unacked *) malloc(sizeof(Unacked));
    if (!nacked) {
	/* no space: just punt */
	syslog(LOG_WARNING, "xmit nack malloc");
	free(noticepack);
	return;
    }

    nacked->rexmits = 0;
    nacked->packet = noticepack;
    nacked->dest.addr = *dest;
    nacked->packsz = packlen;
    nacked->uid = notice->z_uid;
    nacked->timer = timer_set_rel(rexmit_times[0], rexmit, nacked);
    LIST_INSERT(nacklist, nacked);
}

/*
 * Retransmit the packet specified.  If we have timed out or retransmitted
 * too many times, punt the packet and initiate the host recovery algorithm
 * Else, increment the count and re-send the notice packet.
 */

void
rexmit(arg)
    void *arg;
{
    Unacked *packet = (Unacked *) arg;
    int retval;
    ZNotice_t dummy_notice;
    Client *client;

#if 1
    syslog(LOG_DEBUG, "rexmit %s/%d #%d time %d",
	   inet_ntoa(packet->dest.addr.sin_addr),
	   ntohs(packet->dest.addr.sin_port), packet->rexmits + 1, NOW);
#endif

    packet->rexmits++;
    if (rexmit_times[packet->rexmits] == -1) {
	/* Unresponsive client, find it in our database. */
	dummy_notice.z_port = packet->dest.addr.sin_port;
	client = client_which_client(&packet->dest.addr.sin_addr,
				     &dummy_notice);

	/* unlink & free packet */
	LIST_DELETE(packet);
	free(packet->packet);
	free(packet);

	/* Kill the client. */
	if (client) {
	    server_kill_clt(client);
	    client_deregister(client, 1);
	}

	return;
    }

    /* retransmit the packet */
#if 0
    zdbug((LOG_DEBUG," to %s/%d", inet_ntoa(packet->dest.addr.sin_addr),
	   ntohs(packet->dest.addr.sin_port)));
#endif
    retval = ZSetDestAddr(&packet->dest.addr);
    if (retval != ZERR_NONE) {
	syslog(LOG_WARNING, "rexmit set addr: %s", error_message(retval));
    } else {
	retval = ZSendPacket(packet->packet, packet->packsz, 0);
	if (retval != ZERR_NONE)
	    syslog(LOG_WARNING, "rexmit xmit: %s", error_message(retval));
    }

    /* reset the timer */
    packet->timer = timer_set_rel(rexmit_times[packet->rexmits], rexmit,
				  packet);
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
    Sent_type sent;
{
    ZNotice_t acknotice;
    ZPacket_t ackpack;
    int packlen;
    int notme = 0;
    char *sent_name;
    Code_t retval;

    if (bdumping) {		/* don't ack while dumping */
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
    zdbug((LOG_DEBUG,"clt_ack type %s for %d to %s/%d", sent_name,
	   ntohs(notice->z_port), inet_ntoa(who->sin_addr),
	   ntohs(who->sin_port)));
#endif

    acknotice.z_multinotice = "";

    /* leave room for the trailing null */
    acknotice.z_message_len = strlen(acknotice.z_message) + 1;

    packlen = sizeof(ackpack);

    retval = ZFormatSmallRawNotice(&acknotice, ackpack, &packlen);
    if (retval != ZERR_NONE) {
	syslog(LOG_ERR, "clt_ack format: %s", error_message(retval));
	return;
    }
    retval = ZSetDestAddr(who);
    if (retval != ZERR_NONE) {
	syslog(LOG_WARNING, "clt_ack set addr: %s", error_message(retval));
	return;
    }
    retval = ZSendPacket(ackpack, packlen, 0);
    if (retval != ZERR_NONE) {
	syslog(LOG_WARNING, "clt_ack xmit: %s", error_message(retval));
	return;
    } else {
	zdbug((LOG_DEBUG, "packet sent"));
    }
    return;
}

/*
 * An ack has arrived.
 * remove the packet matching this notice from the not-yet-acked queue
 */

static void
nack_cancel(notice, who)
    ZNotice_t *notice;
    struct sockaddr_in *who;
{
    Unacked *nacked;

    /* search the not-yet-acked list for this packet, and flush it. */
#if 0
    zdbug((LOG_DEBUG, "nack_cancel: %s:%08X,%08X",
	   inet_ntoa(notice->z_uid.zuid_addr),
	   notice->z_uid.tv.tv_sec, notice->z_uid.tv.tv_usec));
#endif
    for (nacked = nacklist; nacked; nacked = nacked->next) {
	if (nacked->dest.addr.sin_addr.s_addr == who->sin_addr.s_addr &&
	    nacked->dest.addr.sin_port == who->sin_port) {
	    if (ZCompareUID(&nacked->uid, &notice->z_uid)) {
		timer_reset(nacked->timer);
		free(nacked->packet);
		LIST_DELETE(nacked);
		free(nacked);
		return;
	    }
	}
    }

#if 1
    zdbug((LOG_DEBUG,"nack_cancel: nack not found %s:%08X,%08X",
	   inet_ntoa (notice->z_uid.zuid_addr),
	   notice->z_uid.tv.tv_sec, notice->z_uid.tv.tv_usec));
#endif
}

/* for compatibility when sending subscription information to old clients */
#ifdef OLD_COMPAT
#define	OLD_ZEPHYR_VERSION	"ZEPH0.0"
#endif /* OLD_COMPAT */

/* Dispatch an HM_CTL notice. */

Code_t
hostm_dispatch(notice, auth, who, server)
    ZNotice_t *notice;
    int auth;
    struct sockaddr_in *who;
    Server *server;
{
    Server *owner;
    char *opcode = notice->z_opcode;
    Code_t retval;

#if 0
    zdbug((LOG_DEBUG,"hm_disp"));
#endif

    if (notice->z_kind == HMACK) {
	/* Ignore. */
	;
    } else if (notice->z_kind != HMCTL) {
#if 0
	zdbug((LOG_DEBUG, "bogus HM packet"));
#endif
	clt_ack(notice, who, AUTH_FAILED);
    } else if (strcmp(opcode, HM_BOOT) == 0 || strcmp(opcode, HM_FLUSH) == 0) {
	client_flush_host(&who->sin_addr);
	if (server == me_server) {
	    server_forward(notice, auth, who);
	    if (strcmp(opcode, HM_BOOT) == 0)
		ack(notice, who);
	}
    } else if (strcmp(opcode, HM_ATTACH) == 0) {
	if (server == me_server) {
	    server_forward(notice, auth, who);
	    ack(notice, who);
	}
    } else if (strcmp(opcode, HM_DETACH) != 0) {
	syslog(LOG_WARNING, "hm_dispatch: unknown opcode %s", opcode);
    }
    return ZERR_NONE;
}

/*
 * Dispatch a ZEPHYR_CTL notice.
 */

Code_t
control_dispatch(notice, auth, who, server)
    ZNotice_t *notice;
    int auth;
    struct sockaddr_in *who;
    Server *server;
{
    char *opcode = notice->z_opcode;
    Client *client;
    Code_t retval;
    int wantdefs;

    /*
     * ZEPHYR_CTL Opcodes expected are:
     *	BOOT (inst HM): host has booted; flush data.
     *	CLIENT_SUBSCRIBE: process with the subscription mananger.
     *	CLIENT_UNSUBSCRIBE: ""
     *	CLIENT_CANCELSUB:   ""
     */

    zdbug((LOG_DEBUG, "ctl_disp: opc=%s", opcode));

    if (strcasecmp(notice->z_class_inst, ZEPHYR_CTL_HM) == 0) {
	return hostm_dispatch(notice, auth, who, server);
    } else if (strcmp(opcode, CLIENT_GIMMESUBS) == 0 ||
	       strcmp(opcode, CLIENT_GIMMEDEFS) == 0) {
	/* this special case is before the auth check so that
	   someone who has no subscriptions does NOT get a SERVNAK
	   but rather an empty list.  Note we must therefore
	   check authentication inside subscr_sendlist */
#ifdef OLD_COMPAT
	/* only acknowledge if *not* old version; the old version
	   acknowledges the packet with the reply */
	if (strcmp(notice->z_version, OLD_ZEPHYR_VERSION) != 0)
	    ack(notice, who);
#else /* !OLD_COMPAT */
	ack(notice, who);
#endif /* OLD_COMPAT */
	subscr_sendlist(notice, auth, who);
	return ZERR_NONE;
    } else if (!auth) {
#if 0
	zdbug((LOG_DEBUG,"unauth ctrl_disp"));
#endif
	if (server == me_server)
	    clt_ack(notice, who, AUTH_FAILED);
	return ZERR_NONE;
    }

    wantdefs = strcmp(opcode, CLIENT_SUBSCRIBE_NODEFS);
    if (!wantdefs || strcmp(opcode, CLIENT_SUBSCRIBE) == 0) {
	/* subscription notice */
	retval = client_register(notice, &who->sin_addr, &client, wantdefs);
	if (retval != ZERR_NONE) {
	    syslog(LOG_NOTICE, "subscr. %s/%s/%d failed: %s",
		   notice->z_sender, inet_ntoa(who->sin_addr),
		   ntohs(notice->z_port), error_message(retval));
	    if (server == me_server) {
		if (retval == ZSRV_BADSUBPORT)
		    clt_ack(notice, who, AUTH_FAILED);
		else
		    nack(notice, who);
	    }
	    return(ZERR_NONE);
	}
	if (strcmp(client->principal->string, notice->z_sender) != 0) {
	    /* you may only subscribe for your own clients */
	    if (server == me_server)
		clt_ack(notice, who, AUTH_FAILED);
	    return ZERR_NONE;
	}
#ifdef ZEPHYR_USES_KERBEROS
	/* in case it's changed */
	memcpy(client->session_key, ZGetSession(), sizeof(C_Block));
#endif
	retval = subscr_subscribe(client, notice);
	if (retval != ZERR_NONE) {
	    syslog(LOG_WARNING, "subscr failed: %s", error_message(retval));
	    if (server == me_server)
		nack(notice, who);
	    return ZERR_NONE;
	}
    } else if (strcmp(opcode, CLIENT_UNSUBSCRIBE) == 0) {
	client = client_which_client(&who->sin_addr, notice);
	if (client != NULL) {
	    if (strcmp(client->principal->string, notice->z_sender) != 0) {
		/* you may only cancel for your own clients */
		if (server == me_server)
		    clt_ack(notice, who, AUTH_FAILED);
		return ZERR_NONE;
	    }
#if 0
	    if (zdebug) {
		if (server == me_server) {
		    syslog(LOG_DEBUG, "subscription cancel for %s/%d\n",
			   inet_ntoa(who->sin_addr), ntohs(who->sin_port));
		} else {
		    syslog(LOG_DEBUG,
			   "subscription cancel for %s/%d from %s\n",
			   inet_ntoa(who->sin_addr), ntohs (who->sin_port),
			   server->dest.addr);
		}
	    }
#endif
	    subscr_cancel(who, notice);
	} else {
	    nack(notice, who);
	    return ZERR_NONE;
	}
    } else if (strcmp(opcode, CLIENT_CANCELSUB) == 0) {
	/* canceling subscriptions implies I can punt info about this client */
	client = client_which_client(&who->sin_addr, notice);
	if (client == NULL) {
#if 0
	    zdbug((LOG_DEBUG,"can_sub not found client"));
#endif
	    if (server == me_server)
		nack(notice, who);
	    return ZERR_NONE;
	}
	if (strcmp(client->principal->string, notice->z_sender) != 0) {
	    /* you may only cancel for your own clients */
	    if (server == me_server)
		clt_ack(notice, who, AUTH_FAILED);
	    return ZERR_NONE;
	}
	/* don't flush locations here, let him do it explicitly */
#if 0
	zdbug((LOG_DEBUG, "cancelsub clt_dereg %s/%d",
	       inet_ntoa(who->sin_addr), ntohs(who->sin_port)));
#endif
	client_deregister(client, 0);
    } else {
	syslog(LOG_WARNING, "unknown ctl opcode %s", opcode);
	if (server == me_server)
	    nack(notice, who);
	return ZERR_NONE;
    }

    if (server == me_server) {
	ack(notice, who);
	server_forward(notice, auth, who);
    }
    return ZERR_NONE;
}


