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

enum {
    NACKTAB_HASHSIZE = 1023
};
inline static unsigned int
nacktab_hashval(struct sockaddr_in sa, ZUnique_Id_t uid) {
    return (sa.sin_addr.s_addr ^
	    sa.sin_port ^
	    uid.zuid_addr.s_addr ^
	    uid.tv.tv_sec ^
	    uid.tv.tv_usec) % NACKTAB_HASHSIZE;
}

#define HOSTS_SIZE_INIT			256

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
 * void sendit(notice, auth, who, external)
 *	ZNotice_t *notice;
 *	int auth;
 *	struct sockaddr_in *who;
 *      int external;
 *
 * void xmit(notice, dest, auth, client)
 *	ZNotice_t *notice;
 *	struct sockaddr_in *dest;
 *	int auth;
 *	Client *client;
 */


String *class_control, *class_admin, *class_hm, *class_ulogin, *class_ulocate;

int rexmit_times[] = REXMIT_TIMES;

static void nack_cancel(ZNotice_t *, struct sockaddr_in *);
static void dispatch(ZNotice_t *, int, struct sockaddr_in *, int);
static int send_to_dest(ZNotice_t *, int, Destination *dest, int, int);
static void hostm_deathgram(struct sockaddr_in *, Server *);
static char *hm_recipient(void);

Statistic realm_notices = {0, "inter-realm notices"};
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

static Unacked *nacktab[NACKTAB_HASHSIZE];
static struct in_addr *hosts;
static int hosts_size = 0, num_hosts = 0;

#ifdef DEBUG
static void
dump_stats (void *arg)
{
    syslog(LOG_INFO, "stats: %s: %d", hm_packets.str, hm_packets.val);
    syslog(LOG_INFO, "stats: %s: %d", control_notices.str,
	   control_notices.val);
    syslog(LOG_INFO, "stats: %s: %d", message_notices.str,
	   message_notices.val);
    syslog(LOG_INFO, "stats: %s: %d", login_notices.str, login_notices.val);
    syslog(LOG_INFO, "stats: %s: %d", locate_notices.str, locate_notices.val);
    syslog(LOG_INFO, "stats: %s: %d", admin_notices.str, admin_notices.val);
    syslog(LOG_INFO, "stats: %s: %d", realm_notices.str, realm_notices.val);
    syslog(LOG_INFO, "stats: %s: %d", interserver_notices.str,
	   interserver_notices.val);
    syslog(LOG_INFO, "stats: %s: %d", i_s_ctls.str, i_s_ctls.val);
    syslog(LOG_INFO, "stats: %s: %d", i_s_logins.str, i_s_logins.val);
    syslog(LOG_INFO, "stats: %s: %d", i_s_admins.str, i_s_admins.val);
    syslog(LOG_INFO, "stats: %s: %d", i_s_locates.str, i_s_locates.val);

    /* log stuff once an hour */
    timer_set_rel ((long) 6*60*60, dump_stats, arg);
}
#endif

/*
 * Handle an input packet.
 * Warning: this function may be called from within a brain dump.
 */

void
handle_packet(void)
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
    ZRealm *realm;		/* foreign realm ptr */
    struct sockaddr_in *whence; /* pointer to actual origin */
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
	zdbug((LOG_DEBUG, "internal queue process"));

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
	notice_extract_address(&new_notice, &input_sin);
        /* Should check to see if packet is from another realm's server,
           or a client */
	from_server = 1;
	whence = &input_sin;
    } else {
	from_server = 0;
	whence = &whoisit;
    }

    /* Don't bother checking authentication on client ACKs */
    if (new_notice.z_kind == CLIENTACK) {
	nack_cancel(&new_notice, &whoisit);
	return;
    }

    /* Clients don't check auth of acks, nor do we make it so they
       can in general, so this is safe. */
    if (new_notice.z_kind == SERVACK || new_notice.z_kind == SERVNAK) {
	authentic = ZAUTH_YES;
    } else {
	realm = realm_which_realm(whence);
	authentic = ZCheckSrvAuthentication(&new_notice, whence, realm ? realm->name : NULL);
    }

    message_notices.val++;
    dispatch(&new_notice, authentic, &whoisit, from_server);
    return;
}
/*
 * Dispatch a notice.
 */

static void
dispatch(ZNotice_t *notice,
	 int auth,
	 struct sockaddr_in *who,
	 int from_server)
{
    Code_t status;
    String *notice_class;
    int authflag;
    ZRealm *realm;
    char *cp;

    authflag = (auth == ZAUTH_YES);

    if ((int) notice->z_kind < (int) UNSAFE ||
	(int) notice->z_kind > (int) CLIENTACK) {
	syslog(LOG_NOTICE, "bad notice kind 0x%x from %s", notice->z_kind,
	       inet_ntoa(who->sin_addr));
	return;
    }

    if (notice->z_kind == CLIENTACK) {
	nack_cancel(notice, who);
	return;
    }

    notice_class = make_string(notice->z_class,1);

    if (from_server) {
	interserver_notices.val++;
	status = server_dispatch(notice, authflag, who);
    } else if (class_is_hm(notice_class)) {
	hm_packets.val++;
	status = hostm_dispatch(notice, authflag, who, me_server);
    } else if (realm_which_realm(who) && !(class_is_admin(notice_class))) {
	realm_notices.val++;
	status = realm_dispatch(notice, authflag, who, me_server);
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
	if (!realm_bound_for_realm(ZGetRealm(), notice->z_recipient)) {
	    cp = strchr(notice->z_recipient, '@');
	    if (!cp ||
		!(realm = realm_get_realm_by_name(cp + 1))) {
		/* Foreign user, local realm */
		sendit(notice, authflag, who, 0);
	    } else
		realm_handoff(notice, authflag, who, realm, 1);
	} else {
	    if (notice->z_recipient[0] == '@')
		notice->z_recipient = "";
	    sendit(notice, authflag, who, 1);
	}
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
sendit(ZNotice_t *notice,
       int auth,
       struct sockaddr_in *who,
       int external)
{
    static int send_counter = 0;
    char recipbuf[MAX_PRINCIPAL_SIZE], *recipp, *acl_sender;
    int any = 0;
    Acl *acl;
    Destination dest;
    String *class;

    class = make_string(notice->z_class, 1);
    if (realm_bound_for_realm(ZGetRealm(), notice->z_recipient)) {
      ZRealm *rlm;

      acl = class_get_acl(class);
      if (acl != NULL) {
	acl_sender = auth ? notice->z_sender : 0;
	/* if from foreign realm server, disallow if not realm of sender */
	rlm = realm_which_realm(who);
	if (rlm) {
	  if (!realm_sender_in_realm(rlm->name, notice->z_sender)) {
	    syslog(LOG_WARNING, "sendit auth not verifiable %s (%s) from %s",
		   notice->z_class, rlm->name, notice->z_sender);
	    clt_ack(notice, who, AUTH_FAILED);
	    free_string(class);
	    return;
	  }
	}
	/* if not auth to transmit, fail */
	if (!access_check(acl_sender, who, acl, TRANSMIT)) {
	    syslog(LOG_WARNING, "sendit unauthorized %s from %s%s",
		   notice->z_class, notice->z_sender, auth ? "" : " (unauth)");
	    clt_ack(notice, who, AUTH_FAILED);
	    free_string(class);
	    return;
	}
	/* sender != inst and not auth to send to others --> fail */
	if (strcmp(notice->z_sender, notice->z_class_inst) != 0 &&
	    !access_check(acl_sender, who, acl, INSTUID)) {
	    syslog(LOG_WARNING, "sendit unauth uid %s%s %s.%s",
		   notice->z_sender, auth ? "" : " (unauth)",
		   notice->z_class, notice->z_class_inst);
	    clt_ack(notice, who, AUTH_FAILED);
	    free_string(class);
	    return;
	}
      }
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
    if (realm_bound_for_realm(ZGetRealm(), notice->z_recipient) &&
	*notice->z_recipient == '@')
      dest.recip = make_string("", 0);
    else {
      strncpy(recipbuf, notice->z_recipient, sizeof(recipbuf));
      recipp = strrchr(recipbuf, '@');
      if (recipp)
	/* XXX if realm_expand_realm doesn't find a match
	 * it returns what's passed into it, causing an overlapping
	 * copy, the results of which are undefined.
	 */
	strncpy(recipp + 1, realm_expand_realm(recipp + 1),
	       sizeof(recipbuf) - (recipp - recipbuf) - 1);
      dest.recip = make_string(recipbuf, 0);
    }

    if (send_to_dest(notice, auth, &dest, send_counter, external))
	any = 1;

    /* Send to clients subscribed to the triplet with the instance
     * substituted with the wildcard instance. */
    free_string(dest.inst);
    dest.inst = wildcard_instance;
    if (send_to_dest(notice, auth, &dest, send_counter, external))
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
send_to_dest(ZNotice_t *notice,
	     int auth,
	     Destination *dest,
	     int send_counter,
	     int external)
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
	if ((*clientp)->realm) {
	  if (external) {
	    realm_handoff(notice, auth, &clientp[0]->addr, clientp[0]->realm,
			  1);
	    any = 1;
	  }
	} else {
	    xmit(notice, &((*clientp)->addr), auth, *clientp);
	    any = 1;
	}
    }

    return any;
}

/*
 * Release anything destined for the client in the not-yet-acked table.
 */

void
nack_release(Client *client)
{
    int i;
    Unacked *nacked, *next;

    for (i = 0; i < NACKTAB_HASHSIZE; i++) {
	for (nacked = nacktab[i]; nacked; nacked = next) {
	    next = nacked->next;
	    if (nacked->client == client) {
		timer_reset(nacked->timer);
		Unacked_delete(nacked);
		free(nacked->packet);
		free(nacked);
	    }
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
xmit_frag(ZNotice_t *notice,
	  char *buf,
	  int len,
	  int waitforack)
{
    struct sockaddr_in sin;
    char *savebuf;
    Unacked *nacked;
    Code_t retval;
    int sendfail = 0;

    retval = ZSendPacket(buf, len, 0);
    if (retval != ZERR_NONE) {
	syslog(LOG_WARNING, "xmit_frag send: %s", error_message(retval));
	if (retval != EAGAIN && retval != ENOBUFS)
	    return retval;
	sendfail = 1;
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
	free(nacked);
	return ENOMEM;
    }

    memcpy(savebuf, buf, len);

    sin = ZGetDestAddr();
    nacked->client = NULL;
    nacked->rexmits = (sendfail) ? -1 : 0;
    nacked->packet = savebuf;
    nacked->dest.addr = sin;
    nacked->packsz = len;
    nacked->uid = notice->z_uid;
    nacked->timer = timer_set_rel(rexmit_times[0], rexmit, nacked);
    Unacked_insert(&nacktab[nacktab_hashval(sin, nacked->uid)], nacked);
    return(ZERR_NONE);
}


/*
 * Send the notice to the client.  After transmitting, put it onto the
 * not ack'ed list.
 */

void
xmit(ZNotice_t *notice,
     struct sockaddr_in *dest,
     int auth,
     Client *client)
{
    char *noticepack;
    Unacked *nacked;
    int packlen, sendfail = 0;
    Code_t retval;

    noticepack = (char *) malloc(sizeof(ZPacket_t));
    if (!noticepack) {
	syslog(LOG_ERR, "xmit malloc");
	return;			/* DON'T put on nack list */
    }

    packlen = sizeof(ZPacket_t);

    if (auth && client) {
	/* we are distributing authentic and we have a pointer to auth info */
#if defined(HAVE_KRB5)
	retval = ZFormatAuthenticNoticeV5(notice, noticepack, packlen,
					  &packlen, client->session_keyblock);
#elif defined(HAVE_KRB4)
	retval = ZFormatAuthenticNotice(notice, noticepack, packlen,
					&packlen, client->session_key);
#else /* !HAVE_KRB4 */
	notice->z_auth = 1;
	retval = ZFormatSmallRawNotice(notice, noticepack, &packlen);
#endif /* HAVE_KRB4 */
	if (retval != ZERR_NONE)
	    syslog(LOG_ERR, "xmit auth/raw format: %s", error_message(retval));
    } else {
	notice->z_auth = 0;
	notice->z_authent_len = 0;
	notice->z_ascii_authent = (char *)"";
	retval = ZFormatSmallRawNotice(notice, noticepack, &packlen);
        /* This code is needed because a Zephyr can "grow" when a remote
         * realm name is inserted into the Zephyr before being resent out
         * locally. It essentially matches the code in realm.c to do the
         * same thing with authentic Zephyrs.
         */
        if (retval == ZERR_PKTLEN) {
          char multi[64];
          int hdrlen,  message_len;
	  ZPacket_t the_packet;
	  char *buffer = (char *)&the_packet;
          ZNotice_t partnotice = *notice;
	  int offset = 0;
	  int fragsize = 0;
          int origoffset = 0;
	  int origlen = notice->z_message_len;

          free(noticepack);

          retval = ZSetDestAddr(dest);
          if (retval) {
            syslog(LOG_WARNING, "xmit: ZSetDestAddr: %s", error_message(retval));
            return;
          }

          partnotice.z_auth = 0;
          partnotice.z_authent_len = 0;
          partnotice.z_ascii_authent = (char *)"";

          retval = Z_FormatRawHeader(&partnotice, buffer, sizeof(ZPacket_t),
                                     &hdrlen, NULL, NULL);
          if (retval) {
	      syslog(LOG_ERR, "xmit unauth refrag: Z_FormatRawHeader: %s",
		     error_message(retval));
	      return;
          }

          if (notice->z_multinotice && strcmp(notice->z_multinotice, "")) {
	      if (sscanf(notice->z_multinotice, "%d/%d",
			 &origoffset, &origlen) != 2) {
		  syslog(LOG_WARNING,
			 "xmit unauth refrag: multinotice parse failed");
		  return;
	      }
	  }

	  fragsize = Z_MAXPKTLEN - hdrlen - Z_FRAGFUDGE;

	  if (fragsize < 0) {
	      syslog(LOG_ERR,
		     "xmit unauth refrag: negative fragsize, dropping packet");
	      return;
	  }

          while (offset < notice->z_message_len || !notice->z_message_len) {
            (void) sprintf(multi, "%d/%d", offset+origoffset, origlen);
            partnotice.z_multinotice = multi;
            if (offset > 0) {
              (void) Z_gettimeofday(&partnotice.z_uid.tv, (struct timezone *)0);
              partnotice.z_uid.tv.tv_sec = htonl((u_long)
                                                 partnotice.z_uid.tv.tv_sec);
              partnotice.z_uid.tv.tv_usec = htonl((u_long)
                                                  partnotice.z_uid.tv.tv_usec);
              (void) memcpy((char *)&partnotice.z_uid.zuid_addr, &__My_addr,
                            sizeof(__My_addr));
	      partnotice.z_sender_sockaddr.ip4.sin_family = AF_INET; /* XXX */
              (void) memcpy((char *)&partnotice.z_sender_sockaddr.ip4.sin_addr,
			    &__My_addr, sizeof(__My_addr));
            }
            partnotice.z_message = notice->z_message + offset;
            message_len = min(notice->z_message_len-offset, fragsize);
            partnotice.z_message_len = message_len;

            retval = Z_FormatRawHeader(&partnotice, buffer, sizeof(ZPacket_t),
                                       &hdrlen, NULL, NULL);
            if (retval) {
              syslog(LOG_WARNING, "xmit unauth refrag: Z_FormatRawHeader: %s",
                     error_message(retval));
              return;
            }

            (void) memcpy(buffer + hdrlen, partnotice.z_message,
			  partnotice.z_message_len);

            xmit_frag(&partnotice, buffer, hdrlen + partnotice.z_message_len, 0);

            offset += fragsize;

            if (!notice->z_message_len)
              break;
          }
          return;
        }
        /* End of refrag code */

	if (retval)
	    syslog(LOG_ERR, "xmit unauth: ZFormatSmallRawNotice: %s",
		   error_message(retval));
    }
    if (!retval) {
	retval = ZSetDestAddr(dest);
	if (retval)
	    syslog(LOG_WARNING, "xmit: ZSetDestAddr: %s", error_message(retval));
    }
    if (!retval) {
	retval = ZSendPacket(noticepack, packlen, 0);
	if (retval) {
	    syslog(LOG_WARNING, "xmit: ZSendPacket: (%s/%d) %s",
		   inet_ntoa(dest->sin_addr), ntohs(dest->sin_port),
		   error_message(retval));
	    if (retval == EAGAIN || retval == ENOBUFS) {
		retval = ZERR_NONE;
		sendfail = 1;
	    }
	}
    }

    /* now we've sent it, mark it as not ack'ed */
    if (!retval) {
	nacked = (Unacked *) malloc(sizeof(Unacked));
	if (!nacked) {
	    /* no space: just punt */
	    syslog(LOG_WARNING, "xmit nack malloc");
	    retval = ENOMEM;
	}
    }

    if (!retval) {
	nacked->client = client;
	nacked->rexmits = (sendfail) ? -1 : 0;
	nacked->packet = noticepack;
	nacked->dest.addr = *dest;
	nacked->packsz = packlen;
	nacked->uid = notice->z_uid;
	nacked->timer = timer_set_rel(rexmit_times[0], rexmit, nacked);
	Unacked_insert(&nacktab[nacktab_hashval(*dest, nacked->uid)], nacked);
    }
    if (retval)
	free(noticepack);
}

/*
 * Retransmit the packet specified.  If we have timed out or retransmitted
 * too many times, punt the packet and initiate the host recovery algorithm
 * Else, increment the count and re-send the notice packet.
 */

void
rexmit(void *arg)
{
    Unacked *nacked = (Unacked *) arg;
    int retval;

    syslog(LOG_DEBUG, "rexmit %s/%d #%d time %d",
	   inet_ntoa(nacked->dest.addr.sin_addr),
	   ntohs(nacked->dest.addr.sin_port), nacked->rexmits + 1, (int)NOW);

    nacked->rexmits++;
    if (rexmit_times[nacked->rexmits] == -1) {
	if (!nacked->client
	    || NOW - nacked->client->last_ack >= CLIENT_GIVEUP_MIN) {
	    /* The client (if there was one) has been unresponsive.
	     * Give up sending this packet, and kill the client if
	     * there was one.  (Make sure to remove nacked from the
	     * nack list before calling client_deregister(), which
	     * scans the nack list.)
	     */
	    Unacked_delete(nacked);
	    if (nacked->client) {
		server_kill_clt(nacked->client);
		client_deregister(nacked->client, 1);
	    }
	    free(nacked->packet);
	    free(nacked);
	    return;
	} else {
	    /* The client has sent us an ack recently.  Retry with the maximum
	     * retransmit time. */
	    nacked->rexmits--;
	}
    }

    /* retransmit the packet */
    retval = ZSetDestAddr(&nacked->dest.addr);
    if (retval != ZERR_NONE) {
	syslog(LOG_WARNING, "rexmit set addr: %s", error_message(retval));
    } else {
	retval = ZSendPacket(nacked->packet, nacked->packsz, 0);
	if (retval != ZERR_NONE)
	    syslog(LOG_WARNING, "rexmit xmit: %s", error_message(retval));
	if (retval == EAGAIN || retval == ENOBUFS)
	    nacked->rexmits--;
    }

    /* reset the timer */
    nacked->timer = timer_set_rel(rexmit_times[nacked->rexmits], rexmit,
				  nacked);
    return;
}

/*
 * Send an acknowledgement to the sending client, by sending back the
 * header from the original notice with the z_kind field changed to either
 * SERVACK or SERVNAK, and the contents of the message either SENT or
 * NOT_SENT, depending on the value of the sent argument.
 */

void
clt_ack(ZNotice_t *notice,
	struct sockaddr_in *who,
	Sent_type sent)
{
    ZNotice_t acknotice;
    ZPacket_t ackpack;
    int packlen;
    Code_t retval;

    if (bdumping) {		/* don't ack while dumping */
	zdbug((LOG_DEBUG,"bdumping, no ack"));
	return;
    }

    acknotice = *notice;

    acknotice.z_kind = SERVACK;
    switch (sent) {
      case SENT:
	acknotice.z_message = ZSRVACK_SENT;
	break;
      case NOT_FOUND:
	acknotice.z_message = ZSRVACK_FAIL;
	acknotice.z_kind = SERVNAK;
	break;
      case AUTH_FAILED:
	acknotice.z_kind = SERVNAK;
	acknotice.z_message = ZSRVACK_NOTSENT;
	break;
      case NOT_SENT:
	acknotice.z_message = ZSRVACK_NOTSENT;
	break;
      default:
	abort ();
    }

    acknotice.z_multinotice = "";

    /* leave room for the trailing null */
    acknotice.z_message_len = strlen(acknotice.z_message) + 1;

    packlen = sizeof(ackpack);

    retval = ZFormatSmallRawNotice(&acknotice, ackpack, &packlen);

    if (retval == ZERR_HEADERLEN) {
      /* Since an ack header can be larger than a message header... (crock) */
      acknotice.z_opcode = "";
      acknotice.z_class = "";
      acknotice.z_class_inst = "";
      acknotice.z_opcode = "";
      acknotice.z_default_format = "";

      retval = ZFormatSmallRawNotice(&acknotice, ackpack, &packlen);
    }

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
nack_cancel(ZNotice_t *notice,
	    struct sockaddr_in *who)
{
    Unacked *nacked;
    int hashval;

    /* search the not-yet-acked table for this packet, and flush it. */
    hashval = nacktab_hashval(*who, notice->z_uid);
    for (nacked = nacktab[hashval]; nacked; nacked = nacked->next) {
	if (nacked->dest.addr.sin_addr.s_addr == who->sin_addr.s_addr
	    && nacked->dest.addr.sin_port == who->sin_port
	    && ZCompareUID(&nacked->uid, &notice->z_uid)) {
	    if (nacked->client)
		nacked->client->last_ack = NOW;
	    timer_reset(nacked->timer);
	    free(nacked->packet);
	    Unacked_delete(nacked);
	    free(nacked);
	    return;
	}
    }

    zdbug((LOG_DEBUG,"nack_cancel: nack not found %s:%08X,%08X",
	   inet_ntoa (notice->z_uid.zuid_addr),
	   notice->z_uid.tv.tv_sec, notice->z_uid.tv.tv_usec));
}

/* Dispatch an HM_CTL notice. */

Code_t
hostm_dispatch(ZNotice_t *notice,
	       int auth,
	       struct sockaddr_in *who,
	       Server *server)
{
    char *opcode = notice->z_opcode;
    int i, add_it = 0, remove_it = 0;

    if (notice->z_kind == HMACK) {
	/* Ignore. */
	;
    } else if (notice->z_kind != HMCTL) {
	clt_ack(notice, who, AUTH_FAILED);
    } else if (strcmp(opcode, HM_FLUSH) == 0) {
	client_flush_host(&who->sin_addr);
	if (server == me_server)
	    server_forward(notice, auth, who);
    } else if (strcmp(opcode, HM_BOOT) == 0) {
	client_flush_host(&who->sin_addr);
	if (server == me_server) {
	    server_forward(notice, auth, who);
	    ack(notice, who);
	    add_it = 1;
	}
    } else if (strcmp(opcode, HM_ATTACH) == 0) {
	if (server == me_server) {
	    server_forward(notice, auth, who);
	    ack(notice, who);
	    add_it = 1;
	} else {
	    remove_it = 1;
	}
    } else if (strcmp(opcode, HM_DETACH) == 0) {
	remove_it = 1;
    } else {
	syslog(LOG_WARNING, "hm_dispatch: unknown opcode %s", opcode);
    }

    if (add_it) {
	for (i = 0; i < num_hosts; i++) {
	    if (hosts[i].s_addr == who->sin_addr.s_addr)
		break;
	}
	if (i == num_hosts) {
	    if (hosts_size == 0) {
		hosts = (struct in_addr *) malloc(HOSTS_SIZE_INIT *
						  sizeof(struct in_addr));
		if (!hosts)
		    return ENOMEM;
		hosts_size = HOSTS_SIZE_INIT;
	    } else if (num_hosts == hosts_size) {
		hosts = (struct in_addr *) realloc(hosts, hosts_size * 2 *
						   sizeof(struct in_addr));
		if (!hosts)
		    return ENOMEM;
		hosts_size *= 2;
	    }
	    hosts[num_hosts++] = who->sin_addr;
	}
    } else if (remove_it) {
	for (i = 0; i < num_hosts; i++) {
	    if (hosts[i].s_addr == who->sin_addr.s_addr) {
		memmove(&hosts[i], &hosts[i + 1], num_hosts - (i + 1));
		num_hosts--;
		break;
	    }
	}
    }
    return ZERR_NONE;
}

/*
 * Dispatch a ZEPHYR_CTL notice.
 */

Code_t
control_dispatch(ZNotice_t *notice,
		 int auth,
		 struct sockaddr_in *who,
		 Server *server)
{
    char *target, *opcode = notice->z_opcode;
    Client *client;
    Code_t retval;
    int wantdefs;
    ZRealm *realm;
    struct sockaddr_in newwho;

    /*
     * ZEPHYR_CTL Opcodes expected are:
     *	BOOT (inst HM): host has booted; flush data.
     *	CLIENT_SUBSCRIBE: process with the subscription mananger.
     *	CLIENT_UNSUBSCRIBE: ""
     *	CLIENT_CANCELSUB:   ""
     */

    zdbug((LOG_DEBUG, "ctl_disp: opc=%s", opcode));

    notice_extract_address(notice, &newwho);
    realm = realm_which_realm(&newwho);
    if (realm)
	return(realm_control_dispatch(notice, auth, who, server, realm));

    if (strcasecmp(notice->z_class_inst, ZEPHYR_CTL_HM) == 0) {
	return hostm_dispatch(notice, auth, who, server);
    } else if (strcmp(opcode, CLIENT_GIMMESUBS) == 0 ||
	       strcmp(opcode, CLIENT_GIMMEDEFS) == 0) {
	/* this special case is before the auth check so that
	   someone who has no subscriptions does NOT get a SERVNAK
	   but rather an empty list.  Note we must therefore
	   check authentication inside subscr_sendlist */
	ack(notice, who);
	subscr_sendlist(notice, auth, who);
	return ZERR_NONE;
    } else if (strcmp(opcode, CLIENT_AUTHENTICATE) == 0) {
        /* this special case is before the auth check because,
           well... */
        retval = authenticate_client(notice);
        if (retval == 0) {
            retval = client_register(notice, &who->sin_addr, &client, 0);
            if (retval != ZERR_NONE) {
                syslog(LOG_NOTICE,
                       "authenticate->register failed %s/%s/%d failed: %s",
                       notice->z_sender, inet_ntoa(who->sin_addr),
                       ntohs(notice->z_port), error_message(retval));
                if (server == me_server)
                    clt_ack(notice, who, AUTH_FAILED);
                return ZERR_NONE;
            }
#ifdef HAVE_KRB5
            if (client->session_keyblock) {
                krb5_free_keyblock_contents(Z_krb5_ctx, client->session_keyblock);
                retval = krb5_copy_keyblock_contents(Z_krb5_ctx, ZGetSession(),
                                                     client->session_keyblock);
            } else {
                retval = krb5_copy_keyblock(Z_krb5_ctx, ZGetSession(),
                                            &client->session_keyblock);
            }
            if (retval) {
                syslog(LOG_WARNING, "keyblock copy failed in authenticate: %s",
                       error_message(retval));
                if (server == me_server)
                    nack(notice, who);
                return ZERR_NONE;
            }
#endif
        } else {
            syslog(LOG_NOTICE, "authenticate %s/%s/%d failed: %s",
                   notice->z_sender, inet_ntoa(who->sin_addr),
                   ntohs(notice->z_port), error_message(retval));
            if (server == me_server)
                clt_ack(notice, who, AUTH_FAILED);
            return ZERR_NONE;
        }
    } else if (!auth) {
        syslog(LOG_INFO, "unauthenticated %s message purportedly from %s",
               opcode, notice->z_sender);
	if (server == me_server)
	    clt_ack(notice, who, AUTH_FAILED);
	return ZERR_NONE;
    }

    wantdefs = strcmp(opcode, CLIENT_SUBSCRIBE_NODEFS);
    if (!wantdefs || strcmp(opcode, CLIENT_SUBSCRIBE) == 0) {
	/* subscription notice */
	retval = client_register(notice, &who->sin_addr, &client, wantdefs);
	if (retval != ZERR_NONE) {
	    syslog(LOG_NOTICE, "subscr %s/%s/%d failed: %s",
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
            syslog(LOG_NOTICE,
                   "subscr request from %s on port used by %s (%s.%d)",
                   notice->z_sender, client->principal->string,
                   inet_ntoa(who->sin_addr), ntohs(notice->z_port)); /* XXX */
	    if (server == me_server)
		clt_ack(notice, who, AUTH_FAILED);
	    return ZERR_NONE;
	}
#ifdef HAVE_KRB5
        if (client->session_keyblock) {
             krb5_free_keyblock_contents(Z_krb5_ctx, client->session_keyblock);
             retval = krb5_copy_keyblock_contents(Z_krb5_ctx, ZGetSession(),
                                         client->session_keyblock);
        } else {
             retval = krb5_copy_keyblock(Z_krb5_ctx, ZGetSession(),
                                &client->session_keyblock);
        }
        if (retval) {
             syslog(LOG_WARNING, "keyblock copy failed in subscr: %s",
                    error_message(retval));
             if (server == me_server)
                  nack(notice, who);
             return ZERR_NONE;
        }
#else
#ifdef HAVE_KRB4
	/* in case it's changed */
	memcpy(client->session_key, ZGetSession(), sizeof(C_Block));
#endif
#endif
	retval = subscr_subscribe(client, notice, server);
	if (retval != ZERR_NONE) {
	    syslog(LOG_WARNING, "subscr failed: %s", error_message(retval));
	    if (server == me_server)
		nack(notice, who);
	    return ZERR_NONE;
	}
    } else if (strcmp(opcode, CLIENT_UNSUBSCRIBE) == 0) {
	client = client_find(&who->sin_addr, notice->z_port);
	if (client != NULL) {
	    if (strcmp(client->principal->string, notice->z_sender) != 0) {
		/* you may only cancel for your own clients */
                syslog(LOG_NOTICE,
                       "unsubscr request from %s on port used by %s (%s.%d)",
                       notice->z_sender, client->principal->string,
                       inet_ntoa(who->sin_addr), ntohs(notice->z_port)); /*XXX*/
		if (server == me_server)
		    clt_ack(notice, who, AUTH_FAILED);
		return ZERR_NONE;
	    }
	    subscr_cancel(who, notice);
	} else {
	    nack(notice, who);
	    return ZERR_NONE;
	}
    } else if (strcmp(opcode, CLIENT_CANCELSUB) == 0) {
	/* canceling subscriptions implies I can punt info about this client */
	client = client_find(&who->sin_addr, notice->z_port);
	if (client == NULL) {
	    if (server == me_server)
		nack(notice, who);
	    return ZERR_NONE;
	}
	if (strcmp(client->principal->string, notice->z_sender) != 0) {
	    /* you may only cancel for your own clients */
            syslog(LOG_NOTICE,
                   "cancel request from %s on port used by %s (%s.%d)",
                   notice->z_sender, client->principal->string,
                   inet_ntoa(who->sin_addr), ntohs(notice->z_port)); /* XXX */
	    if (server == me_server)
		clt_ack(notice, who, AUTH_FAILED);
	    return ZERR_NONE;
	}
	/* don't flush locations here, let him do it explicitly */
	client_deregister(client, 0);
    } else if (strcmp(opcode, CLIENT_FLUSHSUBS) == 0) {
	target = notice->z_sender;
	if (notice->z_message_len > 0 && *notice->z_message != 0) {
	    target = notice->z_message;
	    if (memchr(target, '\0', notice->z_message_len) == NULL) {
		syslog(LOG_WARNING, "malformed flushsubs");
		if (server == me_server)
		    nack(notice, who);
		return ZERR_NONE;
	    }
	    if (strcmp(target, notice->z_sender) != 0 &&
		!opstaff_check(notice->z_sender)) {
		syslog(LOG_NOTICE, "unauth flushsubs for %s by %s",
		       target, notice->z_sender);
		if (server == me_server)
		    clt_ack(notice, who, AUTH_FAILED);
		return ZERR_NONE;
	    }
	}
	client_flush_princ(target);
    } else if (strcmp(opcode, CLIENT_AUTHENTICATE) == 0) {
        /* already handled */
    } else {
	syslog(LOG_WARNING, "unknown ctl opcode %s", opcode);
	if (server == me_server) {
	    if (strcmp(notice->z_class_inst, ZEPHYR_CTL_REALM) != 0)
		nack(notice, who);
	}
	return ZERR_NONE;
    }

    if (server == me_server) {
	ack(notice, who);
	server_forward(notice, auth, who);
    }
    return ZERR_NONE;
}

void
hostm_shutdown(void)
{
    int i, s, newserver;
    struct sockaddr_in sin;

    for (i = 0; i < nservers; i++) {
	if (i != me_server_idx && otherservers[i].state == SERV_UP)
	    break;
    }
    newserver = (i < nservers);
    sin.sin_family = AF_INET;
    for (i = 0; i < num_hosts; i++) {
	sin.sin_addr = hosts[i];
	sin.sin_port = hm_port;
	if (newserver) {
	    while (1) {
		s = (random() % (nservers - 1)) + 1;
		if (otherservers[s].state == SERV_UP)
		    break;
	    }
	    hostm_deathgram(&sin, &otherservers[s]);
	} else {
	    hostm_deathgram(&sin, NULL);
	}
    }
}

void
realm_shutdown(void)
{
    int i, s, newserver;

    for (i = 0; i < nservers; i++) {
        if (i != me_server_idx && otherservers[i].state == SERV_UP)
            break;
    }
    zdbug((LOG_DEBUG, "rlm_shutdown"));

    newserver = (i < nservers);
    if (newserver) {
      while (1) {
	s = (random() % (nservers - 1)) + 1;
	if (otherservers[s].state == SERV_UP)
	  break;
      }
      realm_deathgram(&otherservers[s]);
    } else {
      realm_deathgram(NULL);
    }
}

static void
hostm_deathgram(struct sockaddr_in *sin,
		Server *server)
{
    Code_t retval;
    int shutlen;
    ZNotice_t shutnotice;
    char *shutpack;

    memset (&shutnotice, 0, sizeof(shutnotice));

    shutnotice.z_kind = HMCTL;
    shutnotice.z_port = sin->sin_port; /* we are sending it */
    shutnotice.z_class = HM_CTL_CLASS;
    shutnotice.z_class_inst = HM_CTL_SERVER;
    shutnotice.z_opcode = SERVER_SHUTDOWN;
    shutnotice.z_sender = HM_CTL_SERVER;
    shutnotice.z_recipient = hm_recipient();
    shutnotice.z_default_format = "";
    shutnotice.z_num_other_fields = 0;
    shutnotice.z_message = (server) ? server->addr_str : NULL;
    shutnotice.z_message_len = (server) ? strlen(server->addr_str) + 1 : 0;

    retval = ZFormatNotice(&shutnotice, &shutpack, &shutlen, ZNOAUTH);
    if (retval != ZERR_NONE) {
	syslog(LOG_ERR, "hm_shut format: %s",error_message(retval));
	return;
    }
    retval = ZSetDestAddr(sin);
    if (retval != ZERR_NONE) {
	syslog(LOG_WARNING, "hm_shut set addr: %s", error_message(retval));
	free(shutpack);
	return;
    }
    retval = ZSendPacket(shutpack, shutlen, 0);
    if (retval != ZERR_NONE)
	syslog(LOG_WARNING, "hm_shut xmit: %s", error_message(retval));
    free(shutpack);
}

static char *
hm_recipient(void)
{
    static char *recipient;
    char *realm;

    if (recipient)
	return recipient;

    realm = (char *)ZGetRealm();
    if (!realm)
	realm = "???";
    recipient = (char *) malloc(strlen(realm) + 4);
    strcpy (recipient, "hm@");
    strcat (recipient, realm);
    return recipient;
}
