/* This file is part of the Project Athena Zephyr Notification System.
 * It contains functions for managing subscription lists.
 *
 *	Created by:	John T. Kohl
 *
 *	$Source$
 *	$Author$
 *
 *	Copyright (c) 1987,1988 by the Massachusetts Institute of Technology.
 *	For copying and distribution information, see the file
 *	"mit-copyright.h". 
 */

#include <zephyr/mit-copyright.h>
#include "zserver.h"

#ifndef lint
#ifndef SABER
static const char rcsid_subscr_c[] = "$Id$";
#endif
#endif

/*
 * The subscription manager.
 *
 * External functions:
 *
 * Code_t subscr_subscribe(who, notice)
 *	Client *who;
 *	ZNotice_t *notice;
 *
 * Code_t subscr_cancel(sin, notice)
 *	struct sockaddr_in *sin;
 *	ZNotice_t *notice;
 *
 * Code_t subscr_cancel_client(client)
 *	Client *client;
 *
 * Code_t subscr_cancel_host(addr)
 *	struct in_addr *addr;
 *
 * Client *subscr_match_list(notice)
 *	ZNotice_t *notice;
 *
 * void subscr_free_list(list)
 *	Client *list;
 *
 * void subscr_sendlist(notice, auth, who)
 *	ZNotice_t *notice;
 *	int auth;
 *	struct sockaddr_in *who;
 *
 * Code_t subscr_send_subs(client, vers)
 *	Client *client;
 *	char *vers;
 *
 * Code_t subscr_def_subs(who)
 *	Client *who;
 *
 * void subscr_reset();
 *
 */

#ifdef ZEPHYR_USES_KERBEROS
#ifndef NOENCRYPTION
C_Block	serv_key;
Sched	serv_ksched;
#endif
#endif

/* for compatibility when sending subscription information to old clients */

#ifdef OLD_COMPAT
#define	OLD_ZEPHYR_VERSION	"ZEPH0.0"
#define	OLD_CLIENT_INCOMPSUBS	"INCOMP"
static void old_compat_subscr_sendlist __P((ZNotice_t *notice, int auth,
					  struct sockaddr_in *who));
extern int old_compat_count_subscr;	/* counter of old use */
#endif /* OLD_COMPAT */
#ifdef NEW_COMPAT
#define NEW_OLD_ZEPHYR_VERSION	"ZEPH0.1"
static void new_old_compat_subscr_sendlist __P((ZNotice_t *notice, int auth,
					      struct sockaddr_in *who)); 
extern int new_compat_count_subscr;	/* counter of old use */
#endif /* NEW_COMPAT */

extern char *re_comp(), *re_conv();
static Code_t add_subscriptions __P((Client *who, Destlist *subs_queue,
				   ZNotice_t *notice));
static Destlist *extract_subscriptions __P((ZNotice_t *notice));
static void free_subscriptions __P((Destlist *subs));
static char **subscr_marshal_subs __P((ZNotice_t *notice, int auth,
				     struct sockaddr_in *who,
				     int *found));
static Destlist *subscr_copy_def_subs __P((char *person));
static int cl_match  __P((Destlist*, Client *));

static int defaults_read = 0;		/* set to 1 if the default subs
					   are in memory */
static ZNotice_t default_notice;	/* contains default subscriptions */

String *wildcard_instance;
String *empty;

/* WARNING: make sure this is the same as the number of strings you */
/* plan to hand back to the user in response to a subscription check, */
/* else you will lose.  See subscr_sendlist() */  
#define	NUM_FIELDS	3

/*
 * subscribe the client to types described in notice.
 */

Code_t
subscr_subscribe(who, notice)
    Client *who;
    ZNotice_t *notice;
{
    Destlist *subs;

    subs = extract_subscriptions(notice);
    return add_subscriptions(who, subs, notice);
}

static Code_t
add_subscriptions(who, subs, notice)
    Client *who;
    Destlist *subs;
    ZNotice_t *notice;
{
    Destlist *next;
    Code_t retval;
    Acl *acl;
    String *sender;

    if (!subs)
	return ZERR_NONE;	/* no subscr -> no error */

    sender = make_string(notice->z_sender, 0);

    /* Loop over the new subscriptions. */
    for (; subs; subs = next) {
	next = subs->next;
#if 0
	zdbug ((LOG_DEBUG, "subscr: %s/%s/%s", subs->dest.classname->string,
		subs->dest.inst->string, subs->dest.recip->string));
#endif
	if (!bdumping) {
	    if (subs->dest.recip != empty && subs->dest.recip != sender) {
		syslog(LOG_WARNING, "subscr unauth %s recipient %s",
		       sender->string, subs->dest.recip->string);
		continue;
	    }
	    acl = class_get_acl(subs->dest.classname);
	    if (acl) {
		if (!access_check(sender->string, acl, SUBSCRIBE)) {
		    syslog(LOG_WARNING, "subscr unauth %s class %s",
			   sender->string, subs->dest.classname->string);
		    continue; /* the for loop */
		}
		if (wildcard_instance == subs->dest.inst) {
		    if (!access_check(sender->string, acl, INSTWILD)) {
			syslog(LOG_WARNING,
			       "subscr unauth %s class %s wild inst",
			       notice->z_sender, subs->dest.classname->string);
			continue;
		    }
		}
	    }
	}
	retval = triplet_register(who, &subs->dest);
	if (retval != ZERR_NONE) {
	    free(subs);
	    if (retval == ZSRV_CLASSXISTS) {
		continue;
	    } else {
		free_subscriptions(next);
		return retval;
	    }
	}
	LIST_INSERT(who->subs, subs);
    }

    return ZERR_NONE;
}

/*
 * add default subscriptions to the client's subscription chain.
 */

Code_t
subscr_def_subs(who)
    Client *who;
{
    Destlist *subs;

    subs = subscr_copy_def_subs(who->principal->string);
    return add_subscriptions(who, subs, &default_notice);
}

void
subscr_reset()
{
#if 0
    zdbug((LOG_DEBUG, "subscr_reset()"));
#endif
    free(default_notice.z_message);
    default_notice.z_message = NULL;
    defaults_read = 0;
}

static Destlist *
subscr_copy_def_subs(person)
    char *person;
{
    int retval, fd;
    struct stat statbuf;
    char *def_sub_area, *cp;
    Destlist *subs, *sub;

    if (!defaults_read) {
#if 0
	zdbug((LOG_DEBUG, "reading default subscription file"));
#endif
	fd = open(subs_file, O_RDONLY, 0666);
	if (fd < 0) {
	    syslog(LOG_ERR, "can't open %s:%m", subs_file);
	    return NULL;
	}
	retval = fstat(fd, &statbuf);
	if (retval < 0) {
	    syslog(LOG_ERR, "fstat failure on %s:%m", subs_file);
	    close(fd);
	    return NULL;
	}
	def_sub_area = (char *) malloc(statbuf.st_size + 1);
	if (!def_sub_area) {
	    syslog(LOG_ERR, "no mem copy_def_subs");
	    close(fd);
	    return NULL;
	}
	retval = read(fd, def_sub_area, (size_t) statbuf.st_size);
	if (retval != statbuf.st_size) {
	    syslog(LOG_ERR, "short read in copy_def_subs");
	    close(fd);
	    return NULL;
	}

	close(fd);
	def_sub_area[statbuf.st_size] = '\0'; /* null-terminate it */

	/*
	   def_subs_area now points to a buffer full of subscription info.
	   Each line of the stuff is of the form:
	   class,inst,recipient

	   Commas and newlines may not appear as part of the class,
	   instance, or recipient. XXX!
	   */

	/* split up the subscription info */
	for (cp = def_sub_area; cp < def_sub_area + statbuf.st_size; cp++) {
	    if (*cp == '\n' || *cp == ',')
		*cp = '\0';
	}
	default_notice.z_message = def_sub_area;
	default_notice.z_message_len = statbuf.st_size + 1;
	default_notice.z_auth = 1;
	defaults_read = 1;
    }

    /* needed later for access_check() */
    default_notice.z_sender = person;
    subs = extract_subscriptions(&default_notice);
    /* replace any non-* recipients with "person" */

    for (sub = subs; sub; sub = sub->next) {
	/* if not a wildcard, replace it with person */
	if (strcmp(sub->dest.recip->string, "*")) {
	    free_string(sub->dest.recip);
	    sub->dest.recip = make_string(person, 0);
	} else {		/* replace with null recipient */
	    free_string(sub->dest.recip);
	    sub->dest.recip = dup_string(empty);
	}
    }
    return subs;
}

/*
 * Cancel a specific set of subscriptions.
 */

Code_t
subscr_cancel(sin, notice)
    struct sockaddr_in *sin;
    ZNotice_t *notice;
{
    Client *who;
    Destlist *cancel_subs, *subs, *client_subs, *next;
    Code_t retval;
    int found = 0;
    int relation;

#if 0
    zdbug((LOG_DEBUG,"subscr_cancel"));
#endif
    who = client_which_client(&sin->sin_addr, notice);
    if (!who)
	return ZSRV_NOCLT;

    if (!who->subs)
	return ZSRV_NOSUB;

    cancel_subs = extract_subscriptions(notice);
    if (!cancel_subs)
	return ZERR_NONE;	/* no subscr -> no error */

    for (subs = cancel_subs; subs; subs = next) {
	next = subs->next;
	for (client_subs = who->subs; client_subs; client_subs = next) {
	    next = client_subs->next;
	    if (ZDest_eq(&client_subs->dest, &subs->dest)) {
		LIST_DELETE(client_subs);
		triplet_deregister(who, &client_subs->dest);
		free_string(client_subs->dest.classname);
		free_string(client_subs->dest.inst);
		free_string(client_subs->dest.recip);
		free(client_subs);
		found = 1;
		break;
	    }
	}
    }

    free_subscriptions(cancel_subs);

    if (found) {
#if 0
	zdbug((LOG_DEBUG, "found & removed"));
#endif
	return ZERR_NONE;
    } else {
#if 0
	zdbug((LOG_DEBUG, "not found"));
#endif
	return ZSRV_NOSUB;
    }
}

/*
 * Cancel all the subscriptions for this client.
 */

void
subscr_cancel_client(client)
    Client *client;
{
    Destlist *subs, *next;

#if 0
    zdbug((LOG_DEBUG,"subscr_cancel_client %s",
	   inet_ntoa(client->addr.sin_addr)));
#endif
    if (!client->subs)
	return;

    for (subs = client->subs; subs; subs = next) {
	next = subs->next;
#if 0
	zdbug((LOG_DEBUG,"sub_can %s", subs->dest.classname->string));
#endif
	if (triplet_deregister(client, &subs->dest) != ZERR_NONE) {
#if 0
	    zdbug((LOG_DEBUG,"sub_can_clt: not registered!"));
#endif
	}
	free_string(subs->dest.classname);
	free_string(subs->dest.inst);
	free_string(subs->dest.recip);
	free(subs);
    }

    client->subs = NULL;
}

/*
 * Send the requester a list of his current subscriptions
 */

void
subscr_sendlist(notice, auth, who)
    ZNotice_t *notice;
    int auth;
    struct sockaddr_in *who;
{
    char **answer;
    int found;
    struct sockaddr_in send_to_who;
    Code_t retval;

#ifdef OLD_COMPAT
    if (strcmp(notice->z_version, OLD_ZEPHYR_VERSION) == 0) {
	/* we are talking to an old client; use the old-style
	   acknowledgement-message */
	old_compat_subscr_sendlist(notice, auth, who);
	return;
    }
#endif /* OLD_COMPAT */
#ifdef NEW_COMPAT
    if (strcmp(notice->z_version, NEW_OLD_ZEPHYR_VERSION) == 0) {
	/* we are talking to a new old client; use the new-old-style
	   acknowledgement-message */
	new_old_compat_subscr_sendlist(notice, auth, who);
	return;
    }
#endif /* NEW_COMPAT */
    answer = subscr_marshal_subs(notice, auth, who, &found);
    send_to_who = *who;
    send_to_who.sin_port = notice->z_port;  /* Return port */

    retval = ZSetDestAddr(&send_to_who);
    if (retval != ZERR_NONE) {
	syslog(LOG_WARNING, "subscr_sendlist set addr: %s",
	       error_message(retval));
	if (answer)
	    free(answer);
	return;
    }

    /* XXX for now, don't do authentication */
    auth = 0;

    notice->z_kind = ACKED;

    /* use xmit_frag() to send each piece of the notice */

    retval = ZSrvSendRawList(notice, answer, found * NUM_FIELDS, xmit_frag);
    if (retval != ZERR_NONE)
	syslog(LOG_WARNING, "subscr_sendlist xmit: %s", error_message(retval));
    if (answer)
	free(answer);
}

static char **
subscr_marshal_subs(notice, auth, who, found)
    ZNotice_t *notice;
    int auth;
    struct sockaddr_in *who;
    int *found;
{
    ZNotice_t reply;
    char **answer = NULL;
    int temp;
    Code_t retval;
    Client *client;
    Destlist *subs, *sub;
    int i;
    int defsubs = 0;

#if 0
    zdbug((LOG_DEBUG, "subscr_marshal"));
#endif
    *found = 0;

    /* Note that the following code is an incredible crock! */
	
    /* We cannot send multiple packets as acknowledgements to the client,
       since the hostmanager will ignore the later packets.  So we need
       to send directly to the client. */

    /* Make our own copy so we can send directly back to the client */
    /* RSF 11/07/87 */

    if (strcmp(notice->z_opcode, CLIENT_GIMMESUBS) == 0) {
	/* If the client has requested his current subscriptions,
	   the message field of the notice contains the port number
	   of the client for which the sender desires the subscription
	   list.  The port field is the port of the sender. */

	retval = ZReadAscii(notice->z_message, notice->z_message_len,
			    (unsigned char *) &temp, sizeof(u_short), 2);
	if (retval != ZERR_NONE) {
	    syslog(LOG_WARNING, "subscr_marshal read port num: %s",
		   error_message(retval));
	    return(NULL);
	}

	/* Blech blech blech */
	reply = *notice;
	reply.z_port = *((u_short *)&temp);

	client = client_which_client(&who->sin_addr, &reply);

	if (client) {
	    subs = client->subs;
	} else if (strcmp(notice->z_opcode, CLIENT_GIMMEDEFS) == 0) {
#if 0
		zdbug((LOG_DEBUG, "gimmedefs"));
#endif
		/* subscr_copy_def_subs allocates new pointer rings, so
		   it must be freed when finished.
		   the string areas pointed to are static, however.*/
		subs = subscr_copy_def_subs(notice->z_sender);
		defsubs = 1;
	} else {
		syslog(LOG_ERR, "subscr_marshal bogus opcode %s",
		       notice->z_opcode);
		return(NULL);
	}

	if (subs) {

	    /* check authenticity here.  The user must be authentic to get
	       a list of subscriptions. If he is not subscribed to
	       anything, this if-clause fails, and he gets a response
	       indicating no subscriptions.
	       if retrieving default subscriptions, don't care about
	       authentication. */

	    if (!auth && !defsubs)
		return(NULL);
	    if (!defsubs) {
		if (client && (strcmp(client->principal->string,
				      notice->z_sender) != 0)) {
		    zdbug ((LOG_DEBUG,
			    "subscr_marshal: %s requests subs for %s at %s/%d",
			    notice->z_sender, client->principal->string,
			    inet_ntoa(who->sin_addr), ntohs(who->sin_port)));
		    return 0;
		}
	    }

	    for (sub = subs; sub; sub = sub->next)
		(*found)++;

	    /* found is now the number of subscriptions */

	    /* coalesce the subscription information into a list of char *'s */
	    answer = (char **) malloc((*found) * NUM_FIELDS * sizeof(char *));
	    if (answer == NULL) {
		syslog(LOG_ERR, "subscr no mem(answer)");
		*found = 0;
	    } else {
		i = 0;
		for (sub = subs; sub; sub = sub->next) {
		    answer[i * NUM_FIELDS] = sub->dest.classname->string;
		    answer[i * NUM_FIELDS + 1] = sub->dest.inst->string;
		    answer[i * NUM_FIELDS + 2] = sub->dest.recip->string;
		    i++;
		}
	    }
	}
    }
    if (defsubs)
	free_subscriptions(subs);
    return answer;
}

#ifdef NEW_COMPAT
static void
new_old_compat_subscr_sendlist(notice, auth, who)
    ZNotice_t *notice;
    int auth;
    struct sockaddr_in *who;
{
    Code_t retval;
    ZNotice_t reply;
    ZPacket_t reppacket;
    int packlen, found, count, initfound, zerofound;
    char buf[64];
    const char **answer;
    struct sockaddr_in send_to_who;
    int i;

    new_compat_count_subscr++;

    syslog(LOG_INFO, "new old subscr, %s", inet_ntoa(who->sin_addr));
    reply = *notice;
    reply.z_kind = SERVACK;
    reply.z_authent_len = 0; /* save some space */
    reply.z_auth = 0;

    send_to_who = *who;
    send_to_who.sin_port = notice->z_port;  /* Return port */

    retval = ZSetDestAddr(&send_to_who);
    if (retval != ZERR_NONE) {
	syslog(LOG_WARNING, "new_old_subscr_sendlist set addr: %s",
	       error_message(retval));
	return;
    }

    /* retrieve  the subscriptions */
    answer = subscr_marshal_subs(notice, auth, who, &found);

    /* note that when there are no subscriptions, found == 0, so
       we needn't worry about answer being NULL since
       ZFormatSmallRawNoticeList won't reference the pointer */

    /* send 5 at a time until we are finished */
    count = found?((found-1) / 5 + 1):1;	/* total # to be sent */
    i = 0;					/* pkt # counter */
#if 0
    zdbug((LOG_DEBUG,"Found %d subscriptions for %d packets", found, count));
#endif
    initfound = found;
    zerofound = (found == 0);
    while (found > 0 || zerofound) {
	packlen = sizeof(reppacket);
	sprintf(buf, "%d/%d", ++i, count);
	reply.z_opcode = buf;
	retval = ZFormatSmallRawNoticeList(&reply,
					   answer + (initfound - found)
					    * NUM_FIELDS,
					   ((found > 5) ? 5 : found)
					    * NUM_FIELDS,
					   reppacket, &packlen);
	if (retval != ZERR_NONE) {
	    syslog(LOG_ERR, "subscr_sendlist format: %s",
		   error_message(retval));
	    if (answer)
		free(answer);
	    return;
	}
	retval = ZSendPacket(reppacket, packlen, 0);
	if (retval != ZERR_NONE) {
	    syslog(LOG_WARNING, "subscr_sendlist xmit: %s",
		   error_message(retval));
	    if (answer)
		free(answer);
	    return;
	}
	found -= 5;
	zerofound = 0;
    }
#if 0
    zdbug((LOG_DEBUG,"subscr_sendlist acked"));
#endif
    if (answer)
	free(answer);
}
#endif /* NEW_COMPAT */

#ifdef OLD_COMPAT
static void
old_compat_subscr_sendlist(notice, auth, who)
    ZNotice_t *notice;
    int auth;
    struct sockaddr_in *who;
{
    Client *client = client_which_client(&who->sin_addr, notice);
    Destlist *subs;
    Code_t retval;
    ZNotice_t reply;
    ZPacket_t reppacket;
    int packlen, i, found = 0;
    char **answer = NULL;

    old_compat_count_subscr++;

    syslog(LOG_INFO, "old old subscr, %s", inet_ntoa(who->sin_addr));
    if (client && client->subs) {

	/* check authenticity here.  The user must be authentic to get
	   a list of subscriptions. If he is not subscribed to
	   anything, the above test fails, and he gets a response
	   indicating no subscriptions */

	if (!auth) {
	    clt_ack(notice, who, AUTH_FAILED);
	    return;
	}

	for (subs = client->subs; subs; subs = subs->next)
	    found++;
	/* found is now the number of subscriptions */

	/* coalesce the subscription information into a list of char *'s */
	answer = (char **) malloc(found * NUM_FIELDS * sizeof(char *));
	if (!answer) {
	    syslog(LOG_ERR, "old_subscr_sendlist no mem(answer)");
	    found = 0;
	} else {
	    i = 0;
	    for (subs = client->subs; subs; subs = subs->next) {
		answer[i*NUM_FIELDS] = subs->dest.classname->string;
		answer[i*NUM_FIELDS + 1] = subs->dest.inst->string;
		answer[i*NUM_FIELDS + 2] = subs->dest.recip->string;
		i++;
	    }
	}
    }

    /* note that when there are no subscriptions, found == 0, so
       we needn't worry about answer being NULL */

    reply = *notice;
    reply.z_kind = SERVACK;
    reply.z_authent_len = 0; /* save some space */
    reply.z_auth = 0;

    /* if it's too long, chop off one at a time till it fits */
    while ((retval = ZFormatSmallRawNoticeList(&reply, answer,
					       found * NUM_FIELDS,
					       reppacket,
					       &packlen)) != ZERR_PKTLEN) {
	found--;
	reply.z_opcode = OLD_CLIENT_INCOMPSUBS;
    }
    if (retval != ZERR_NONE) {
	syslog(LOG_ERR, "old_subscr_sendlist format: %s",
	       error_message(retval));
	if (answer)
	    free(answer);
	return;
    }
    retval = ZSetDestAddr(who);
    if (retval != ZERR_NONE) {
	syslog(LOG_WARNING, "subscr_sendlist set addr: %s",
	       error_message(retval));
	if (answer)
	    free(answer);
	return;
    }
    retval = ZSendPacket(reppacket, packlen, 0);
    if (retval != ZERR_NONE) {
	syslog(LOG_WARNING, "subscr_sendlist xmit: %s",
	       error_message(retval));
	if (answer)
	    free(answer);
	return;
    }
#if 0
    zdbug((LOG_DEBUG,"subscr_sendlist acked"));
#endif
    if (answer)
	free(answer);
}
#endif /* OLD_COMPAT */

/*
 * Send the client's subscriptions to another server
 */

/* version is currently unused; if necessary later versions may key off it
   to determine what to send to the peer (protocol changes) */

/*ARGSUSED*/
Code_t
subscr_send_subs(client)
    Client *client;
{
    int i = 0;
    Destlist *subs;
#ifdef ZEPHYR_USES_KERBEROS
    char buf[512];
    C_Block cblock;
#endif /* ZEPHYR_USES_KERBEROS */
    char buf2[512];
    char *list[7 * NUM_FIELDS];
    int num = 0;
    Code_t retval;

#if 0
    zdbug((LOG_DEBUG, "send_subs"));
#endif
    sprintf(buf2, "%d",ntohs(client->addr.sin_port));

    list[num++] = buf2;

#ifdef ZEPHYR_USES_KERBEROS
#ifdef NOENCRYPTION
    memcpy(cblock, client->session_key, sizeof(C_Block));
#else
    des_ecb_encrypt(client->session_key, cblock, serv_ksched.s, DES_ENCRYPT);
#endif

    retval = ZMakeAscii(buf, sizeof(buf), cblock, sizeof(C_Block),
			sizeof(C_Block));
    if (retval != ZERR_NONE) {
#if 0
	zdbug((LOG_DEBUG,"zmakeascii failed: %s", error_message(retval)));
#endif
    } else {
	list[num++] = buf;
#if 0
	zdbug((LOG_DEBUG, "cblock %s", buf));
#endif
    }		
#endif /* ZEPHYR_USES_KERBEROS */
    retval = bdump_send_list_tcp(SERVACK, &client->addr, ZEPHYR_ADMIN_CLASS,
				 num > 1 ? "CBLOCK" : "", ADMIN_NEWCLT,
				 client->principal->string, "", list, num);
    if (retval != ZERR_NONE) {
	syslog(LOG_ERR, "subscr_send_subs newclt: %s", error_message(retval));
	return retval;
    }

    if (!client->subs)
	return ZERR_NONE;

    for (subs = client->subs; subs; subs = subs->next) {
	/* for each subscription */
	list[i * NUM_FIELDS] = subs->dest.classname->string;
	list[i * NUM_FIELDS + 1] = subs->dest.inst->string;
	list[i * NUM_FIELDS + 2] = subs->dest.recip->string;
	i++;
	if (i >= 7) {
	    /* we only put 7 in each packet, so we don't run out of room */
	    retval = bdump_send_list_tcp(ACKED, &client->addr,
					 ZEPHYR_CTL_CLASS, "",
					 CLIENT_SUBSCRIBE, "", "", list,
					 i * NUM_FIELDS);
	    if (retval != ZERR_NONE) {
		syslog(LOG_ERR, "subscr_send_subs subs: %s",
		       error_message(retval));
		return retval;
	    }
	    i = 0;
	}
    }
    if (i) {
	retval = bdump_send_list_tcp(ACKED, &client->addr, ZEPHYR_CTL_CLASS,
				     "", CLIENT_SUBSCRIBE, "", "", list,
				     i * NUM_FIELDS);
	if (retval != ZERR_NONE) {
	    syslog(LOG_ERR, "subscr_send_subs subs: %s",
		   error_message(retval));
	    return retval;
	}
    }

    return ZERR_NONE;
}

/*
 * free the memory allocated for the list of subscriptions.
 */

static void
free_subscriptions(subs)
    Destlist *subs;
{
    Destlist *next;

    for (; subs; subs = next) {
	next = subs->next;
	free_string(subs->dest.classname);
	free_string(subs->dest.inst);
	free_string(subs->dest.recip);
	free(subs);
    }
}

#define	ADVANCE(xx)	{ cp += (strlen(cp) + 1); \
		  if (cp >= notice->z_message + notice->z_message_len) { \
			  syslog(LOG_WARNING, "malformed subscription %d", \
				 xx); \
			  return subs; \
		  }}

/*
 * Parse the message body, returning a linked list of subscriptions, or
 * NULL if there are no subscriptions there.
 */

static Destlist *
extract_subscriptions(notice)
    ZNotice_t *notice;
{
    Destlist *subs = NULL, *sub;
    char *recip, *class_name, *classinst;
    char *cp = notice->z_message;

    /* parse the data area for the subscriptions */
    while (cp < notice->z_message + notice->z_message_len) {
	class_name = cp;
	if (*cp == '\0')	    /* we've exhausted the subscriptions */
	    return(subs);
	ADVANCE(1);
	classinst = cp;
	ADVANCE(2);
	recip = cp;
#if 0
	zdbug((LOG_DEBUG, "ext_sub: CLS %s INST %s RCPT %s",
	       class_name, classinst, cp));
#endif
	cp += (strlen(cp) + 1);
	if (cp > notice->z_message + notice->z_message_len) {
	    syslog(LOG_WARNING, "malformed sub 3");
	    return subs;
	}
	sub = (Destlist *) malloc(sizeof(Destlist));
	if (!sub) {
	    syslog(LOG_WARNING, "ex_subs: no mem 2");
	    return subs;
	}
	sub->dest.classname = make_string(class_name, 1);
	sub->dest.inst = make_string(classinst, 1);
	sub->dest.recip = make_string(recip, 0);
	LIST_INSERT(subs, sub);
    }
    return subs;
}

/*
 * print subscriptions in subs onto fp.
 * assumed to be called with SIGFPE blocked
 * (true if called from signal handler)
 */

void
subscr_dump_subs(fp, subs)
    FILE *fp;
    Destlist *subs;
{
    char *p;

    if (!subs)			/* no subscriptions to dump */
	return;

    for (; subs; subs = subs->next) {
	fputs("\t\t'", fp);
	subscr_quote(subs->dest.classname->string, fp);
	fputs("' '", fp);
	subscr_quote(subs->dest.inst->string, fp);
	fputs("' '", fp);
	subscr_quote(subs->dest.recip->string, fp);
	fputs("'\n", fp);
    }
}

