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

#ifndef lint
#ifndef SABER
static char rcsid_subscr_c[] = "$Id$";
#endif
#endif

/*
 * The subscription manager.
 *
 * External functions:
 *
 * Code_t subscr_subscribe(who, notice)
 *	ZClient_t *who;
 *	ZNotice_t *notice;
 *
 * Code_t subscr_cancel(sin, notice)
 *	struct sockaddr_in *sin;
 *	ZNotice_t *notice;
 *
 * Code_t subscr_cancel_client(client)
 *	ZClient_t *client;
 *
 * Code_t subscr_cancel_host(addr)
 *	struct in_addr *addr;
 *
 * ZClientList_t *subscr_match_list(notice)
 *	ZNotice_t *notice;
 *
 * void subscr_free_list(list)
 *	ZClientList_t *list;
 *
 * void subscr_sendlist(notice, auth, who)
 *	ZNotice_t *notice;
 *	int auth;
 *	struct sockaddr_in *who;
 *
 * Code_t subscr_send_subs(client, vers)
 *	ZClient_t *client;
 *	char *vers;
 *
 * Code_t subscr_def_subs(who)
 *	ZClient_t *who;
 *
 * void subscr_reset();
 *
 */

#include "zserver.h"
#include <ctype.h>
#include <strings.h>
#include <sys/stat.h>

#ifdef __STDC__
# define        P(s) s
#else
# define P(s) ()
#endif

#ifdef KERBEROS
#ifndef NOENCRYPTION
C_Block	serv_key;
Sched	serv_ksched;
#endif
#endif

/* for compatibility when sending subscription information to old clients */

#ifdef OLD_COMPAT
#define	OLD_ZEPHYR_VERSION	"ZEPH0.0"
#define	OLD_CLIENT_INCOMPSUBS	"INCOMP"
static void old_compat_subscr_sendlist P((ZNotice_t *notice, int auth,
					  struct sockaddr_in *who));
extern int old_compat_count_subscr;	/* counter of old use */
#endif /* OLD_COMPAT */
#ifdef NEW_COMPAT
#define NEW_OLD_ZEPHYR_VERSION	"ZEPH0.1"
static void new_old_compat_subscr_sendlist P((ZNotice_t *notice, int auth,
					      struct sockaddr_in *who)); 
extern int new_compat_count_subscr;	/* counter of old use */
#endif /* NEW_COMPAT */

extern char *re_comp(), *re_conv();
static Code_t add_subscriptions P((ZClient_t *who, ZSubscr_t *subs_queue,
				   ZNotice_t *notice));
static ZSubscr_t *extract_subscriptions P((register ZNotice_t *notice));
static void free_subscriptions P((register ZSubscr_t *subs));
static char **subscr_marshal_subs P((ZNotice_t *notice, int auth,
				     struct sockaddr_in *who,
				     register int *found));
static ZSubscr_t *subscr_copy_def_subs P((char *person));
static int cl_match  P((ZSubscr_t*, ZClient_t *));

static int defaults_read = 0;		/* set to 1 if the default subs
					   are in memory */
static ZNotice_t default_notice;	/* contains default subscriptions */

#undef P

ZSTRING *wildcard_instance;
ZSTRING *empty;

/* WARNING: make sure this is the same as the number of strings you */
/* plan to hand back to the user in response to a subscription check, */
/* else you will lose.  See subscr_sendlist() */  
#define	NUM_FIELDS	3

/*
 * subscribe the client to types described in notice.
 */

Code_t
subscr_subscribe(who, notice)
     ZClient_t *who;
     ZNotice_t *notice;
{
	ZSubscr_t *subs_queue, *sub;
	Code_t retval;
	
	if (!who->zct_subs) {
		/* allocate a subscription head */
		sub = (ZSubscr_t *) xmalloc(sizeof(ZSubscr_t));
		if (!sub)
			return(ENOMEM);
		sub->q_forw = sub->q_back = sub;
		sub->zst_dest.classname = sub->zst_dest.inst =
		  sub->zst_dest.recip = NULL;
		who->zct_subs = sub;
	}

	subs_queue = extract_subscriptions(notice);
	return(add_subscriptions(who, subs_queue, notice));
}

static Code_t
add_subscriptions(who, subs_queue, notice)
     ZClient_t *who;
     ZSubscr_t *subs_queue;
     ZNotice_t *notice;
{
	ZSubscr_t *sub, *next;
	Code_t retval;
	ZAcl_t *acl;
	ZSTRING *sender;

	if (!subs_queue)
		return(ZERR_NONE);	/* no subscr -> no error */

	sender = make_zstring(notice->z_sender,0);

	START_CRITICAL_CODE;

	/* Loop over the new subscriptions. */
	next = subs_queue->q_forw;
	while (next != subs_queue) {
		sub = next;
		next = sub->q_forw;

#if 0
		zdbug ((LOG_DEBUG, "subscr: %s/%s/%s",
			sub->zst_dest.classname->string,
			sub->zst_dest.inst->string,
			sub->zst_dest.recip->string));
#endif

		if (!bdumping) {
		    if ((sub->zst_dest.recip != empty)
			&& (sub->zst_dest.recip != sender)) {
			syslog(LOG_WARNING, "subscr unauth %s recipient %s",
			       sender->string,
			       sub->zst_dest.recip->string);
			continue;
		    }
		    acl = class_get_acl(sub->zst_dest.classname);
		    if (acl) {
			if (!(access_check(sender->string, acl, SUBSCRIBE))) {
				syslog(LOG_WARNING,
				       "subscr unauth %s class %s",
				       sender->string,
				       sub->zst_dest.classname->string);
				continue; /* the for loop */
			}
			if (wildcard_instance == sub->zst_dest.inst) {
			    if (!access_check(sender->string, acl, INSTWILD)) {
				syslog(LOG_WARNING,
				       "subscr unauth %s class %s wild inst",
				       notice->z_sender,
				       sub->zst_dest.classname->string);
				continue;
			    }
			}
		    }
		}
		xremque(sub);
		retval = triplet_register(who, &sub->zst_dest);
		if (retval != ZERR_NONE) {
			xfree(sub);
			if (retval == ZSRV_CLASSXISTS) {
				continue;
			} else {
				free_subscriptions(subs_queue);
				END_CRITICAL_CODE;
				return(retval);
			}
		}
		xinsque(sub, who->zct_subs);
	}

	END_CRITICAL_CODE;

	free_subscriptions(subs_queue);
	return(ZERR_NONE);
}

/*
 * add default subscriptions to the client's subscription chain.
 */

Code_t
subscr_def_subs(who)
     ZClient_t *who;
{
	ZSubscr_t *subs;

	if (!who->zct_subs) {
		/* allocate a subscription head */
		if (!(subs = (ZSubscr_t *) xmalloc(sizeof(ZSubscr_t)))) {
			syslog(LOG_ERR, "no mem subscr_def_subs");
			return(ENOMEM);
		}
		subs->q_forw = subs->q_back = subs;
		subs->zst_dest.classname = subs->zst_dest.inst =
		  subs->zst_dest.recip = (ZSTRING *) NULL;
		who->zct_subs = subs;
	}

	subs = subscr_copy_def_subs(who->zct_principal->string);
	return(add_subscriptions(who, subs, &default_notice));
}

void
subscr_reset()
{
#if 0
	zdbug((LOG_DEBUG, "subscr_reset()"));
#endif
	xfree(default_notice.z_message);
	default_notice.z_message = NULL;
	defaults_read = 0;
}

static ZSubscr_t *
subscr_copy_def_subs(person)
     char *person;
{
	int retval;
	int fd;
	struct stat statbuf;
	char *def_sub_area;
	register char *cp;
	ZSubscr_t *subs;
	register ZSubscr_t *subs2;

	if (!defaults_read) {
#if 0
		zdbug((LOG_DEBUG, "reading default subscription file"));
#endif
		fd = open(DEFAULT_SUBS_FILE, O_RDONLY, 0666);
		if (fd < 0) {
			syslog(LOG_ERR, "can't open %s:%m", DEFAULT_SUBS_FILE);
			return((ZSubscr_t *)0);
		}
		retval = fstat(fd, &statbuf);
		if (retval < 0) {
			syslog(LOG_ERR, "fstat failure on %s:%m",
			       DEFAULT_SUBS_FILE);
			(void) close(fd);
			return((ZSubscr_t *)0);
		}
		if (!(def_sub_area = (char *) xmalloc(statbuf.st_size + 1))) {
			syslog(LOG_ERR, "no mem copy_def_subs");
			(void) close(fd);
			return((ZSubscr_t *)0);
		}
		retval = read(fd, def_sub_area, (int) statbuf.st_size);
		/*
		  "Upon successful completion, read and readv return the number
		  of bytes actually read and placed in the buffer.  The system
		  guarantees to read the number of bytes requested if the
		  descriptor references a normal file that has that many bytes
		  left before the end-of-file, but in no other case."
								-- read(2)
		  Therefore, the following test is valid.
		 */
		if (retval != statbuf.st_size) {
			syslog(LOG_ERR, "short read in copy_def_subs");
			(void) close(fd);
			return((ZSubscr_t *)0);
		}

		(void) close(fd);
		def_sub_area[statbuf.st_size] = '\0'; /* null-terminate it */

		/*
		  def_subs_area now points to a buffer full of subscription
		  info.
		  each line of the stuff is of the form:
		  class,inst,recipient

		  Commas and newlines may not appear as part of the class,
		  instance, or recipient. XXX!
		 */

		/* split up the subscription info */
		for (cp = def_sub_area;
		     cp < def_sub_area + statbuf.st_size;
		     cp++)
			if ((*cp == '\n') || (*cp == ','))
				*cp = '\0';
		default_notice.z_message = def_sub_area;
		default_notice.z_message_len = (int) statbuf.st_size + 1;
		default_notice.z_auth = 1;
		defaults_read = 1;
	}
	/* needed later for access_check() */
	default_notice.z_sender = person;
	subs = extract_subscriptions(&default_notice);
	/* replace any non-* recipients with "person" */

	for (subs2 = subs->q_forw; subs2 != subs; subs2 = subs2->q_forw) {
		/* if not a wildcard, replace it with person */
		if (strcmp(subs2->zst_dest.recip->string, "*")) {
		  free_zstring(subs2->zst_dest.recip);
			subs2->zst_dest.recip = make_zstring(person,0);
		} else {		/* replace with null recipient */
		  free_zstring(subs2->zst_dest.recip);
		  subs2->zst_dest.recip = dup_zstring(empty);
		}
	}
	return(subs);
}

/*
 * Cancel a specific set of subscriptions.
 */

Code_t
subscr_cancel(sin, notice)
     struct sockaddr_in *sin;
     ZNotice_t *notice;
{
	ZClient_t *who;
	register ZSubscr_t *cancel_queue, *cancel, *sub;
	Code_t retval;
	int found = 0;
	int relation;

#if 0
	zdbug((LOG_DEBUG,"subscr_cancel"));
#endif
	who = client_which_client(sin, notice);
	if (!who)
		return(ZSRV_NOCLT);

	if (!who->zct_subs)
		return(ZSRV_NOSUB);

	cancel_queue = extract_subscriptions(notice);
	if (!cancel_queue)
		return(ZERR_NONE);	/* no subscr -> no error */

	START_CRITICAL_CODE;

	for (cancel = cancel_queue->q_forw; cancel != cancel_queue;
	     cancel = cancel->q_forw) {
	    for (sub = who->zct_subs->q_forw; sub != who->zct_subs;
		 sub = sub->q_forw) {
		if (ZDest_eq(&cancel->zst_dest, &sub->zst_dest)) {
		    xremque(sub);
		    triplet_deregister(who, &sub->zst_dest);
		    free_zstring(sub->zst_dest.classname);
		    free_zstring(sub->zst_dest.inst);
		    free_zstring(sub->zst_dest.recip);
		    xfree(sub);
		    found = 1;
		    break;
		}
	    }
	}

	END_CRITICAL_CODE;

	free_subscriptions(cancel_queue);
	if (found) {
#if 0
	  zdbug((LOG_DEBUG, "found & removed"));
#endif
	  return(ZERR_NONE);
	} else {
#if 0
	  zdbug((LOG_DEBUG, "not found"));
#endif
	  return(ZSRV_NOSUB);
	}
}

/*
 * Cancel all the subscriptions for this client.
 */

void
subscr_cancel_client(client)
     ZClient_t *client;
{
	register ZSubscr_t *subs;

#if 0
	zdbug((LOG_DEBUG,"subscr_cancel_client %s",
	       inet_ntoa (client->zct_addr.sin_addr)));
#endif
	if (!client->zct_subs)
		return;

	START_CRITICAL_CODE;

	for (subs = client->zct_subs->q_forw;
	     subs != client->zct_subs;
	     subs = client->zct_subs->q_forw) {
#if 0
		zdbug((LOG_DEBUG,"sub_can %s",
		       subs->zst_dest.classname->string));
#endif
		if (triplet_deregister(client, &subs->zst_dest) != ZERR_NONE) {
#if 0
			zdbug((LOG_DEBUG,"sub_can_clt: not registered!"));
#endif
		}
		xremque(subs);
		free_zstring(subs->zst_dest.classname);
		free_zstring(subs->zst_dest.inst);
		free_zstring(subs->zst_dest.recip);
		xfree(subs);
	}

	/* also flush the head of the queue */
	/* subs is now client->zct_subs */
	free_zstring(subs->zst_dest.classname);
	free_zstring(subs->zst_dest.inst);
	free_zstring(subs->zst_dest.recip);
	xfree(subs);
	client->zct_subs = NULLZST;

	END_CRITICAL_CODE;

	return;
}

#ifdef notdef
/* not used for the moment */
/*
 * Cancel all the subscriptions for clients at this addr.
 */

Code_t
subscr_cancel_host(addr)
struct in_addr *addr;
{
	register ZHostList_t *hosts;
	register ZClientList_t *clist = NULLZCLT, *clt;

	/* find the host */
	if (!(hosts = hostm_find_host(addr)))
		return(ZSRV_HNOTFOUND);
	clist = hosts->zh_clients;

	START_CRITICAL_CODE;

	/* flush each one */
	for (clt = clist->q_forw; clt != clist; clt = clt->q_forw)
		(void) subscr_cancel_client(clt->zclt_client);

	END_CRITICAL_CODE;

	return(ZERR_NONE);
}
#endif

/*
 * Free memory used by a list we allocated.
 */

void
subscr_free_list(list)
     ZClientList_t *list;
{
	register ZClientList_t *lyst;

	for (lyst = list->q_forw; lyst != list; lyst = list->q_forw) {
		xremque(lyst);
		xfree(lyst);
	}
	xfree(list);
	return;
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
	if (!strcmp(notice->z_version, OLD_ZEPHYR_VERSION)) {
		/* we are talking to an old client; use the old-style
		   acknowledgement-message */
		old_compat_subscr_sendlist(notice, auth, who);
		return;
	}
#endif /* OLD_COMPAT */
#ifdef NEW_COMPAT
	if (!strcmp(notice->z_version, NEW_OLD_ZEPHYR_VERSION)) {
		/* we are talking to a new old client; use the new-old-style
		   acknowledgement-message */
		new_old_compat_subscr_sendlist(notice, auth, who);
		return;
	}
#endif /* NEW_COMPAT */
	answer = subscr_marshal_subs(notice, auth, who, &found);
	send_to_who = *who;
	send_to_who.sin_port = notice->z_port;  /* Return port */

	if ((retval = ZSetDestAddr(&send_to_who)) != ZERR_NONE) {
		syslog(LOG_WARNING, "subscr_sendlist set addr: %s",
		       error_message(retval));
		if (answer)
			xfree(answer);
		return;
	}

	/* XXX for now, don't do authentication */
	auth = 0;

	notice->z_kind = ACKED;

	/* use xmit_frag() to send each piece of the notice */

	if ((retval = ZSrvSendRawList(notice, (char **) answer,
				      found*NUM_FIELDS, xmit_frag))
	    != ZERR_NONE) {
		syslog(LOG_WARNING, "subscr_sendlist xmit: %s",
		       error_message(retval));
	}
	if (answer)
		xfree(answer);
	return;
}

static char **
subscr_marshal_subs(notice, auth, who, found)
     ZNotice_t *notice;
     int auth;
     struct sockaddr_in *who;
     register int *found;
{
	ZNotice_t reply;
	char **answer = (char **) 0;
	int temp;
	Code_t retval;
	ZClient_t *client;
	register ZSubscr_t *subs, *subs2 = NULLZST;
	register int i;
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
	

	if (!strcmp(notice->z_opcode, CLIENT_GIMMESUBS)) {
		/* If the client has requested his current subscriptions,
		   the message field of the notice contains the port number
		   of the client for which the sender desires the subscription
		   list.  The port field is the port of the sender. */

		if ((retval = ZReadAscii(notice->z_message,
					 notice->z_message_len,
					 (unsigned char *)&temp,
					 sizeof(u_short))) != ZERR_NONE) {
			syslog(LOG_WARNING, "subscr_marshal read port num: %s",
			       error_message(retval));
			return((char **)0);
		}

		/* Blech blech blech */
		reply = *notice;
		reply.z_port = *((u_short *)&temp);
	
		client = client_which_client(who, &reply);
	
		if (client)
			subs2 = client->zct_subs;
	} else if (!strcmp(notice->z_opcode, CLIENT_GIMMEDEFS)) {
#if 0
		zdbug((LOG_DEBUG, "gimmedefs"));
#endif
		/* subscr_copy_def_subs allocates new pointer rings, so
		   it must be freed when finished.
		   the string areas pointed to are static, however.*/
		subs2 = subscr_copy_def_subs(notice->z_sender);
		defsubs = 1;
	} else {
		syslog(LOG_ERR, "subscr_marshal bogus opcode %s",
		       notice->z_opcode);
		return((char **) 0);
	}

	if (subs2) {

		/* check authenticity here.  The user must be authentic to get
		   a list of subscriptions. If he is not subscribed to
		   anything, this if-clause fails, and he gets a response
		   indicating no subscriptions.
		   if retrieving default subscriptions, don't care about
		   authentication. */

		if (!auth && !defsubs) {
			return((char **) 0);
		}
		if (!defsubs) {
		    if (client && (strcmp(client->zct_principal->string,
					   notice->z_sender) != 0)) {
			zdbug ((LOG_DEBUG,
			"subscr_marshal: %s requests subs for %s at %s/%d",
				notice->z_sender,
				client->zct_principal->string,
				inet_ntoa (who->sin_addr),
				ntohs (who->sin_port)));
			return 0;
		    }
		}

		for (subs = subs2->q_forw;
		     subs != subs2;
		     subs = subs->q_forw, (*found)++);
		
		/* found is now the number of subscriptions */

		/* coalesce the subscription information into a list of
		   char *'s */
		if ((answer = (char **) xmalloc((*found) * NUM_FIELDS * sizeof(char *))) == (char **) 0) {
			syslog(LOG_ERR, "subscr no mem(answer)");
			*found = 0;
		} else
			for (i = 0, subs = subs2->q_forw;
			     i < *found ;
			     i++, subs = subs->q_forw) {
				answer[i*NUM_FIELDS] = subs->zst_dest.classname->string;
				answer[i*NUM_FIELDS + 1] = subs->zst_dest.inst->string;
				answer[i*NUM_FIELDS + 2] = subs->zst_dest.recip->string;
			}
	}
	if (defsubs)
		free_subscriptions(subs2);
	return(answer);
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
	Zconst char **answer;
	struct sockaddr_in send_to_who;
	register int i;

	new_compat_count_subscr++;

	syslog(LOG_INFO, "new old subscr, %s", inet_ntoa(who->sin_addr));
	reply = *notice;
	reply.z_kind = SERVACK;
	reply.z_authent_len = 0; /* save some space */
	reply.z_auth = 0;

	send_to_who = *who;
	send_to_who.sin_port = notice->z_port;  /* Return port */

	if ((retval = ZSetDestAddr(&send_to_who)) != ZERR_NONE) {
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
	i = 0;				/* pkt # counter */
#if 0
	zdbug((LOG_DEBUG,"Found %d subscriptions for %d packets",
	       found,count));
#endif
	initfound = found;
	zerofound = (found == 0);
	while (found > 0 || zerofound) {
		packlen = sizeof(reppacket);
		(void) sprintf(buf, "%d/%d", ++i, count);
		reply.z_opcode = buf;
		retval = ZFormatSmallRawNoticeList(&reply,
						   answer+(initfound-found)*NUM_FIELDS,
						   ((found > 5) ? 5 : found)*NUM_FIELDS,
						   reppacket,
						   &packlen);
		if (retval != ZERR_NONE) {
			syslog(LOG_ERR, "subscr_sendlist format: %s",
			       error_message(retval));
			if (answer)
				xfree(answer);
			return;
		}
		if ((retval = ZSendPacket(reppacket, packlen, 0)) != ZERR_NONE) {
			syslog(LOG_WARNING, "subscr_sendlist xmit: %s",
			       error_message(retval));
			if (answer)
				xfree(answer);
			return;
		}
		found -= 5;
		zerofound = 0;
	}
#if 0
	zdbug((LOG_DEBUG,"subscr_sendlist acked"));
#endif
	if (answer)
		xfree(answer);
	return;
}
#endif /* NEW_COMPAT */

#ifdef OLD_COMPAT
static void
old_compat_subscr_sendlist(notice, auth, who)
     ZNotice_t *notice;
     int auth;
     struct sockaddr_in *who;
{
	ZClient_t *client = client_which_client(who, notice);
	register ZSubscr_t *subs;
	Code_t retval;
	ZNotice_t reply;
	ZPacket_t reppacket;
	int packlen, i, found = 0;
	char **answer = (char **) NULL;

	old_compat_count_subscr++;

	syslog(LOG_INFO, "old old subscr, %s", inet_ntoa(who->sin_addr));
	if (client && client->zct_subs) {

		/* check authenticity here.  The user must be authentic to get
		   a list of subscriptions. If he is not subscribed to
		   anything, the above test fails, and he gets a response
		   indicating no subscriptions */

		if (!auth) {
			clt_ack(notice, who, AUTH_FAILED);
			return;
		}

		for (subs = client->zct_subs->q_forw;
		     subs != client->zct_subs;
		     subs = subs->q_forw, found++);
		
		/* found is now the number of subscriptions */

		/* coalesce the subscription information into a list of
		   char *'s */
		if ((answer = (char **) xmalloc(found * NUM_FIELDS * sizeof(char *))) == (char **) 0) {
			syslog(LOG_ERR, "old_subscr_sendlist no mem(answer)");
			found = 0;
		} else
			for (i = 0, subs = client->zct_subs->q_forw;
			     i < found ;
			     i++, subs = subs->q_forw) {
				answer[i*NUM_FIELDS] = subs->zst_class;
				answer[i*NUM_FIELDS + 1] = subs->zst_classinst;
				answer[i*NUM_FIELDS + 2] = subs->zst_recipient;
			}
	}
	/* note that when there are no subscriptions, found == 0, so
	   we needn't worry about answer being NULL */

	reply = *notice;
	reply.z_kind = SERVACK;
	reply.z_authent_len = 0; /* save some space */
	reply.z_auth = 0;


	/* if it's too long, chop off one at a time till it fits */
	while ((retval = ZFormatSmallRawNoticeList(&reply,
					      answer,
					      found * NUM_FIELDS,
					      reppacket,
					      &packlen)) == ZERR_PKTLEN) {
		found--;
		reply.z_opcode = OLD_CLIENT_INCOMPSUBS;
	}
	if (retval != ZERR_NONE) {
		syslog(LOG_ERR, "old_subscr_sendlist format: %s",
		       error_message(retval));
		if (answer)
			xfree(answer);
		return;
	}
	if ((retval = ZSetDestAddr(who)) != ZERR_NONE) {
		syslog(LOG_WARNING, "subscr_sendlist set addr: %s",
		       error_message(retval));
		if (answer)
			xfree(answer);
		return;
	}
	if ((retval = ZSendPacket(reppacket, packlen, 0)) != ZERR_NONE) {
		syslog(LOG_WARNING, "subscr_sendlist xmit: %s",
		       error_message(retval));
		if (answer)
			xfree(answer);
		return;
	}
#if 0
	zdbug((LOG_DEBUG,"subscr_sendlist acked"));
#endif
	if (answer)
		xfree(answer);
	return;
}
#endif /* OLD_COMPAT */

/*
 * Send the client's subscriptions to another server
 */

/* version is currently unused; if necessary later versions may key off it
   to determine what to send to the peer (protocol changes) */

/*ARGSUSED*/
Code_t
subscr_send_subs(client, vers)
     ZClient_t *client;
     char *vers;
{
	register int i = 0;
	register ZSubscr_t *sub;
#ifdef KERBEROS	
	char buf[512];
	C_Block cblock;
#endif /* KERBEROS */
	char buf2[512];
	char *lyst[7 * NUM_FIELDS];
	int num = 0;
	Code_t retval;

#if 0
	zdbug((LOG_DEBUG, "send_subs"));
#endif
	(void) sprintf(buf2, "%d",ntohs(client->zct_sin.sin_port));

	lyst[num++] = buf2;

#ifdef KERBEROS
#ifdef NOENCRYPTION
	(void) memcpy((caddr_t)cblock, (caddr_t)client->zct_cblock, sizeof(C_Block));
#else
	des_ecb_encrypt(client->zct_cblock, cblock, serv_ksched.s, DES_ENCRYPT);
#endif

	if ((retval = ZMakeAscii(buf, sizeof(buf), cblock,
				 sizeof(C_Block))) != ZERR_NONE) {
#if 0
		zdbug((LOG_DEBUG,"zmakeascii failed: %s",
		       error_message(retval)));
#endif
	} else {
		lyst[num++] = buf;
#if 0
		zdbug((LOG_DEBUG,"cblock %s",buf));
#endif
	}		
#endif /* KERBEROS */
	if ((retval = bdump_send_list_tcp(SERVACK, client->zct_sin.sin_port,
					  ZEPHYR_ADMIN_CLASS,
					  num > 1 ? "CBLOCK" : "",
					  ADMIN_NEWCLT,
					  (char*)client->zct_principal->string,
					  "", lyst, num)) != ZERR_NONE ) {
		syslog(LOG_ERR, "subscr_send_subs newclt: %s",
		       error_message(retval));
		return(retval);
	}
	
	if (!client->zct_subs)
		return(ZERR_NONE);
	for (sub = client->zct_subs->q_forw;
	     sub != client->zct_subs;
	     sub = sub->q_forw) {
		/* for each subscription */
		lyst[i * NUM_FIELDS] = sub->zst_dest.classname->string;
		lyst[i * NUM_FIELDS + 1] = sub->zst_dest.inst->string;
		lyst[i * NUM_FIELDS + 2] = sub->zst_dest.recip->string;
		i++;
		if (i >= 7) {
			/* we only put 7 in each packet, so we don't
			   run out of room */
			if ((retval = bdump_send_list_tcp(ACKED,
							  client->zct_sin.sin_port,
							  ZEPHYR_CTL_CLASS, "",
							  CLIENT_SUBSCRIBE, "",
							  "", lyst,
							  i * NUM_FIELDS))
			    != ZERR_NONE) {
				syslog(LOG_ERR, "subscr_send_subs subs: %s",
				       error_message(retval));
				return(retval);
			}
			i = 0;
		}
	}
	if (i) {
		if ((retval = bdump_send_list_tcp(ACKED,
						  client->zct_sin.sin_port,
						  ZEPHYR_CTL_CLASS, "",
						  CLIENT_SUBSCRIBE, "", "",
						  lyst, i * NUM_FIELDS))
		    != ZERR_NONE) {
			syslog(LOG_ERR, "subscr_send_subs subs: %s",
			       error_message(retval));
			return(retval);
		}
	}
	return(ZERR_NONE);
}

/*
 * free the memory allocated for the list of subscriptions.
 */

static void
free_subscriptions(subs)
     register ZSubscr_t *subs;
{
	register ZSubscr_t *sub;

	for (sub = subs->q_forw; sub != subs; sub = subs->q_forw) {
		xremque(sub);
		free_zstring(sub->zst_dest.classname);
		free_zstring(sub->zst_dest.inst);
		free_zstring(sub->zst_dest.recip);
		xfree(sub);
	}
	free_zstring(subs->zst_dest.classname);
	free_zstring(subs->zst_dest.inst);
	free_zstring(subs->zst_dest.recip);
	xfree(subs);

	return;
}

#define	ADVANCE(xx)	{ cp += (strlen(cp) + 1); \
		  if (cp >= notice->z_message + notice->z_message_len) { \
			  syslog(LOG_WARNING, "malformed subscription %d", xx); \
			  return(subs); \
		  }}

/*
 * Parse the message body, returning a linked list of subscriptions, or
 * NULLZST if there are no subscriptions there.
 */

static ZSubscr_t *
extract_subscriptions(notice)
     register ZNotice_t *notice;
{
	register ZSubscr_t *subs = NULLZST, *subs2;
	register char *recip, *class_name, *classinst;
	register char *cp = notice->z_message;

	/* parse the data area for the subscriptions */
	while (cp < notice->z_message + notice->z_message_len) {
		class_name = cp;
		if (*cp == '\0')
			/* we've exhausted the subscriptions */
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
			return(subs);
		}
		if (!subs) {
			if (!(subs = (ZSubscr_t *)
			      xmalloc(sizeof(ZSubscr_t)))) {
				syslog(LOG_WARNING, "ex_subs: no mem");
				return(NULLZST);
			}
			subs->q_forw = subs->q_back = subs;
			subs->zst_dest.classname = subs->zst_dest.inst =
			  subs->zst_dest.recip = NULL;
		}
		if (!(subs2 = (ZSubscr_t *) xmalloc(sizeof(ZSubscr_t)))) {
			syslog(LOG_WARNING, "ex_subs: no mem 2");
			return(subs);
		}
		subs2->q_forw = subs2->q_back = subs2;
		subs2->zst_dest.classname = make_zstring(class_name,1);
		subs2->zst_dest.inst = make_zstring(classinst,1);
		subs2->zst_dest.recip = make_zstring(recip,0);
		
		xinsque(subs2, subs);
	}
	return(subs);
}

/*
 * print subscriptions in subs onto fp.
 * assumed to be called with SIGFPE blocked
 * (true if called from signal handler)
 */

void
subscr_dump_subs(fp, subs)
     FILE *fp;
     ZSubscr_t *subs;
{
	register ZSubscr_t *ptr;
	register char *p;

	if (!subs)			/* no subscriptions to dump */
	    return;

	for (ptr = subs->q_forw; ptr != subs; ptr = ptr->q_forw) {
		fputs("\t\t'", fp);
		subscr_quote(ptr->zst_dest.classname->string, fp);
		fputs("' '", fp);
		subscr_quote(ptr->zst_dest.inst->string, fp);
		fputs("' '", fp);
		subscr_quote(ptr->zst_dest.recip->string, fp);
		fputs("'\n", fp);
	}
	return;
}

