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
static char rcsid_subscr_c[] = "$Header$";
#endif SABER
#endif lint

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
#include <sys/stat.h>

/* for compatibility when sending subscription information to old clients */
#ifdef OLD_COMPAT
#define	OLD_ZEPHYR_VERSION	"ZEPH0.0"
#define	OLD_CLIENT_INCOMPSUBS	"INCOMP"
static void old_compat_subscr_sendlist();
#endif /* OLD_COMPAT */
#ifdef NEW_COMPAT
#define NEW_OLD_ZEPHYR_VERSION	"ZEPH0.1"
static void new_old_compat_subscr_sendlist();
#endif /* NEW_COMPAT */

extern char *re_comp(), *re_conv(), *rindex(), *index();
static ZSubscr_t *extract_subscriptions();
static int subscr_equiv(), clt_unique();
static void free_subscriptions(), free_sub();
static char **subscr_marshal_subs();
static Code_t subscr_subscribe_real();
static ZSubscr_t *subscr_copy_def_subs();

static int defaults_read = 0;		/* set to 1 if the default subs
					   are in memory */
static ZNotice_t default_notice;	/* contains default subscriptions */

static ZSubscr_t matchall_sub = {
	(ZSubscr_t *) 0,
	(ZSubscr_t *) 0,
	MATCHALL_CLASS,
	"",
	"" };

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
	ZSubscr_t *subs;
	

	if (!who->zct_subs) {
		/* allocate a subscription head */
		if (!(subs = (ZSubscr_t *) xmalloc(sizeof(ZSubscr_t))))
			return(ENOMEM);
		subs->q_forw = subs->q_back = subs;
		who->zct_subs = subs;
	}

	if (!(subs = extract_subscriptions(notice)))
		return(ZERR_NONE);	/* no subscr -> no error */

	return(subscr_subscribe_real(who, subs, notice));
}

static Code_t
subscr_subscribe_real(who, newsubs, notice)
ZClient_t *who;
register ZSubscr_t *newsubs;
ZNotice_t *notice;
{
	int relation;
	int omask;
	Code_t retval;
	ZAcl_t *acl;
	register ZSubscr_t *subs2, *subs3, *subs;

	omask = sigblock(sigmask(SIGFPE)); /* don't let db dumps start */
	for (subs = newsubs->q_forw;
	     subs != newsubs;
	     subs = subs->q_forw) {
		/* for each new subscription */

		if (!bdumping && *(subs->zst_recipient) &&
		    strcmp(subs->zst_recipient, notice->z_sender)) {
		    syslog(LOG_WARNING, "subscr unauth to rcpt %s by %s",
			   subs->zst_recipient,
			   notice->z_sender);
		    continue;
		}
		acl = class_get_acl(subs->zst_class);
		if (acl) {
			if (!access_check(notice, acl, SUBSCRIBE)) {
				syslog(LOG_WARNING, "subscr unauth %s %s",
				       notice->z_sender, subs->zst_class);
				continue; /* the for loop */
			}
			if (!strcmp(WILDCARD_INSTANCE, subs->zst_classinst)) {
				if (!access_check(notice, acl, INSTWILD)) {
					syslog(LOG_WARNING,
					       "subscr unauth wild %s %s.*",
					       notice->z_sender,
					       subs->zst_class);
					continue;
				}
			}
		}
		for (subs2 = who->zct_subs->q_forw;
		     subs2 != who->zct_subs;
		     subs2 = subs2->q_forw) {
			/* for each existing subscription */
			relation = strcmp(subs->zst_class, subs2->zst_class);
			if (relation > 0) /* we have passed the last
					     possible one */
				break;
			if (relation < 0) /* nope... */
				continue;
			if (subscr_equiv(subs, subs2)) /* duplicate? */
				goto duplicate;
		}
		/* subs2 now points to the first class which is greater
		   than the new class. We need to back up so that the
		   insertion below goes BEFORE this one (i.e. after the
		   previous one) */
		subs2 = subs2->q_back;

		/* ok, we are a new subscription. register and chain on. */

		if (!(subs3 = (ZSubscr_t *) xmalloc(sizeof(ZSubscr_t)))) {
			free_subscriptions(newsubs);
			(void) sigsetmask(omask);
			return(ENOMEM);
		}

		if ((retval = class_register(who, subs)) != ZERR_NONE) {
			xfree(subs3);
			free_subscriptions(newsubs);
			(void) sigsetmask(omask);
			return(retval);
		}

		subs3->zst_class = strsave(subs->zst_class);
		subs3->zst_classinst = strsave(subs->zst_classinst);
		subs3->zst_recipient = strsave(subs->zst_recipient);

		subs3->q_forw = subs3->q_back = subs3;

		/* subs2 was adjusted above */
		xinsque(subs3, subs2);

duplicate:	;			/* just go on to the next */
	}
	(void) sigsetmask(omask);

	free_subscriptions(newsubs);
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
		who->zct_subs = subs;
	}

	subs = subscr_copy_def_subs(who->zct_principal);
	return(subscr_subscribe_real(who, subs, &default_notice));
}

void
subscr_reset()
{
	zdbug((LOG_DEBUG, "subscr_reset()"));
	xfree(default_notice.z_message);
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
		zdbug((LOG_DEBUG, "reading default subscription file"));
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
		if (!(def_sub_area = xmalloc(statbuf.st_size + 1))) {
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
		default_notice.z_message_len = statbuf.st_size + 1;
		default_notice.z_auth = 1;
		defaults_read = 1;
	}
	/* needed later for access_check() */
	default_notice.z_sender = person;
	subs = extract_subscriptions(&default_notice);
	/* replace any non-* recipients with "person" */

	for (subs2 = subs->q_forw; subs2 != subs; subs2 = subs2->q_forw)
		/* if not a wildcard, replace it with person */
		if (strcmp(subs2->zst_recipient, "*")) {
			subs2->zst_recipient = person;
		} else {		/* replace with null recipient */
			subs2->zst_recipient = "";
		}
	return(subs);
}

/*
 * Cancel one subscription.
 */

Code_t
subscr_cancel(sin, notice)
struct sockaddr_in *sin;
ZNotice_t *notice;
{
	ZClient_t *who;
	register ZSubscr_t *subs, *subs2, *subs3, *subs4;
	Code_t retval;
	int found = 0, relation;
	int omask;

	zdbug((LOG_DEBUG,"subscr_cancel"));
	if (!(who = client_which_client(sin, notice)))
		return(ZSRV_NOCLT);

	if (!who->zct_subs)
		return(ZSRV_NOSUB);

	if (!(subs = extract_subscriptions(notice)))
		return(ZERR_NONE);	/* no subscr -> no error */

	
	omask = sigblock(sigmask(SIGFPE)); /* don't let db dumps start */
	for (subs4 = subs->q_forw;
	     subs4 != subs;
	     subs4 = subs4->q_forw)
		for (subs2 = who->zct_subs->q_forw;
		     subs2 != who->zct_subs;) {
			/* for each existing subscription */
			/* is this what we are canceling? */
			relation = strcmp(subs4->zst_class, subs2->zst_class);
			if (relation > 0) /* we have passed the last
					     possible one */
				break;
			if (relation < 0) { /* nope... */
				subs2 = subs2->q_forw;
				continue;
			}
			if (subscr_equiv(subs4, subs2)) { 
				/* go back, since remque will change things */
				subs3 = subs2->q_back;
				xremque(subs2);
				(void) class_deregister(who, subs2);
				free_sub(subs2);
				found = 1;
				/* now that the remque adjusted the linked
				   list, we go forward again */
				subs2 = subs3->q_forw;
			} else {
				zdbug((LOG_DEBUG, "not %s.%s.%s",
				       subs2->zst_class,
				       subs2->zst_classinst,
				       subs2->zst_recipient));
				subs2 = subs2->q_forw;
				       
			}
		}
	/* make sure we are still registered for all the
	   classes */
	if (found)
		for (subs2 = who->zct_subs->q_forw;
		     subs2 != who->zct_subs;
		     subs2 = subs2->q_forw)
			if ((retval = class_register(who, subs2)) != ZERR_NONE) {
				free_subscriptions(subs);
				(void) sigsetmask(omask);
				return(retval);
			}
	(void) sigsetmask(omask);
	free_subscriptions(subs);
	if (found) {
		zdbug((LOG_DEBUG, "found & removed"));
		return(ZERR_NONE);
	} else {
		zdbug((LOG_DEBUG, "not found"));
		return(ZSRV_NOSUB);
	}
}

/*
 * Cancel all the subscriptions for this client.
 */

void
subscr_cancel_client(client)
register ZClient_t *client;
{
	register ZSubscr_t *subs;
	int omask;

	zdbug((LOG_DEBUG,"subscr_cancel_client"));
	if (!client->zct_subs)
		return;
	
	omask = sigblock(sigmask(SIGFPE)); /* don't let db dumps start */
	for (subs = client->zct_subs->q_forw;
	     subs != client->zct_subs;
	     subs = client->zct_subs->q_forw) {
		zdbug((LOG_DEBUG,"sub_can %s",subs->zst_class));
		if (class_deregister(client, subs) != ZERR_NONE) {
			zdbug((LOG_DEBUG,"sub_can_clt: not registered!"));
		}

		xremque(subs);
		free_sub(subs);
	}

	/* also flush the head of the queue */
	/* subs is now client->zct_subs */
	xfree(subs);
	client->zct_subs = NULLZST;

	(void) sigsetmask(omask);
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
	int omask;

	/* find the host */
	if (!(hosts = hostm_find_host(addr)))
		return(ZSRV_HNOTFOUND);
	clist = hosts->zh_clients;

	omask = sigblock(sigmask(SIGFPE)); /* don't let db dumps start */
	/* flush each one */
	for (clt = clist->q_forw; clt != clist; clt = clt->q_forw)
		(void) subscr_cancel_client(clt->zclt_client);
	(void) sigsetmask(omask);
	return(ZERR_NONE);
}
#endif notdef

/*
 * Here is the bulk of the work in the subscription manager.
 * We grovel over the list of clients possibly interested in this
 * notice, and copy into a list on a match.  Make sure we only add any given
 * client once.
 */

ZClientList_t *
subscr_match_list(notice)
ZNotice_t *notice;
{
	register ZClientList_t *hits, *clients, *majik, *clients2, *hit2;
	register char *cp;
	char *newclass, *saveclass, *newclinst, *saveclinst;
	ZSubscr_t check_sub;

	if (!(hits = (ZClientList_t *) xmalloc(sizeof(ZClientList_t))))
		return(NULLZCLT);
	hits->q_forw = hits->q_back = hits;

	
	saveclass = notice->z_class;
	cp = newclass = strsave(notice->z_class);

	while (*cp) {
		if (isupper(*cp))
			*cp = tolower(*cp);
		cp++;
	}
	saveclinst = notice->z_class_inst;
	cp = newclinst = strsave(notice->z_class_inst);

	while (*cp) {
		if (isupper(*cp))
			*cp = tolower(*cp);
		cp++;
	}

	check_sub.zst_class = newclass;
	check_sub.zst_classinst = newclinst;
	check_sub.zst_recipient = notice->z_recipient;
	check_sub.q_forw = check_sub.q_back = &check_sub;

	if (!(clients = class_lookup(&check_sub))) {
		if  (!(majik = class_lookup(&matchall_sub))) {
			notice->z_class = saveclass;
			notice->z_class_inst = saveclinst;
			xfree(newclass);
			xfree(newclinst);
			xfree(hits);
			return(NULLZCLT);
		}
	} else
		majik = class_lookup(&matchall_sub);

	notice->z_class = newclass;
	notice->z_class_inst = newclinst;
	if (clients) {
		for (clients2 = clients->q_forw;
		     clients2 != clients;
		     clients2 = clients2->q_forw)
			if (cl_match(notice, clients2->zclt_client)) {
				if (!clt_unique(clients2->zclt_client, hits))
					continue;
				/* we hit */
				if (!(hit2 = (ZClientList_t *) xmalloc(sizeof(ZClientList_t)))) {
					syslog(LOG_WARNING,
					       "subscr_match: punting/no mem");
					notice->z_class = saveclass;
					xfree(newclass);
					notice->z_class_inst = saveclinst;
					xfree(newclinst);
					return(hits);
				}
				hit2->zclt_client = clients2->zclt_client;
				hit2->q_forw = hit2->q_back = hit2;
				xinsque(hit2, hits);
			}
		class_free(clients);
	}
	if (majik) {
		for (clients2 = majik->q_forw;
		     clients2 != majik;
		     clients2 = clients2->q_forw) {
			if (!clt_unique(clients2->zclt_client, hits))
				continue;
			/* we hit */
			if (!(hit2 = (ZClientList_t *) xmalloc(sizeof(ZClientList_t)))) {
				syslog(LOG_WARNING,
				       "subscr_match(majik): punting/no mem");
				notice->z_class = saveclass;
				xfree(newclass);
				notice->z_class_inst = saveclinst;
				xfree(newclinst);
				return(hits);
			}
			hit2->zclt_client = clients2->zclt_client;
			hit2->q_forw = hit2->q_back = hit2;

			xinsque(hit2, hits);
		}
		class_free(majik);
	}
	notice->z_class = saveclass;
	xfree(newclass);
	notice->z_class_inst = saveclinst;
	xfree(newclinst);
	if (hits->q_forw == hits) {
		xfree(hits);
		return(NULLZCLT);
	}
	return(hits);
}

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

	if ((retval = ZSrvSendRawList(notice, answer, found*NUM_FIELDS,
				      xmit_frag))
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
	char **answer = (char **) NULL;
	int temp;
	Code_t retval;
	ZClient_t *client;
	register ZSubscr_t *subs, *subs2 = NULLZST;
	register int i;
	int defsubs = 0;

	zdbug((LOG_DEBUG, "subscr_marshal"));
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
		zdbug((LOG_DEBUG, "gimmedefs"));
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
				answer[i*NUM_FIELDS] = subs->zst_class;
				answer[i*NUM_FIELDS + 1] = subs->zst_classinst;
				answer[i*NUM_FIELDS + 2] = subs->zst_recipient;
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
	char **answer;
	struct sockaddr_in send_to_who;
	register int i;

	zdbug((LOG_DEBUG, "new_old_compat_subscr_sendlist"));
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
	zdbug((LOG_DEBUG,"Found %d subscriptions for %d packets",
	       found,count));
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
	zdbug((LOG_DEBUG,"subscr_sendlist acked"));
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

	zdbug((LOG_DEBUG, "old_compat_subscr_sendlist"));
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
	zdbug((LOG_DEBUG,"subscr_sendlist acked"));
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
#endif /* KERBEROS */
	char buf2[512], *lyst[7 * NUM_FIELDS];
	int num = 0;
	Code_t retval;

	zdbug((LOG_DEBUG, "send_subs"));
	(void) sprintf(buf2, "%d",ntohs(client->zct_sin.sin_port));

	lyst[num++] = buf2;

#ifdef KERBEROS
	if ((retval = ZMakeAscii(buf, sizeof(buf), client->zct_cblock,
				 sizeof(C_Block))) != ZERR_NONE) {
		zdbug((LOG_DEBUG,"zmakeascii failed: %s",
		       error_message(retval)));
	} else {
		lyst[num++] = buf;
		zdbug((LOG_DEBUG,"cblock %s",buf));
	}		
#endif KERBEROS
	if ((retval = bdump_send_list_tcp(SERVACK, bdump_sin.sin_port,
					  ZEPHYR_ADMIN_CLASS,
					  num > 1 ? "CBLOCK" : "",
					  ADMIN_NEWCLT, client->zct_principal,
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
		lyst[i * NUM_FIELDS] = sub->zst_class;
		lyst[i * NUM_FIELDS + 1] = sub->zst_classinst;
		lyst[i * NUM_FIELDS + 2] = sub->zst_recipient;
		i++;
		if (i > 7) {
			/* we only put 7 in each packet, so we don't
			   run out of room */
			if ((retval = bdump_send_list_tcp(ACKED,
							  bdump_sin.sin_port,
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
		if ((retval = bdump_send_list_tcp(ACKED, bdump_sin.sin_port,
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
 * is this client unique to this list?  0 = no, 1 = yes
 */

static int
clt_unique(clt, clist)
ZClient_t *clt;
ZClientList_t *clist;
{
	register ZClientList_t *client;

	for (client = clist->q_forw;
	     client != clist;
	     client = client->q_forw)
		if (client->zclt_client == clt)
			return(0);
	return(1);
}

/*
 * is this client listening to this notice? 1=yes, 0=no
 */

static int
cl_match(notice, client)
register ZNotice_t *notice;
register ZClient_t *client;
{
	register ZSubscr_t *subs;
	int relation;

	if (client->zct_subs == NULLZST) {
		syslog(LOG_WARNING, "cl_match w/ no subs");
		return(0);
	}
		
	for (subs = client->zct_subs->q_forw;
	     subs != client->zct_subs;
	     subs = subs->q_forw) {
		/* for each subscription, do matching */
		relation = strcmp(notice->z_class, subs->zst_class);
		if (relation > 0)	/* past the last possible one */
			return(0);
		if (relation < 0)
			continue;	/* no match */
		if (strcmp(subs->zst_classinst, WILDCARD_INSTANCE) &&
		    strcmp(subs->zst_classinst, notice->z_class_inst))
			continue;
		if (strcmp(notice->z_recipient, subs->zst_recipient))
			continue;
		return(1);
	}
	/* fall through */
	return(0);
}	

/*
 * Free up a subscription
 */

static void
free_sub(sub)
ZSubscr_t *sub;
{
	xfree(sub->zst_class);
	xfree(sub->zst_classinst);
	xfree(sub->zst_recipient);
	xfree(sub);
	return;
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
		xfree(sub);
	}
	xfree(subs);
	return;
}

/*
 * are the subscriptions the same? 1=yes, 0=no
 */

static int
subscr_equiv(s1, s2)
register ZSubscr_t *s1, *s2;
{
	if (strcmp(s1->zst_classinst,s2->zst_classinst))
		return(0);
	if (strcmp(s1->zst_recipient,s2->zst_recipient))
		return(0);
	return(1);
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
	register char *recip, *class, *classinst;
	register char *cp = notice->z_message;

	/* parse the data area for the subscriptions */
	while (cp < notice->z_message + notice->z_message_len) {
		class = cp;
		if (*cp == '\0')
			/* we've exhausted the subscriptions */
			return(subs);
		/* we lowercase the class and class instance
		   so we can be case insensitive on comparisons */
		while (*cp) {
			if (isupper(*cp))
				*cp = tolower(*cp);
			cp++;
		}
		cp = class;
		ADVANCE(1);
		classinst = cp;
		while (*cp) {
			if (isupper(*cp))
				*cp = tolower(*cp);
			cp++;
		}
		cp = classinst;
		ADVANCE(2);
		recip = cp;
		zdbug((LOG_DEBUG,"CLS: %s INST: %s RCPT: %s",
		       class, classinst, cp));
		cp += (strlen(cp) + 1);
		if (cp > notice->z_message + notice->z_message_len) {
			syslog(LOG_WARNING, "malformed sub 3");
			return(subs);
		}
		if (!subs) {
			if (!(subs = (ZSubscr_t *) xmalloc(sizeof(ZSubscr_t)))) {
				syslog(LOG_WARNING, "ex_subs: no mem");
				return(NULLZST);
			}
			subs->q_forw = subs->q_back = subs;
			subs->zst_class = subs->zst_classinst = subs->zst_recipient = NULL;
		}
		if (!(subs2 = (ZSubscr_t *) xmalloc(sizeof(ZSubscr_t)))) {
			syslog(LOG_WARNING, "ex_subs: no mem 2");
			return(subs);
		}
		subs2->zst_class = class;
		subs2->zst_classinst = classinst;
		subs2->zst_recipient = recip;
		subs2->q_forw = subs2->q_back = subs2;

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

	if (!subs)			/* no subscriptions to dump */
	    return;

	for (ptr = subs->q_forw; ptr != subs; ptr = ptr->q_forw) {
		fputs("\t\t'", fp);
		fputs(ptr->zst_class, fp);
		fputs("' '", fp);
		fputs(ptr->zst_classinst, fp);
		fputs("' '", fp);
		fputs(ptr->zst_recipient, fp);
		fputs("'\n", fp);
	}
	return;
}
