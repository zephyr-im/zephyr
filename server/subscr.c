/* This file is part of the Project Athena Zephyr Notification System.
 * It contains functions for managing subscription lists.
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
static char rcsid_subscr_s_c[] = "$Header$";
#endif SABER
#endif lint

/*
 * The subscription manager.
 *
 * External functions:
 *
 * Code_t subscr_subscribe(sin, notice)
 * struct sockaddr_in *sin;
 * ZNotice_t *notice;
 *
 * Code_t subscr_cancel(sin, notice)
 * struct sockaddr_in *sin;
 * ZNotice_t *notice;
 *
 * Code_t subscr_cancel_client(client)
 * ZClient_t *client;
 *
 * Code_t subscr_cancel_host(addr)
 * struct in_addr *addr;
 *
 * ZClientList_t *subscr_match_list(notice)
 * ZNotice_t *notice;
 *
 * void subscr_list_free(list)
 * ZClientList_t *list;
 *
 */

#include "zserver.h"

extern char *re_comp(), *rindex(), *index();
static ZSubscr_t *extract_subscriptions();
static int subscr_equiv(), clt_unique();
static void free_subscriptions(), free_sub();

/*
 * subscribe the client to types described in notice.
 */

Code_t
subscr_subscribe(who, notice)
ZClient_t *who;
ZNotice_t *notice;
{
	register ZSubscr_t *subs, *subs2, *newsubs, *subs3;
	ZAcl_t *acl;
	Code_t retval;

	if (who->zct_subs == NULLZST) {
		/* allocate a subscription head */
		if ((subs = (ZSubscr_t *) xmalloc(sizeof(ZSubscr_t))) == NULLZST)
			return(ENOMEM);
		subs->q_forw = subs->q_back = subs;
		who->zct_subs = subs;
	}

	if ((newsubs = extract_subscriptions(notice)) == NULLZST)
		return(ZERR_NONE);	/* no subscr -> no error */

	for (subs = newsubs->q_forw;
	     subs != newsubs;
	     subs = subs->q_forw) {
		/* for each new subscription */

		if ((acl = class_get_acl(subs->zst_class)) != NULLZACLT &&
		    !access_check(notice, acl, SUBSCRIBE)) {
			syslog(LOG_WARNING, "subscr unauth %s %s",
			       notice->z_sender, subs->zst_class);
			continue;
		}
		for (subs2 = who->zct_subs->q_forw;
		     subs2 != who->zct_subs;
		     subs2 = subs2->q_forw) {
			/* for each existing subscription */
			if (subscr_equiv(subs, subs2)) /* duplicate? */
				goto duplicate;
		}

		/* ok, we are a new subscription. register and chain on. */

		if ((subs3 = (ZSubscr_t *) xmalloc(sizeof(ZSubscr_t))) == NULLZST) {
			free_subscriptions(newsubs);
			return(ENOMEM);
		}

		if ((retval = class_register(who, subs->zst_class)) != ZERR_NONE) {
			free_subscriptions(newsubs);
			return(retval);
		}

		subs3->zst_class = strsave(subs->zst_class);
		subs3->zst_classinst = strsave(subs->zst_classinst);
		subs3->zst_recipient = strsave(subs->zst_recipient);
		subs3->q_forw = subs3->q_back = subs3;

		xinsque(subs3, who->zct_subs);

duplicate:	;			/* just go on to the next */
	}

	free_subscriptions(newsubs);
	return(ZERR_NONE);
}

/* are the subscriptions the same? 1=yes, 0=no */

static int
subscr_equiv(s1, s2)
register ZSubscr_t *s1, *s2;
{
	if (strcmp(s1->zst_class,s2->zst_class))
		return(0);
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

static ZSubscr_t *
extract_subscriptions(notice)
register ZNotice_t *notice;
{
	register ZSubscr_t *subs = NULLZST, *subs2;
	register char *recip, *class, *classinst;
	register char *cp = notice->z_message;
	char *buf;

	/* parse the data area for the subscriptions */
	while (cp < notice->z_message + notice->z_message_len) {
		class = buf = cp;
		if (*buf == '\0')
			/* we've exhausted the subscriptions */
			return(subs);
		zdbug2("class %s",cp);
		ADVANCE(1);
		classinst = buf = cp;
		zdbug2("clinst %s",cp);
		ADVANCE(2);
		recip = cp;
		zdbug2("recip %s",cp);
		cp += (strlen(cp) + 1);
		if (cp > notice->z_message + notice->z_message_len) {
			syslog(LOG_WARNING, "malformed sub 3");
			return(subs);
		}
		if (subs == NULLZST) {
			if ((subs = (ZSubscr_t *) xmalloc(sizeof(ZSubscr_t))) == NULLZST) {
				syslog(LOG_WARNING, "ex_subs: no mem");
				return(NULLZST);
			}
			subs->q_forw = subs->q_back = subs;
			subs->zst_class = subs->zst_classinst = subs->zst_recipient = NULL;
		}
		if ((subs2 = (ZSubscr_t *) xmalloc(sizeof(ZSubscr_t))) == NULLZST) {
			syslog(LOG_WARNING, "ex_subs: no mem 2");
			return(subs);
		}
		subs2->zst_class = strsave(class);
		subs2->zst_classinst = strsave(classinst);
		subs2->zst_recipient = strsave(recip);
		subs2->q_forw = subs2->q_back = subs2;

		xinsque(subs2, subs);
	}
	return(subs);
}

static void
free_subscriptions(subs)
register ZSubscr_t *subs;
{
	register ZSubscr_t *sub;

	for (sub = subs->q_forw; sub != subs; sub = subs->q_forw) {
		xfree(sub->zst_class);
		xfree(sub->zst_classinst);
		xfree(sub->zst_recipient);
		xremque(sub);
		xfree(sub);
	}
	xfree(subs);
	return;
}

Code_t
subscr_cancel(sin,notice)
struct sockaddr_in *sin;
ZNotice_t *notice;
{
	ZClient_t *who;
	register ZSubscr_t *subs, *subs2;
	Code_t retval;

	zdbug1("subscr_cancel");
	if ((who = client_which_client(sin, notice)) == NULLZCNT)
		return(ZSRV_NOCLT);

	if (who->zct_subs == NULLZST)
		return(ZSRV_NOSUB);

	if ((subs = extract_subscriptions(notice)) == NULLZST)
		return(ZERR_NONE);	/* no subscr -> no error */

	for (subs2 = who->zct_subs->q_forw;
	     subs2 != who->zct_subs;
	     subs2 = subs2->q_forw) {
		/* for each existing subscription */
		/* is this what we are canceling? */
		if (subscr_equiv(subs, subs2)) { 
			xremque(subs2);
			if (class_deregister(who, subs2->zst_class) != ZERR_NONE) {
				syslog(LOG_ERR, "subscr_cancel: not registered!");
				abort();
				/*NOTREACHED*/
			}
			free_sub(subs2);
			/* make sure we are still registered for all the
			   classes */
			for (subs2 = who->zct_subs->q_forw;
			     subs2 != who->zct_subs;
			     subs2 = subs2->q_forw)
				if ((retval = class_register(who, subs2->zst_class)) != ZERR_NONE)
					return(retval);
			return(ZERR_NONE);
		}
	}
	return(ZSRV_NOSUB);
}

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

void
subscr_cancel_client(client)
register ZClient_t *client;
{
	register ZSubscr_t *subs;

	zdbug1("subscr_cancel_client");
	if (client->zct_subs == NULLZST)
		return;
	
	for (subs = client->zct_subs->q_forw;
	     subs != client->zct_subs;
	     subs = client->zct_subs->q_forw) {
		zdbug2("sub_can %s",subs->zst_class);
		if (class_deregister(client, subs->zst_class) != ZERR_NONE) {
			zdbug1("sub_can_clt: not registered!");
		}

		xremque(subs);
		free_sub(subs);
	}

	/* also flush the head of the queue */
	/* subs is now client->zct_subs */
	xfree(subs);
	client->zct_subs = NULLZST;

	return;
}

Code_t
subscr_cancel_host(addr)
struct in_addr *addr;
{
	register ZHostList_t *hosts;
	register ZClientList_t *clist = NULLZCLT, *clt;

	if ((hosts = hostm_find_host(addr)) == NULLZHLT)
		return(ZSRV_HNOTFOUND);
	clist = hosts->zh_clients;

	/* flush each one */
	for (clt = clist->q_forw; clt != clist; clt = clt->q_forw)
		(void) subscr_cancel_client(clt->zclt_client);
	return(ZERR_NONE);
}

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

	if ((hits = (ZClientList_t *) xmalloc(sizeof(ZClientList_t))) == NULLZCLT)
		return(NULLZCLT);
	hits->q_forw = hits->q_back = hits;

	if ((clients = class_lookup(notice->z_class)) == NULLZCLT) {
		if  ((majik = class_lookup(MATCHALL_CLASS)) == NULLZCLT)
			return(NULLZCLT);
	} else
		majik = class_lookup(MATCHALL_CLASS);

	if (clients != NULLZCLT)
		for (clients2 = clients->q_forw;
		     clients2 != clients;
		     clients2 = clients2->q_forw)
			if (cl_match(notice, clients2->zclt_client)) {
				if (!clt_unique(clients2->zclt_client, hits)) {
					zdbug2("dup 0x%x", clients2->zclt_client);
					continue;
				}
				zdbug2("matched 0x%x", clients2->zclt_client);
				/* we hit */
				if ((hit2 = (ZClientList_t *) xmalloc(sizeof(ZClientList_t))) == NULLZCLT) {
					syslog(LOG_WARNING,
					       "subscr_match: punting/no mem");
					return(hits);
				}
				hit2->zclt_client = clients2->zclt_client;
				hit2->q_forw = hit2->q_back = hit2;

				xinsque(hit2, hits);
			} else zdbug2("didn't match 0x%x",
				      clients2->zclt_client);
	
	if (majik != NULLZCLT)
		for (clients2 = majik->q_forw;
		     clients2 != majik;
		     clients2 = clients2->q_forw) {
			if (!clt_unique(clients2->zclt_client, hits)) {
				zdbug2("dup 0x%x", clients2->zclt_client);
				continue;
			}
			zdbug2("matched 0x%x", clients2->zclt_client);
			/* we hit */
			if ((hit2 = (ZClientList_t *) xmalloc(sizeof(ZClientList_t))) == NULLZCLT) {
				syslog(LOG_WARNING,
				       "subscr_match(majik): punting/no mem");
				return(hits);
			}
			hit2->zclt_client = clients2->zclt_client;
			hit2->q_forw = hit2->q_back = hit2;

			xinsque(hit2, hits);
		}
	if (hits->q_forw == hits)
		return(NULLZCLT);
	return(hits);
}

void
subscr_list_free(list)
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
	char *reresult;

	if (client->zct_subs == NULLZST) {
		syslog(LOG_WARNING, "cl_match w/ no subs");
		return(0);
	}
		
	for (subs = client->zct_subs->q_forw;
	     subs != client->zct_subs;
	     subs = subs->q_forw) {
		/* for each subscription, do regex matching */
		/* we don't regex the class, since wildcard
		   matching on the class is disallowed. */
		if (strcmp(notice->z_class, subs->zst_class))
			continue;	/* no match */
		if ((reresult = re_comp(subs->zst_classinst)) != NULL) {
			syslog(LOG_WARNING, "re_comp error %s on '%s'",
			       reresult, subs->zst_classinst);
			continue;
		}
		if (!re_exec(notice->z_class_inst))
			continue;
		if ((reresult = re_comp(subs->zst_recipient)) != NULL) {
			syslog(LOG_WARNING, "re_comp error %s on '%s'",
			       reresult, subs->zst_recipient);
			continue;
		}
		if (!re_exec(notice->z_recipient))
			continue;
		/* OK, we matched */
		return(1);
	}
	/* fall through */
	return(0);
}	
