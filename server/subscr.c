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
static char rcsid_subscr_s_c[] = "$Header$";
#endif lint

/*
 * The subscription manager.
 *
 * External functions:
 *
 * Code_t subscr_subscribe(notice)
 * ZNotice_t *notice;
 *
 * Code_t subscr_cancel(notice)
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
static int subscr_equiv();
static void free_subscriptions(), free_sub();

Code_t
subscr_subscribe(notice)
ZNotice_t *notice;
{
	ZClient_t *who;
	register ZSubscr_t *subs, *subs2, *newsubs, *subs3;
	Code_t retval;

	if ((who = client_which_client(notice)) == NULLZCNT)
		return(ZSRV_NOCLT);

	if (who->zct_subs == NULLZST) {
		/* allocate a subscription head */
		if ((subs = (ZSubscr_t *) malloc(sizeof(ZSubscr_t))) == NULLZST)
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

		for (subs2 = who->zct_subs->q_forw;
		     subs2 != who->zct_subs;
		     subs2 = subs2->q_forw) {
			/* for each existing subscription */
			if (subscr_equiv(subs, subs2)) /* duplicate? */
				goto duplicate;
		}

		/* ok, we are a new subscription. register and chain on. */

		if ((subs3 = (ZSubscr_t *) malloc(sizeof(ZSubscr_t))) == NULLZST) {
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

		insque(who->zct_subs, subs3);

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

static ZSubscr_t *
extract_subscriptions(notice)
register ZNotice_t *notice;
{
	register ZSubscr_t *subs = NULLZST, *subs2;
	register int len = notice->z_message_len;
	register char *recip, *class, *classinst;
	register char *cp = notice->z_message;
	char *buf;

	/* parse the data area for the subscriptions */
	while (cp < notice->z_message + notice->z_message_len) {
		recip = buf = cp;
		if ((cp = index(buf, ',')) == NULL) {
			syslog(LOG_WARNING, "malformed subscription 1 %s",
			       buf);
			return(subs);
		}
		*cp++ = '\0';
		class = buf = cp;
		if ((cp = index(buf, ',')) == NULL) {
			syslog(LOG_WARNING, "malformed subscription 2 %s",
			       buf);
			return(subs);
		}
		*cp++ = '\0';
		classinst = cp;
		cp += strlen(classinst);
		if (subs == NULLZST) {
			if ((subs = (ZSubscr_t *) malloc(sizeof(ZSubscr_t))) == NULLZST) {
				syslog(LOG_WARNING, "ex_subs: no mem");
				return(NULLZST);
			}
			subs->q_forw = subs->q_back = subs;
		}
		if ((subs2 = (ZSubscr_t *) malloc(sizeof(ZSubscr_t))) == NULLZST) {
			syslog(LOG_WARNING, "ex_subs: no mem 2");
			return(NULLZST);
		}
		subs2->zst_class = strsave(class);
		subs2->zst_classinst = strsave(classinst);
		subs2->zst_recipient = strsave(recip);

		insque(subs, subs2);
	}
	return;
}

static void
free_subscriptions(subs)
register ZSubscr_t *subs;
{
	register ZSubscr_t *sub;

	free(subs->zst_class);
	free(subs->zst_classinst);
	free(subs->zst_recipient);

	for (sub = subs->q_forw; sub != subs; sub = subs->q_forw) {
		free(sub->zst_class);
		free(sub->zst_classinst);
		free(sub->zst_recipient);
		remque(sub);
		free(sub);
	}
	free(subs);
	return;
}

Code_t
subscr_cancel(notice)
ZNotice_t *notice;
{
	ZClient_t *who;
	register ZSubscr_t *subs, *subs2;
	Code_t retval;

	if ((who = client_which_client(notice)) == NULLZCNT)
		return(ZSRV_NOCLT);

	if (who->zct_subs == NULLZST)
		return(ZSRV_NOSUB);

	if ((subs = extract_subscriptions(notice)) == NULLZST)
		return(ZERR_NONE);	/* no subscr -> no error */

	for (subs2 = who->zct_subs->q_forw;
	     subs2 != who->zct_subs;
	     subs2 = subs2->q_forw) {
		/* for each existing subscription */
		if (subscr_equiv(subs, subs2)) { /* duplicate? */
			remque(subs2);
			if (class_deregister(who, subs2->zst_class) != ZERR_NONE) {
				syslog(LOG_ERR, "subscr_cancel: not registered!");
				abort();
				/*NOTREACHED*/
			}
			free_sub(subs2);
			return(ZERR_NONE);
		}
	}
	return(ZSRV_NOSUB);
}

static void
free_sub(sub)
ZSubscr_t *sub;
{
	free(sub->zst_class);
	free(sub->zst_classinst);
	free(sub->zst_recipient);
	free(sub);
	return;
}

Code_t
subscr_cancel_client(client)
register ZClient_t *client;
{
	register ZSubscr_t *subs;

	if (client->zct_subs == NULLZST)
		return(ZERR_NONE);
	
	for (subs = client->zct_subs->q_forw;
	     subs != client->zct_subs;
	     subs = client->zct_subs->q_forw) {
		if (class_deregister(client, subs->zst_class) != ZERR_NONE) {
			syslog(LOG_ERR, "sub_can_clt: not registered!");
			abort();
			/*NOTREACHED*/
		}
		remque(subs);
		free_sub(subs);
	}
	return(ZERR_NONE);
}

Code_t
subscr_cancel_host(addr, server)
struct in_addr *addr;
ZServerDesc_t *server;
{
	register ZHostList_t *hosts;
	register ZClientList_t *clist = NULLZCLT, *clt;

	/* find list of clients */
	for (hosts = server->zs_hosts;
	     hosts != server->zs_hosts;
	     hosts = hosts->q_forw) {
		if (!bcmp(*addr, hosts->zh_addr, sizeof (struct in_addr))) {
			clist = hosts->zh_clients;
			break;
		}
	}
	if (hosts != server->zs_hosts)
		return(ZSRV_WRONGSRV);

	/* flush each one */
	for (clt = clist->q_forw; clt != clist; clt = clt->q_forw)
		(void) subscr_cancel_client(clt);
	return(ZERR_NONE);
}

/*
 * Here is the bulk of the work in the subscription manager.
 * We grovel over the list of clients possibly interested in this
 * notice, and copy into a list on a match.
 */

ZClientList_t *
subscr_match_list(notice)
ZNotice_t *notice;
{
	register ZClientList_t *hits, *clients, *clients2, *hit2;

	if ((hits = (ZClientList_t *) malloc(sizeof(ZClientList_t))) == NULLZCLT)
		return(NULLZCLT);
	hits->q_forw = hits->q_back = hits;

	if ((clients = class_lookup(notice->z_class)) == NULLZCLT)
		return(NULLZCLT);
	
	for (clients2 = clients->q_forw;
	     clients2 != clients;
	     clients2 = clients2->q_forw)
		if (client_match(notice, clients2->zclt_client)) {
			/* we hit */
			if ((hit2 = (ZClientList_t *) malloc(sizeof(ZClientList_t))) == NULLZCLT) {
				syslog(LOG_WARNING, "subscr_match: punting/no mem");
				return(hits);
			}
			hit2->zclt_client = clients2->zclt_client;
			insque(hits, hit2);
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
		remque(lyst);
		free(lyst);
	}
	free(list);
	return;
}

#define	ZCLASS_MATCHALL		"ZMATCH_ALL"
/*
 * is this client listening to this notice? 1=yes, 0=no
 */
static int
client_match(notice, client)
register ZNotice_t *notice;
register ZClient_t *client;
{
	register ZSubscr_t *subs;
	char *reresult;

	if (client->zct_subs == NULLZST) {
		syslog(LOG_WARNING, "client_match w/ no subs");
		return(0);
	}
		
	for (subs = client->zct_subs->q_forw;
	     subs != client->zct_subs;
	     subs = subs->q_forw) {
		/* for each subscription, do regex matching */
		/* we don't regex the class, since wildcard
		   matching on the class is disallowed.  However,
		   we do check for the Magic Class */
		if (strcmp(ZCLASS_MATCHALL, subs->zst_class) &&
		    strcmp(notice->z_class, subs->zst_class))
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
