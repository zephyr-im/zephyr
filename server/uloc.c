/* This file is part of the Project Athena Zephyr Notification System.
 * It contains functions for the User Locator service.
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
static char rcsid_uloc_s_c[] = "$Header$";
#endif lint

#include "zserver.h"

/*
 *
 * External functions:
 *
 * void ulocate_dispatch(notice, auth, who)
 *	ZNotice_t *notice;
 *	int auth;
 *	struct sockaddr_in *who;
 *
 * void ulogin_dispatch(notice, auth, who)
 *	ZNotice_t *notice;
 *	int auth;
 *	struct sockaddr_in *who;
 *
 * void uloc_hflush(addr)
 *	struct in_addr *addr;
 *
 */

/*
 * The user locator functions.
 *
 * We maintain a table sorted by user field, with entries
 *	user@realm	machine		time	visible
 */

typedef enum _login_type {
	INVISIBLE,
	VISIBLE
} login_type;

typedef struct _ZLocation_t {
	char *zlt_user;
	char *zlt_machine;
#ifdef notdef
	char *zlt_tty;
#endif
	char *zlt_time;			/* in ctime format */
	login_type zlt_visible;
	struct in_addr zlt_addr;
} ZLocation_t;

#define	NULLZLT		((ZLocation_t *) 0)
#define	QUIET		(-1)

static void ulogin_locate(), ulogin_add_user();
static ZLocation_t *ulogin_find();
static int uloc_compare(), ulogin_setup(), ulogin_parse(), ul_equiv();
static int ulogin_remove_user(), ulogin_hide_user();

static ZLocation_t *locations = NULLZLT; /* ptr to first in array */
static int num_locs = 0;		/* number in array */

void ulogin_dispatch(notice, auth, who)
ZNotice_t *notice;
int auth;
struct sockaddr_in *who;
{
	Code_t retval;
	zdbug1("ulogin_disp");

	if (!auth) {
		zdbug1("unauthentic ulogin");
		clt_ack(notice, who, AUTH_FAILED);
		return;
	}
	if (!strcmp(notice->z_opcode, LOGIN_USER_LOGIN)) {
		zdbug1("user login");
		ulogin_add_user(notice, VISIBLE, who);
		sendit(notice, auth, who);
	} else if (!strcmp(notice->z_opcode, LOGIN_QUIET_LOGIN)) {
		zdbug1("quiet login");
		ulogin_add_user(notice, INVISIBLE, who);
		ack(notice, who);
	} else if (!strcmp(notice->z_opcode, LOGIN_USER_LOGOUT)) {
		zdbug1("logout");
		if ((retval = ulogin_remove_user(notice)) == QUIET)
			ack(notice, who);
		else if (retval)
			clt_ack(notice, who, NOT_FOUND);
		else
			sendit(notice, auth, who);
	} else {
		syslog(LOG_ERR, "unknown ulog opcode %s", notice->z_opcode);
		nack(notice, who);
	}
	return;
}

void ulocate_dispatch(notice, auth, who)
ZNotice_t *notice;
int auth;
struct sockaddr_in *who;
{
	zdbug1("ulocate_disp");

	/* we allow unauthenticated locates */
	if (!strcmp(notice->z_opcode, LOCATE_LOCATE)) {
		zdbug1("locate");
		ulogin_locate(notice, who);
		/* does xmit and ack itself, so return */
		return;
	} 
	if (!auth) {
		zdbug1("unauthentic ulocate");
		clt_ack(notice, who, AUTH_FAILED);
		return;
	}
	if (!strcmp(notice->z_opcode, LOCATE_HIDE)) {
		zdbug1("user hide");
		if (ulogin_hide_user(notice, INVISIBLE)) {
			clt_ack(notice, who, NOT_FOUND);
			return;
		}
	} else if (!strcmp(notice->z_opcode, LOCATE_UNHIDE)) {
		zdbug1("user unhide");
		if (ulogin_hide_user(notice, VISIBLE)) {
			clt_ack(notice, who, NOT_FOUND);
			return;
		}
	} else {
		syslog(LOG_ERR, "unknown uloc opcode %s", notice->z_opcode);
		nack(notice, who);
	}
	ack(notice, who);
	return;
}

static void
ulogin_add_user(notice, visible, who)
ZNotice_t *notice;
login_type visible;
struct sockaddr_in *who;
{
	ZLocation_t *loc;

	if ((loc = ulogin_find(notice, 1)) != NULLZLT) {
		zdbug1("ul_add: already here");
		(void) ulogin_hide_user(notice, visible);
		return;
	}

	if (num_locs == 0) {		/* first one */
		if ((locations = (ZLocation_t *) malloc(sizeof(ZLocation_t))) == NULLZLT) {
			syslog(LOG_ERR, "zloc mem alloc");
			return;
		}
		if (ulogin_setup(notice, locations, visible, who)) {
			xfree(locations);
			locations = NULLZLT;
			return;
		}
		num_locs = 1;
#ifdef DEBUG
	if (zdebug) {
		register int i;

		for (i = 0; i < num_locs; i++)
			syslog(LOG_DEBUG, "%s/%d",
			       locations[i].zlt_user,
			       (int) locations[i].zlt_visible);
	}
#endif DEBUG
		return;
	}

	if ((loc = (ZLocation_t *) realloc((caddr_t) locations, (unsigned) ((num_locs + 1) * sizeof(ZLocation_t)))) == NULLZLT) {
		syslog(LOG_ERR, "zloc realloc");
		num_locs = 0;
		locations = NULLZLT;
		return;
	}
	locations = loc;
	if (ulogin_setup(notice, &locations[num_locs], visible, who))
		return;
	num_locs++;

	/* sort it in */
	qsort((caddr_t)locations, num_locs, sizeof(ZLocation_t), uloc_compare);
	
#ifdef DEBUG
	if (zdebug) {
		register int i;

		for (i = 0; i < num_locs; i++)
			syslog(LOG_DEBUG, "%s/%d",
			       locations[i].zlt_user,
			       (int) locations[i].zlt_visible);
	}
#endif DEBUG
	/* all done */
	return;
}

static int
ulogin_setup(notice, locs, visible, who)
ZNotice_t *notice;
register ZLocation_t *locs;
login_type visible;
struct sockaddr_in *who;
{
	if (ulogin_parse(notice, locs))
		return(1);
	locs->zlt_user = strsave(locs->zlt_user);
	if (!locs->zlt_user) {
		syslog(LOG_ERR, "zloc bad format");
		return(1);
	}
	locs->zlt_machine = strsave(locs->zlt_machine);
	if (!locs->zlt_machine) {
		syslog(LOG_ERR, "zloc bad format");
		xfree(locs->zlt_user);
		return(1);
	}
#ifdef notdef
	locs->zlt_tty = strsave(locs->zlt_tty);
	if (!locs->zlt_tty) {
		syslog(LOG_ERR, "zloc bad format");
		xfree(locs->zlt_user);
		xfree(locs->zlt_machine);
		return(1);
	}
#endif notdef
	locs->zlt_time = strsave(locs->zlt_time);
	if (!locs->zlt_time) {
		syslog(LOG_ERR, "zloc bad format");
		xfree(locs->zlt_user);
		xfree(locs->zlt_machine);
#ifdef notdef
		xfree(locs->zlt_tty);
#endif notdef
		return(1);
	}
	locs->zlt_visible = visible;
	locs->zlt_addr = who->sin_addr;
	return(0);
}

#define	ADVANCE(xx)	{ cp += (strlen(cp) + 1); \
		if (cp >= base + notice->z_message_len) { \
			syslog(LOG_ERR, "zloc bad format %d", xx); \
			return(1); \
		} }

static int
ulogin_parse(notice, locs)
register ZNotice_t *notice;
register ZLocation_t *locs;
{
	register char *cp, *base;

	if (!notice->z_message_len) {
		syslog(LOG_WARNING, "short ulogin");
		return(1);
	}

	locs->zlt_user = notice->z_class_inst;
	cp = base = notice->z_message;

	zdbug2("user %s",notice->z_class_inst);
	locs->zlt_machine = cp;
	zdbug2("mach %s",cp);
#ifdef notdef
	ADVANCE(1);
	locs->zlt_tty = cp;
	zdbug2("tty %s",cp);
#endif notdef
	ADVANCE(2);
	locs->zlt_time = cp;
	zdbug2("time %s",cp);
	cp += (strlen(cp) + 1);
	if (cp > base + notice->z_message_len) {
		syslog(LOG_ERR, "zloc bad format 3");
		return(1);
	}
	return(0);
}	

static int
uloc_compare(l1, l2)
ZLocation_t *l1, *l2;
{
	return(strcmp(l1->zlt_user, l2->zlt_user));
}

static ZLocation_t *
ulogin_find(notice, strict)
ZNotice_t *notice;
int strict;
{
	register int i, rlo, rhi;
	int compar;
	ZLocation_t tmploc;

	if (locations == NULLZLT)
		return(NULLZLT);

	/* i is the current loc we are checking */
	/* rlo is the lowest we will still check, rhi is the highest we will
	   still check */

	i = num_locs >> 1;		/* start in the middle */
	rlo = 0;
	rhi = num_locs - 1;		/* first index is 0 */

	while (compar = strcmp(locations[i].zlt_user,notice->z_class_inst)) {
		if (compar < 0)
			rlo = i + 1;
		else
			rhi = i - 1;
		if (rhi - rlo < 0) {
			zdbug1("ul_find not found");
			return(NULLZLT);
		}
		i = (rhi + rlo) >> 1; /* split the diff */
	}
	if (strict  && ulogin_parse(notice, &tmploc)) {
		zdbug1("ul_find bad fmt");
		return(NULLZLT);
	}
	/* back up to the first of this guy */
	if (i) {
		while (i > 0 && !strcmp(locations[--i].zlt_user, notice->z_class_inst));
		if (i || strcmp(locations[i].zlt_user, notice->z_class_inst))
			i++;
	}
	if (strict)
		while (i < num_locs && !ul_equiv(&tmploc, &locations[i]) &&
		       !strcmp(locations[i].zlt_user, notice->z_class_inst))
			i++;

	if ((i == num_locs) || strcmp(locations[i].zlt_user, notice->z_class_inst)) {
		zdbug1("ul_find final match loss");
		return(NULLZLT);
	}
	return(&locations[i]);
}

static int
ul_equiv(l1, l2)
register ZLocation_t *l1, *l2;
{
	if (strcmp(l1->zlt_machine, l2->zlt_machine))
		return(0);
#ifdef notdef
	if (strcmp(l1->zlt_tty, l2->zlt_tty))
		return(0);
#endif notdef
	return(1);
}

void
uloc_hflush(addr)
struct in_addr *addr;
{
	ZLocation_t *loc;
	register int i = 0, new_num = 0;

	/* slightly inefficient, assume the worst, and allocate enough space */
	if ((loc = (ZLocation_t *) xmalloc(num_locs * sizeof(ZLocation_t))) == NULLZLT) {
		syslog(LOG_CRIT, "uloc_flush malloc");
		abort();
		/*NOTREACHED*/
	}

	/* copy entries which don't match */
	while (i < num_locs) {
		if (locations[i].zlt_addr.s_addr != addr->s_addr)
			loc[new_num++] = locations[i];
		i++;
	}

	xfree(locations);

	if (!new_num) {
		zdbug1("no more locs");
		xfree(loc);
		locations = NULLZLT;
		return;
	}
	locations = loc;
	num_locs = new_num;

#ifdef DEBUG
	if (zdebug) {
		register int i;

		for (i = 0; i < num_locs; i++)
			syslog(LOG_DEBUG, "%s/%d",
			       locations[i].zlt_user,
			       (int) locations[i].zlt_visible);
	}
#endif DEBUG
	/* all done */
	return;
}

static int
ulogin_remove_user(notice)
ZNotice_t *notice;
{
	ZLocation_t *loc, *loc2;
	register int i = 0;
	int quiet = 0;

	if ((loc2 = ulogin_find(notice, 1)) == NULLZLT) {
		zdbug1("ul_rem: not here");
		return(1);
	}

	if (loc2->zlt_visible == INVISIBLE)
		quiet = QUIET;

	if (--num_locs == 0) {		/* last one */
		zdbug1("last loc");
		xfree(locations);
		locations = NULLZLT;
		return(quiet);
	}

	if ((loc = (ZLocation_t *) xmalloc(num_locs * sizeof(ZLocation_t))) == NULLZLT) {
		syslog(LOG_CRIT, "ul_rem malloc");
		abort();
		/*NOTREACHED*/
	}

	/* copy old entries */
	while (i < num_locs && &locations[i] < loc2) {
		loc[i] = locations[i];
		i++;
	}

	i++;				/* skip over this one */

	/* copy the rest */
	while (i <= num_locs) {
		loc[i - 1] = locations[i];
		i++;
	}

	xfree(locations);

	locations = loc;

#ifdef DEBUG
	if (zdebug) {
		register int i;

		for (i = 0; i < num_locs; i++)
			syslog(LOG_DEBUG, "%s/%d",
			       locations[i].zlt_user,
			       (int) locations[i].zlt_visible);
	}
#endif DEBUG
	/* all done */
	return(quiet);
}

static int
ulogin_hide_user(notice, visible)
ZNotice_t *notice;
login_type visible;
{
	ZLocation_t *loc;

	if ((loc = ulogin_find(notice, 1)) == NULLZLT) {
		zdbug1("ul_hide: not here");
		return(1);
	}
	loc->zlt_visible = visible;
	return(0);
}

static void
ulogin_locate(notice, who)
ZNotice_t *notice;
struct sockaddr_in *who;
{
	ZLocation_t **matches = (ZLocation_t **) 0;
	ZLocation_t *loc;
	char **answer;
	register int i = 0;
	register int found = 0;		/* # of matches */
	Code_t retval;
	ZNotice_t reply;
	ZPacket_t reppacket;
	int packlen;

	/* advance past non-matching locs */
	if ((loc = ulogin_find(notice, 0)) == NULLZLT)
		/* not here anywhere */
		goto rep;

	i = loc - locations;
	while (i < num_locs && !strcmp(notice->z_class_inst, locations[i].zlt_user)) {
		/* these locations match */
		zdbug2("match %s", locations[i].zlt_user);
		if (locations[i].zlt_visible != VISIBLE) {
			i++;
			continue;
		}
		if (!found) {
			if ((matches = (ZLocation_t **) xmalloc(sizeof(ZLocation_t *))) == (ZLocation_t **) 0) {
				syslog(LOG_ERR, "ulog_loc: no mem");
				break;	/* from the while */
			}
			matches[0] = &locations[i];
			found++;
		} else {
			if ((matches = (ZLocation_t **) realloc((caddr_t) matches, (unsigned) ++found * sizeof(ZLocation_t *))) == (ZLocation_t **) 0) {
				syslog(LOG_ERR, "ulog_loc: realloc no mem");
				found = 0;
				break;	/* from the while */
			}
			matches[found - 1] = &locations[i];
		}
		i++;
	}

	/* OK, now we have a list of user@host's to return to the client
	   in matches */

rep:
	reply = *notice;
	reply.z_kind = SERVACK;

	packlen = sizeof(reppacket);

#ifdef DEBUG
	if (zdebug) {
		for (i = 0; i < found ; i++)
			zdbug2("found %s", matches[i]->zlt_user);
	}
#endif DEBUG

	/* coalesce the location information into a list of char *'s */
	if ((answer = (char **) xmalloc(found * 2 * sizeof(char *))) == (char **) 0) {
		syslog(LOG_ERR, "zloc no mem(answer)");
		found = 0;
	} else
		for (i = 0; i < found ; i++) {
			answer[i*2] = matches[i]->zlt_machine;
#ifdef notdef
			answer[i*3 + 1] = matches[i]->zlt_tty;
#endif notdef
			answer[i*2 + 1] = matches[i]->zlt_time;
		}

	/* if it's too long, chop off one at a time till it fits */
	while ((retval = ZFormatRawNoticeList(&reply, answer, found * 2, reppacket, packlen, &packlen)) == ZERR_PKTLEN)
		found--;

	if (retval != ZERR_NONE) {
		syslog(LOG_ERR, "ulog_locate format: %s",
		       error_message(retval));
		xfree(answer);
		return;
	}
	if ((retval = ZSetDestAddr(who)) != ZERR_NONE) {
		syslog(LOG_WARNING, "ulog_locate set addr: %s",
		       error_message(retval));
		xfree(answer);
		return;
	}
	if ((retval = ZSendPacket(reppacket, packlen)) != ZERR_NONE) {
		syslog(LOG_WARNING, "ulog_locate xmit: %s",
		       error_message(retval));
		xfree(answer);
		return;
	}
	zdbug1("ulog_loc acked");
	xfree(answer);
	return;
}
