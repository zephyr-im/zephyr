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
 * The user locator functions.
 *
 * External functions:
 *
 * void ulocate_dispatch(notice, auth, who, server)
 *	ZNotice_t *notice;
 *	int auth;
 *	struct sockaddr_in *who;
 *	ZServerDesc_t *server;
 *
 * void ulogin_dispatch(notice, auth, who, server)
 *	ZNotice_t *notice;
 *	int auth;
 *	struct sockaddr_in *who;
 *	ZServerDesc_t *server;
 *
 * void uloc_hflush(addr)
 *	struct in_addr *addr;
 *
 * Code_t uloc_send_locations(host)
 *	ZHostList_t *host;
 */

/*
 * The user locator.
 * We maintain an array of ZLocation_t sorted by user (so we can do
 * binary searches), growing and shrinking it as necessary.
 */

/* WARNING: make sure this is the same as the number of strings you */
/* plan to hand back to the user in response to a locate request, */
/* else you will lose.  See ulogin_locate() and uloc_send_locations() */  
#define	NUM_FIELDS	2


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
	struct in_addr zlt_addr;	/* IP addr of this loc */
} ZLocation_t;

#define	NULLZLT		((ZLocation_t *) 0)
#define	NOLOC		(1)
#define	QUIET		(-1)
#define	UNAUTH		(-2)

static void ulogin_locate(), ulogin_add_user();
static ZLocation_t *ulogin_find();
static int ulogin_setup(), ulogin_parse(), ul_equiv();
static int ulogin_remove_user(), ulogin_hide_user();

static ZLocation_t *locations = NULLZLT; /* ptr to first in array */
static int num_locs = 0;		/* number in array */

/*
 * Dispatch a LOGIN notice.
 */

void
ulogin_dispatch(notice, auth, who, server)
ZNotice_t *notice;
int auth;
struct sockaddr_in *who;
ZServerDesc_t *server;
{
	Code_t retval;
	zdbug((LOG_DEBUG,"ulogin_disp"));

	if (!strcmp(notice->z_opcode, LOGIN_USER_LOGOUT)) {
		zdbug((LOG_DEBUG,"logout"));
		if ((retval = ulogin_remove_user(notice, auth, who)) == QUIET) {
			if (server == me_server)
				ack(notice, who);
		}
		else if (retval == UNAUTH) {
			zdbug((LOG_DEBUG, "unauth logout: %d %d",auth,
			       ntohs(notice->z_port)));
			if (server == me_server)
				clt_ack(notice, who, AUTH_FAILED);
			return;
		} else if (retval == NOLOC) {
			if (server == me_server)
				clt_ack(notice, who, NOT_FOUND);
			return;
		} else
			/* XXX we assume that if this user is at a certain
			   IP address, we can trust the logout to be
			   authentic */
			if (server == me_server)
				sendit(notice, 1, who);
		if (server == me_server)
			server_forward(notice, auth, who);
		return;
	}
	if (!auth) {
		zdbug((LOG_DEBUG,"unauthentic ulogin"));
		if (server == me_server)
			clt_ack(notice, who, AUTH_FAILED);
		return;
	}
	if (!strcmp(notice->z_opcode, LOGIN_USER_LOGIN)) {
		zdbug((LOG_DEBUG,"user login"));
		ulogin_add_user(notice, VISIBLE, who);
		if (server == me_server)
			sendit(notice, auth, who);
	} else if (!strcmp(notice->z_opcode, LOGIN_QUIET_LOGIN)) {
		zdbug((LOG_DEBUG,"quiet login"));
		ulogin_add_user(notice, INVISIBLE, who);
		if (server == me_server)
			ack(notice, who);
	} else {
		syslog(LOG_ERR, "unknown ulog opcode %s", notice->z_opcode);
		if (server == me_server)
			nack(notice, who);
		return;
	}
	if (server == me_server)
		server_forward(notice, auth, who);
	return;
}

/*
 * Dispatch a LOCATE notice.
 */

void
ulocate_dispatch(notice, auth, who, server)
ZNotice_t *notice;
int auth;
struct sockaddr_in *who;
ZServerDesc_t *server;
{
	zdbug((LOG_DEBUG,"ulocate_disp"));

	/* we allow unauthenticated locates */
	if (!strcmp(notice->z_opcode, LOCATE_LOCATE)) {
		zdbug((LOG_DEBUG,"locate"));
		ulogin_locate(notice, who);
		/* does xmit and ack itself, so return */
		return;
	} 
	/* ... but not unauthentic changes of location status */
	if (!auth) {
		zdbug((LOG_DEBUG,"unauthentic ulocate"));
		if (server == me_server)
			clt_ack(notice, who, AUTH_FAILED);
		return;
	}
	if (!strcmp(notice->z_opcode, LOCATE_HIDE)) {
		zdbug((LOG_DEBUG,"user hide"));
		if (ulogin_hide_user(notice, INVISIBLE)) {
			if (server == me_server)
				clt_ack(notice, who, NOT_FOUND);
			return;
		}
	} else if (!strcmp(notice->z_opcode, LOCATE_UNHIDE)) {
		zdbug((LOG_DEBUG,"user unhide"));
		if (ulogin_hide_user(notice, VISIBLE)) {
			if (server == me_server)
				clt_ack(notice, who, NOT_FOUND);
			return;
		}
	} else {
		syslog(LOG_ERR, "unknown uloc opcode %s", notice->z_opcode);
		if (server == me_server)
			nack(notice, who);
	}
	if (server == me_server) {
		server_forward(notice, auth, who);
		ack(notice, who);
	}
	return;
}

/*
 * Flush all locations at the address.
 */

void
uloc_hflush(addr)
struct in_addr *addr;
{
	ZLocation_t *loc;
	register int i = 0, new_num = 0;

	/* slightly inefficient, assume the worst, and allocate enough space */
	if (!(loc = (ZLocation_t *) xmalloc(num_locs * sizeof(ZLocation_t)))) {
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
		zdbug((LOG_DEBUG,"no more locs"));
		xfree(loc);
		locations = NULLZLT;
		num_locs = new_num;
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

/*
 * Send the locations for host for a brain dump
 */

Code_t
uloc_send_locations(host)
ZHostList_t *host;
{
	register ZLocation_t *loc;
	register int i;
	register struct in_addr *haddr = &host->zh_addr.sin_addr;
	char *lyst[NUM_FIELDS];
	Code_t retval;

	for (i = 0, loc = locations; i < num_locs; i++, loc++) {
		if (loc->zlt_addr.s_addr != haddr->s_addr)
			continue;
		lyst[0] = loc->zlt_machine;
#ifdef notdef
		lyst[1] = loc->zlt_tty;
		lyst[2] = loc->zlt_time;
#else
		lyst[1] = loc->zlt_time;
#endif notdef

		if ((retval = bdump_send_list_tcp(ACKED, bdump_sin.sin_port,
						  LOGIN_CLASS, loc->zlt_user,
						  (loc->zlt_visible == VISIBLE)
						  ? LOGIN_USER_LOGIN
						  : LOGIN_QUIET_LOGIN,
						  myname, "", lyst,
						  NUM_FIELDS)) != ZERR_NONE) {
			syslog(LOG_ERR, "uloc_send_locs: %s",
			       error_message(retval));
			return(retval);
		}
	}
	return(ZERR_NONE);
}

/*
 * Add the user to the internal table of locations.
 */

static void
ulogin_add_user(notice, visible, who)
ZNotice_t *notice;
login_type visible;
struct sockaddr_in *who;
{
	ZLocation_t *oldlocs, newloc;
	register int i = 0;

	if ((oldlocs = ulogin_find(notice, 1))) {
		zdbug((LOG_DEBUG,"ul_add: already here"));
		(void) ulogin_hide_user(notice, visible);
		return;
	}

	oldlocs = locations;

	if (!(locations = (ZLocation_t *) xmalloc((num_locs + 1) * sizeof(ZLocation_t)))) {
		syslog(LOG_ERR, "zloc mem alloc");
		locations = oldlocs;
		return;
	}

	if (num_locs == 0) {		/* first one */
		if (ulogin_setup(notice, locations, visible, who)) {
			xfree(locations);
			locations = NULLZLT;
			return;
		}
		num_locs = 1;
		return;
	}

	/* not the first one, insert him */

	if (ulogin_setup(notice, &newloc, visible, who))
		return;
	num_locs++;

	/* copy old locs */
	while (i < (num_locs - 1) && strcmp(oldlocs[i].zlt_user, newloc.zlt_user) < 0) {
		locations[i] = oldlocs[i];
		i++;
	}

	/* add him in here */
	locations[i++] = newloc;
	
	/* copy the rest */
	while (i < num_locs) {
		locations[i] = oldlocs[i - 1];
		i++;
	}
	xfree(oldlocs);
	
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

/*
 * Set up the location locs with the information in the notice.
 */ 

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

/*
 * Parse the location information in the notice, and fill it into *locs
 */

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

	zdbug((LOG_DEBUG,"user %s",notice->z_class_inst));
	locs->zlt_machine = cp;
	zdbug((LOG_DEBUG,"mach %s",cp));
#ifdef notdef
	ADVANCE(1);
	locs->zlt_tty = cp;
	zdbug((LOG_DEBUG,"tty %s",cp));
#endif notdef
	ADVANCE(2);
	locs->zlt_time = cp;
	zdbug((LOG_DEBUG,"time %s",cp));
	cp += (strlen(cp) + 1);
	if (cp > base + notice->z_message_len) {
		syslog(LOG_ERR, "zloc bad format 3");
		return(1);
	}
	return(0);
}	

/*
 * Find the username specified in notice->z_class_inst.
 * If strict, make sure the locations in notice and the table match.
 * Otherwise return a pointer to the first instance of this user@realm
 * in the table.
 */

static ZLocation_t *
ulogin_find(notice, strict)
ZNotice_t *notice;
int strict;
{
	register int i, rlo, rhi;
	int compar;
	ZLocation_t tmploc;

	if (!locations)
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
			zdbug((LOG_DEBUG,"ul_find not found"));
			return(NULLZLT);
		}
		i = (rhi + rlo) >> 1; /* split the diff */
	}
	if (strict  && ulogin_parse(notice, &tmploc)) {
		zdbug((LOG_DEBUG,"ul_find bad fmt"));
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
		zdbug((LOG_DEBUG,"ul_find final match loss"));
		return(NULLZLT);
	}
	return(&locations[i]);
}

/*
 * are the locations of this user equivalent? 1 = yes, 0 = no
 */

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

/*
 * remove the user specified in notice from the internal table
 */

static int
ulogin_remove_user(notice, auth, who)
ZNotice_t *notice;
int auth;
struct sockaddr_in *who;
{
	ZLocation_t *loc, *loc2;
	register int i = 0;
	int quiet = 0;

	if (!(loc2 = ulogin_find(notice, 1))) {
		zdbug((LOG_DEBUG,"ul_rem: not here"));
		return(NOLOC);
	}

	/* if unauthentic, the sender MUST be the same IP addr
	   that registered */

	if (!auth && loc2->zlt_addr.s_addr != who->sin_addr.s_addr)
		return(UNAUTH);

	if (loc2->zlt_visible == INVISIBLE)
		quiet = QUIET;

	if (--num_locs == 0) {		/* last one */
		zdbug((LOG_DEBUG,"last loc"));
		xfree(locations);
		locations = NULLZLT;
		return(quiet);
	}

	if (!(loc = (ZLocation_t *) xmalloc(num_locs * sizeof(ZLocation_t)))) {
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

/*
 * Set the user's visible flag to visible
 */

static int
ulogin_hide_user(notice, visible)
ZNotice_t *notice;
login_type visible;
{
	ZLocation_t *loc;

	if (!(loc = ulogin_find(notice, 1))) {
		zdbug((LOG_DEBUG,"ul_hide: not here"));
		return(1);
	}
	loc->zlt_visible = visible;
	return(0);
}

/*
 * Locate the user and send the locations in the acknowledgement to the client.
 */

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
	if (!(loc = ulogin_find(notice, 0)))
		/* not here anywhere */
		goto rep;

	i = loc - locations;
	while (i < num_locs && !strcmp(notice->z_class_inst, locations[i].zlt_user)) {
		/* these locations match */
		zdbug((LOG_DEBUG,"match %s", locations[i].zlt_user));
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
			zdbug((LOG_DEBUG,"found %s", matches[i]->zlt_user));
	}
#endif DEBUG

	/* coalesce the location information into a list of char *'s */
	if ((answer = (char **) xmalloc(found * NUM_FIELDS * sizeof(char *))) == (char **) 0) {
		syslog(LOG_ERR, "zloc no mem(answer)");
		found = 0;
	} else
		for (i = 0; i < found ; i++) {
			answer[i*NUM_FIELDS] = matches[i]->zlt_machine;
#ifdef notdef
			answer[i*NUM_FIELDS + 1] = matches[i]->zlt_tty;
#endif notdef
			answer[i*NUM_FIELDS + 1] = matches[i]->zlt_time;
		}

	xfree(matches);
	/* if it's too long, chop off one at a time till it fits */
	while ((retval = ZFormatRawNoticeList(&reply,
					      answer,
					      found * NUM_FIELDS,
					      reppacket,
					      packlen,
					      &packlen)) == ZERR_PKTLEN)
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
	zdbug((LOG_DEBUG,"ulog_loc acked"));
	xfree(answer);
	return;
}
