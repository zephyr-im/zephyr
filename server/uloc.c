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
 * void uloc_flush_client(sin)
 *	struct sockaddr_in *sin;
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
#define	NUM_FIELDS	3


typedef enum _exposure_type {
	NONE,
	OPSTAFF_VIS,
	REALM_VIS,
	REALM_ANN,
	NET_VIS,
	NET_ANN
} exposure_type;

typedef struct _ZLocation_t {
	char *zlt_user;
	char *zlt_machine;
	char *zlt_time;			/* in ctime format */
	char *zlt_tty;
	exposure_type zlt_exposure;
	struct in_addr zlt_addr;	/* IP addr of this loc */
	unsigned short zlt_port;	/* port of registering client--
					 for removing old entries */
} ZLocation_t;

#define	NULLZLT		((ZLocation_t *) 0)
#define	NOLOC		(1)
#define	QUIET		(-1)
#define	UNAUTH		(-2)

static void ulogin_locate(), ulogin_add_user(), ulogin_flush_user();
static ZLocation_t *ulogin_find();
static int ulogin_setup(), ulogin_parse(), ul_equiv(), ulogin_expose_user();
static exposure_type ulogin_remove_user();

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
	exposure_type retval;
	int err_ret;

	zdbug((LOG_DEBUG,"ulogin_disp"));

	if (!strcmp(notice->z_opcode, LOGIN_USER_LOGOUT)) {
		zdbug((LOG_DEBUG,"logout"));
		retval = ulogin_remove_user(notice, auth, who, &err_ret);
		switch (retval) {
		case NONE:
			if (err_ret == UNAUTH) {
				zdbug((LOG_DEBUG, "unauth logout: %s %d",
				       inet_ntoa(who->sin_addr),
				       ntohs(notice->z_port)));
				if (server == me_server)
					clt_ack(notice, who, AUTH_FAILED);
				return;
			} else if (err_ret == NOLOC) {
				if (server == me_server)
					clt_ack(notice, who, NOT_FOUND);
				return;
			} 
			syslog(LOG_ERR,"bogus location exposure NONE, %s",
			       notice->z_sender);
			break;
		case OPSTAFF_VIS:
		case REALM_VIS:
			/* he is not announced to people.  Silently ack */
			if (server == me_server)
				ack(notice, who);
			break;
		case REALM_ANN:
		case NET_VIS:
		case NET_ANN:
			/* currently no distinction between these.
			 just announce */
			/* XXX we assume that if this user is at a certain
			   IP address, we can trust the logout to be
			   authentic.  ulogin_remove_user checks the
			   ip addrs */
			if (server == me_server)
				sendit(notice, 1, who);
			break;
		default:
			syslog(LOG_ERR,"bogus location exposure %d/%s",
			       (int) retval, notice->z_sender);
			break;
		}
		if (server == me_server) /* tell the other servers */
			server_forward(notice, auth, who);
		return;
	}
	if (!auth) {
		zdbug((LOG_DEBUG,"unauthentic ulogin"));
		if (server == me_server)
			clt_ack(notice, who, AUTH_FAILED);
		return;
	}
	if (!strcmp(notice->z_opcode, LOGIN_USER_FLUSH)) {
		zdbug((LOG_DEBUG, "user flush"));
		ulogin_flush_user(notice);
		if (server == me_server)
			ack(notice, who);
#ifdef notdef
	} else if (!strcmp(notice->z_opcode, EXPOSE_NONE)) {
		zdbug((LOG_DEBUG,"no expose"));
		(void) ulogin_remove_user(notice, auth, who, &err_ret);
		if (err_ret == UNAUTH) {
			zdbug((LOG_DEBUG, "unauth noexpose: %s/%d",
			       inet_ntoa(who->sin_addr),
			       ntohs(notice->z_port)));
			if (server == me_server)
				clt_ack(notice, who, AUTH_FAILED);
			return;
		} else if (err_ret == NOLOC) {
			if (server == me_server)
				clt_ack(notice, who, NOT_FOUND);
			return;
		}
		if (server == me_server)
			server_forward(notice, auth, who);
		return;
#endif notdef
	} else if (!strcmp(notice->z_opcode, EXPOSE_OPSTAFF)) {
		zdbug((LOG_DEBUG,"opstaff"));
		ulogin_add_user(notice, OPSTAFF_VIS, who);
		if (server == me_server)
			sendit(notice, auth, who);
	} else if (!strcmp(notice->z_opcode, EXPOSE_REALMVIS)) {
		zdbug((LOG_DEBUG,"realmvis"));
		ulogin_add_user(notice, REALM_VIS, who);
		if (server == me_server) /* realm vis is not broadcast,
					    so we ack it here */
			ack(notice, who);
	} else if (!strcmp(notice->z_opcode, EXPOSE_REALMANN)) {
		zdbug((LOG_DEBUG,"realmann"));
		ulogin_add_user(notice, REALM_ANN, who);
		if (server == me_server) /* announce to the realm */
			sendit(notice, auth, who);
	} else if (!strcmp(notice->z_opcode, EXPOSE_NETVIS)) {
		zdbug((LOG_DEBUG,"netvis"));
		ulogin_add_user(notice, NET_VIS, who);
		if (server == me_server) /* announce to the realm */
			sendit(notice, auth, who);
	} else if (!strcmp(notice->z_opcode, EXPOSE_NETANN)) {
		zdbug((LOG_DEBUG,"netann"));
		ulogin_add_user(notice, NET_ANN, who);
		if (server == me_server) /* tell the world */
			sendit(notice, auth, who);
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

	if (!auth) {
		zdbug((LOG_DEBUG,"unauthentic ulocate"));
		if (server == me_server)
			clt_ack(notice, who, AUTH_FAILED);
		return;
	}
	if (!strcmp(notice->z_opcode, LOCATE_LOCATE)) {
		zdbug((LOG_DEBUG,"locate"));
		ulogin_locate(notice, who);
		/* does xmit and ack itself, so return */
		return;
#ifdef notdef
	} else if (!strcmp(notice->z_opcode, LOCATE_HIDE)) {
		zdbug((LOG_DEBUG,"user hide"));
		if (ulogin_expose_user(notice, INVISIBLE)) {
			if (server == me_server)
				clt_ack(notice, who, NOT_FOUND);
			return;
		}
	} else if (!strcmp(notice->z_opcode, LOCATE_UNHIDE)) {
		zdbug((LOG_DEBUG,"user unhide"));
		if (ulogin_expose_user(notice, VISIBLE)) {
			if (server == me_server)
				clt_ack(notice, who, NOT_FOUND);
			return;
		}
#endif notdef
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
			       (int) locations[i].zlt_exposure);
	}
#endif DEBUG
	/* all done */
	return;
}

void
uloc_flush_client(sin)
struct sockaddr_in *sin;
{
	ZLocation_t *loc;
	register int i = 0, new_num = 0;

	/* slightly inefficient, assume the worst, and allocate enough space */
	if (!(loc = (ZLocation_t *) xmalloc(num_locs * sizeof(ZLocation_t)))) {
		syslog(LOG_CRIT, "uloc_flush_clt malloc");
		abort();
		/*NOTREACHED*/
	}

	/* copy entries which don't match */
	while (i < num_locs) {
		if ((locations[i].zlt_addr.s_addr != sin->sin_addr.s_addr)
		     && (locations[i].zlt_port != sin->sin_port))
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
			       (int) locations[i].zlt_exposure);
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
	char *exposure_level;
	Code_t retval;

	for (i = 0, loc = locations; i < num_locs; i++, loc++) {
		if (loc->zlt_addr.s_addr != haddr->s_addr)
			continue;
		lyst[0] = loc->zlt_machine;
		lyst[1] = loc->zlt_time;
		lyst[2] = loc->zlt_tty;


		switch (loc->zlt_exposure) {
		case OPSTAFF_VIS:
			exposure_level = EXPOSE_OPSTAFF;
			break;
		case REALM_VIS:
			exposure_level = EXPOSE_REALMVIS;
			break;
		case REALM_ANN:
			exposure_level = EXPOSE_REALMANN;
			break;
		case NET_VIS:
			exposure_level = EXPOSE_NETVIS;
			break;
		case NET_ANN:
			exposure_level = EXPOSE_NETANN;
			break;
		default:
			syslog(LOG_ERR,"broken location state %s/%d",
			       loc->zlt_user, (int) loc->zlt_exposure);
			break;
		}
		if ((retval = bdump_send_list_tcp(ACKED, loc->zlt_port,
						  LOGIN_CLASS, loc->zlt_user,
						  exposure_level,
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
ulogin_add_user(notice, exposure, who)
ZNotice_t *notice;
exposure_type exposure;
struct sockaddr_in *who;
{
	ZLocation_t *oldlocs, newloc;
	register int i = 0;

	if ((oldlocs = ulogin_find(notice, 1))) {
		zdbug((LOG_DEBUG,"ul_add: already here"));
		(void) ulogin_expose_user(notice, exposure);
		return;
	}

	oldlocs = locations;

	if (!(locations = (ZLocation_t *) xmalloc((num_locs + 1) * sizeof(ZLocation_t)))) {
		syslog(LOG_ERR, "zloc mem alloc");
		locations = oldlocs;
		return;
	}

	if (num_locs == 0) {		/* first one */
		if (ulogin_setup(notice, locations, exposure, who)) {
			xfree(locations);
			locations = NULLZLT;
			return;
		}
		num_locs = 1;
		return;
	}

	/* not the first one, insert him */

	if (ulogin_setup(notice, &newloc, exposure, who))
		return;
	num_locs++;

	/* copy old locs */
	while ((i < (num_locs - 1)) && strcmp(oldlocs[i].zlt_user, newloc.zlt_user) < 0) {
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
			       (int) locations[i].zlt_exposure);
	}
#endif DEBUG
	return;
}

/*
 * Set up the location locs with the information in the notice.
 */ 

static int
ulogin_setup(notice, locs, exposure, who)
ZNotice_t *notice;
register ZLocation_t *locs;
exposure_type exposure;
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
	locs->zlt_tty = strsave(locs->zlt_tty);
	if (!locs->zlt_tty) {
		syslog(LOG_ERR, "zloc bad format");
		xfree(locs->zlt_user);
		xfree(locs->zlt_machine);
		return(1);
	}
	locs->zlt_time = strsave(locs->zlt_time);
	if (!locs->zlt_time) {
		syslog(LOG_ERR, "zloc bad format");
		xfree(locs->zlt_user);
		xfree(locs->zlt_machine);
		xfree(locs->zlt_tty);
		return(1);
	}
	locs->zlt_exposure = exposure;
	locs->zlt_addr = who->sin_addr;
	locs->zlt_port = notice->z_port;
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

	cp += (strlen(cp) + 1);
	if (cp >= base + notice->z_message_len) {
		syslog(LOG_ERR, "zloc bad format 1");
		return(1);
	}
	locs->zlt_time = cp;
	zdbug((LOG_DEBUG,"time %s",cp));

	cp += (strlen(cp) + 1);

	if (cp == base + notice->z_message_len) {
		/* no tty--for backwards compat, we allow this */
		zdbug((LOG_DEBUG, "no tty"));
		locs->zlt_tty = "";
	} else if (cp > base + notice->z_message_len) {
		syslog(LOG_ERR, "zloc bad format 2");
		return(1);
	} else {
		locs->zlt_tty = cp;
		zdbug((LOG_DEBUG,"tty %s",cp));
		cp += (strlen(cp) + 1);
	}
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
	if (strcmp(l1->zlt_tty, l2->zlt_tty))
		return(0);
	return(1);
}

/*
 * remove the user specified in notice from the internal table
 */

static exposure_type
ulogin_remove_user(notice, auth, who, err_return)
ZNotice_t *notice;
int auth;
struct sockaddr_in *who;
int *err_return;
{
	ZLocation_t *loc, *loc2;
	register int i = 0;
	exposure_type quiet = NONE;

	*err_return = 0;
	if (!(loc2 = ulogin_find(notice, 1))) {
		zdbug((LOG_DEBUG,"ul_rem: not here"));
		*err_return = NOLOC;
		return(NONE);
	}

	/* if unauthentic, the sender MUST be the same IP addr
	   that registered */

	if (!auth && loc2->zlt_addr.s_addr != who->sin_addr.s_addr) {
		*err_return = UNAUTH;
		return(NONE);
	}

	quiet = loc2->zlt_exposure;

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
			       (int) locations[i].zlt_exposure);
	}
#endif DEBUG
	/* all done */
	return(quiet);
}

/*
 * remove all locs of the user specified in notice from the internal table
 */

static void
ulogin_flush_user(notice)
ZNotice_t *notice;
{
	ZLocation_t *loc, *loc2;
	register int i, j, num_match, num_left;

	i = num_match = num_left = 0;

	if (!(loc2 = ulogin_find(notice, 0))) {
		zdbug((LOG_DEBUG,"ul_rem: not here"));
		return;
	}

	num_left = num_locs - (loc2 - locations);

	while (num_left &&
	       !strcmp(loc2[num_match].zlt_user, notice->z_class_inst)) {
		num_match++;
		num_locs--;
		num_left--;
	}
	if (num_locs == 0) {		/* last one */
		zdbug((LOG_DEBUG,"last loc"));
		xfree(locations);
		locations = NULLZLT;
		return;
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

	for (j = 0; j < num_match; j++)
		i++;				/* skip over the matches */

	/* copy the rest */
	while (i <= num_locs) {
		loc[i - num_match] = locations[i];
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
			       (int) locations[i].zlt_exposure);
	}
#endif DEBUG
	/* all done */
	return;
}

/*
 * Set the user's exposure flag to exposure
 */

static int
ulogin_expose_user(notice, exposure)
ZNotice_t *notice;
exposure_type exposure;
{
	ZLocation_t *loc, loc2;
	int index, notfound = 1;

	if (ulogin_parse(notice, &loc2))
		return(1);

	if (!(loc = ulogin_find(notice, 0))) {
		zdbug((LOG_DEBUG,"ul_hide: not here"));
		return(1);
	}
	index = loc - locations;

	while ((index < num_locs) &&
	       !strcmp(locations[index].zlt_user, loc2.zlt_user)) {

		/* change exposure for each loc on that host */
		if (!strcmp(locations[index].zlt_machine, loc2.zlt_machine)) {
			notfound = 0;
			locations[index].zlt_exposure = exposure;
		}
		index++;
	}

	return(notfound);
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
		switch (locations[i].zlt_exposure) {
		case OPSTAFF_VIS:
			i++;
			continue;
		case REALM_VIS:
		case REALM_ANN:
		case NET_VIS:
		case NET_ANN:
		default:
			break;
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
			answer[i*NUM_FIELDS + 1] = matches[i]->zlt_time;
			answer[i*NUM_FIELDS + 2] = matches[i]->zlt_tty;
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
