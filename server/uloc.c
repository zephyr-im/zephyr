/* This file is part of the Project Athena Zephyr Notification System.
 * It contains functions for the User Locator service.
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
static char rcsid_uloc_c[] =
  "$Id$";
#endif /* SABER */
#endif /* lint */

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
 * Code_t uloc_send_locations(host, version)
 *	ZHostList_t *host;
 *	char *version;
 *
 * void uloc_dump_locs(fp)
 *	FILE *fp;
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
	ZSTRING * zlt_user;
	ZSTRING * zlt_machine;
	char * zlt_time;		/* in ctime format */
	ZSTRING * zlt_tty;
	struct in_addr zlt_addr;	/* IP addr of this loc */
	unsigned short zlt_port;	/* port of registering client--
					   for removing old entries */
	exposure_type zlt_exposure;
} ZLocation_t;

#define NULLZLT		((ZLocation_t *) 0)
#define NOLOC		1
#define QUIET		-1
#define UNAUTH		-2

#ifdef __STDC__
# define        P(s) s
#else
# define P(s) ()
#endif

static void ulogin_locate P((ZNotice_t *notice, struct sockaddr_in *who,
			     int auth)),
    ulogin_flush_user P((ZNotice_t *notice));
static ZLocation_t *ulogin_find P((ZNotice_t *notice, int strict));
static int ulogin_setup P((ZNotice_t *notice, ZLocation_t *locs,
			exposure_type exposure, struct sockaddr_in *who)),
    ulogin_add_user P((ZNotice_t *notice, exposure_type exposure,
		    struct sockaddr_in *who)),
    ulogin_parse P((ZNotice_t *notice, ZLocation_t *locs)),
    ulogin_expose_user P((ZNotice_t *notice, exposure_type exposure));
static exposure_type ulogin_remove_user P((ZNotice_t *notice, int auth,
					struct sockaddr_in *who,
					int *err_return));
static void login_sendit P((ZNotice_t *notice, int auth, struct sockaddr_in *who));
static char **ulogin_marshal_locs P((ZNotice_t *notice, int *found, int auth));

static int ul_equiv P((ZLocation_t *l1, ZLocation_t *l2));

static void free_loc P((ZLocation_t *loc));

static ZLocation_t *locations = NULLZLT; /* ptr to first in array */
static int num_locs = 0;	/* number in array */

/*
 * Dispatch a LOGIN notice.
 */

Code_t
ulogin_dispatch(notice, auth, who, server)
     ZNotice_t *notice;
     int auth;
     struct sockaddr_in *who;
     ZServerDesc_t *server;
{
	exposure_type retval;
	int err_ret;
	ZHostList_t *host;

#if 0
	zdbug((LOG_DEBUG,
	       "ulogin_dispatch: opc=%s from=%s/%d auth=%d who=%s/%d",
	       notice->z_opcode, notice->z_sender, ntohs (notice->z_port),
	       auth, inet_ntoa (who->sin_addr), ntohs (who->sin_port)));
#endif

	host = hostm_find_host(&who->sin_addr);
	if (host && host->zh_locked)
		return(ZSRV_REQUEUE);

	if (!strcmp(notice->z_opcode, LOGIN_USER_LOGOUT)) {
#if 0
		zdbug((LOG_DEBUG,"logout"));
#endif
		retval = ulogin_remove_user(notice, auth, who, &err_ret);
		switch (retval) {
		case NONE:
			if (err_ret == UNAUTH) {
#if 0
				zdbug((LOG_DEBUG, "unauth logout: %s %d",
				       inet_ntoa(who->sin_addr),
				       ntohs(notice->z_port)));
#endif
				if (server == me_server)
					clt_ack(notice, who, AUTH_FAILED);
				return(ZERR_NONE);
			} else if (err_ret == NOLOC) {
				if (server == me_server)
					clt_ack(notice, who, NOT_FOUND);
				return(ZERR_NONE);
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
			/* we assume that if this user is at a certain
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
		return(ZERR_NONE);
	}
	if (!bdumping && 
	    (!auth || strcmp(notice->z_sender, notice->z_class_inst)))  {
#if 1
		zdbug((LOG_DEBUG,"unauthentic ulogin: %d %s %s", auth,
		       notice->z_sender, notice->z_class_inst));
#endif
		if (server == me_server)
			clt_ack(notice, who, AUTH_FAILED);
		return(ZERR_NONE);
	}
	if (!strcmp(notice->z_opcode, LOGIN_USER_FLUSH)) {
#if 0
		zdbug((LOG_DEBUG, "user flush"));
#endif
		ulogin_flush_user(notice);
		if (server == me_server)
			ack(notice, who);
	} else if (!strcmp(notice->z_opcode, EXPOSE_NONE)) {
#if 0
		zdbug((LOG_DEBUG,"no expose"));
#endif
		(void) ulogin_remove_user(notice, auth, who, &err_ret);
		if (err_ret == UNAUTH) {
#if 0
			zdbug((LOG_DEBUG, "unauth noexpose: %s/%d",
			       inet_ntoa(who->sin_addr),
			       ntohs(notice->z_port)));
#endif
			if (server == me_server)
				clt_ack(notice, who, AUTH_FAILED);
			return(ZERR_NONE);
		} else if (err_ret == NOLOC) {
			if (server == me_server)
				clt_ack(notice, who, NOT_FOUND);
			return(ZERR_NONE);
		}
		if (server == me_server) {
			ack(notice, who);
			server_forward(notice, auth, who);
		}
		return(ZERR_NONE);
	} else if (!strcmp(notice->z_opcode, EXPOSE_OPSTAFF)) {
#if 0
		zdbug((LOG_DEBUG,"opstaff"));
#endif
		err_ret = ulogin_add_user(notice, OPSTAFF_VIS, who);
		if (server == me_server)
		    if (err_ret)
			nack(notice, who);
		    else
			ack(notice, who);
	} else if (!strcmp(notice->z_opcode, EXPOSE_REALMVIS)) {
#if 0
		zdbug((LOG_DEBUG,"realmvis"));
#endif
		err_ret = ulogin_add_user(notice, REALM_VIS, who);
		if (server == me_server) /* realm vis is not broadcast,
					    so we ack it here */
		    if (err_ret)
			nack(notice, who);
		    else
			ack(notice, who);
	} else if (!strcmp(notice->z_opcode, EXPOSE_REALMANN)) {
#if 0
		zdbug((LOG_DEBUG,"realmann"));
#endif
		err_ret = ulogin_add_user(notice, REALM_ANN, who);
		if (server == me_server) /* announce to the realm */
		    if (err_ret)
			nack(notice, who);
		    else
			login_sendit(notice, auth, who);
	} else if (!strcmp(notice->z_opcode, EXPOSE_NETVIS)) {
#if 0
		zdbug((LOG_DEBUG,"netvis"));
#endif
		err_ret = ulogin_add_user(notice, NET_VIS, who);
		if (server == me_server) /* announce to the realm */
		    if (err_ret)
			nack(notice, who);
		    else
			login_sendit(notice, auth, who);
	} else if (!strcmp(notice->z_opcode, EXPOSE_NETANN)) {
#if 0
		zdbug((LOG_DEBUG,"netann"));
#endif
		err_ret = ulogin_add_user(notice, NET_ANN, who);
		if (server == me_server) /* tell the world */
		    if (err_ret)
			nack(notice, who);
		    else
			login_sendit(notice, auth, who);
	} else {
		syslog(LOG_ERR, "unknown ulog opcode %s", notice->z_opcode);
		if (server == me_server)
			nack(notice, who);
		return(ZERR_NONE);
	}
	if (server == me_server)
		server_forward(notice, auth, who);
	return(ZERR_NONE);
}

static void
login_sendit(notice, auth, who)
     ZNotice_t *notice;
     int auth;
     struct sockaddr_in *who;
{
	ZNotice_t log_notice;

	/* we must copy the notice struct here because we need the original
	   for forwarding.  We needn't copy the private data of the notice,
	   since that isn't modified by sendit and its subroutines. */

	log_notice = *notice;

	log_notice.z_opcode = LOGIN_USER_LOGIN;
	sendit(&log_notice, auth, who);
	return;
}


/*
 * Dispatch a LOCATE notice.
 */
Code_t
ulocate_dispatch(notice, auth, who, server)
     ZNotice_t *notice;
     int auth;
     struct sockaddr_in *who;
     ZServerDesc_t *server;
{
#if 0
	zdbug((LOG_DEBUG,"ulocate_disp"));
#endif

#if 0 /* Now we support unauthentic locate for net-visible.  */
	if (!auth) {
#if 0
		zdbug((LOG_DEBUG,"unauthentic ulocate"));
#endif
		if (server == me_server)
			clt_ack(notice, who, AUTH_FAILED);
		return(ZERR_NONE);
	}
#endif
	if (!strcmp(notice->z_opcode, LOCATE_LOCATE)) {
#if 0
		zdbug((LOG_DEBUG,"locate"));
#endif
		/* we are talking to a current-rev client; send an ack */
		ack(notice, who);
		ulogin_locate(notice, who, auth);
		return(ZERR_NONE);
	} else {
		syslog(LOG_ERR, "unknown uloc opcode %s", notice->z_opcode);
		if (server == me_server)
			nack(notice, who);
		return(ZERR_NONE);
	}
#if 0
	if (server == me_server) {
		server_forward(notice, auth, who);
		ack(notice, who);
	}
#endif
	return(ZERR_NONE);
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

	if (num_locs == 0)
	    return;			/* none to flush */

	START_CRITICAL_CODE;

	/* slightly inefficient, assume the worst, and allocate enough space */
	loc = (ZLocation_t *) xmalloc(num_locs *sizeof(ZLocation_t));
	if (!loc) {
		syslog(LOG_CRIT, "uloc_flush alloc");
		abort();
		/*NOTREACHED*/
	}

	/* copy entries which don't match */
	while (i < num_locs) {
		if (locations[i].zlt_addr.s_addr != addr->s_addr)
			loc[new_num++] = locations[i];
		else {
#if 0
		    if (zdebug)
			syslog(LOG_DEBUG, "uloc hflushing %s/%s/%s",
			       locations[i].zlt_user->string,
			       locations[i].zlt_machine->string,
			       locations[i].zlt_tty->string);
#endif
		    free_loc(&locations[i]);
		}
		i++;
	}

	xfree(locations);
	locations = NULLZLT;

	if (!new_num) {
#if 0
		zdbug((LOG_DEBUG,"no more locs"));
#endif
		xfree(loc);
		loc = NULLZLT;
		num_locs = new_num;

		END_CRITICAL_CODE;

		return;
	}
	locations = loc;
	num_locs = new_num;

	END_CRITICAL_CODE;

	/* all done */
	return;
}

void
uloc_flush_client(sin)
     struct sockaddr_in *sin;
{
	ZLocation_t *loc;
	register int i = 0, new_num = 0;

	if (num_locs == 0)
	    return;			/* none to flush */

	START_CRITICAL_CODE;

	/* slightly inefficient, assume the worst, and allocate enough space */
	loc = (ZLocation_t *) xmalloc(num_locs *sizeof(ZLocation_t));
	if (!loc) {
		syslog(LOG_CRIT, "uloc_flush_clt alloc");
		abort();
		/*NOTREACHED*/
	}

	/* copy entries which don't match */
	while (i < num_locs) {
		if ((locations[i].zlt_addr.s_addr != sin->sin_addr.s_addr)
		     || (locations[i].zlt_port != sin->sin_port))
			loc[new_num++] = locations[i];
		else {
#if 0
		    if (zdebug)
			syslog(LOG_DEBUG, "uloc cflushing %s/%s/%s",
			       locations[i].zlt_user->string,
			       locations[i].zlt_machine->string,
			       locations[i].zlt_tty->string);
#endif
		    free_loc(&locations[i]);
		}
		i++;
	}

	xfree(locations);
	locations = NULLZLT;

	if (!new_num) {
#if 0
		zdbug((LOG_DEBUG,"no more locs"));
#endif
		xfree(loc);
		loc = NULLZLT;
		num_locs = new_num;

		END_CRITICAL_CODE;

		return;
	}
	locations = loc;
	num_locs = new_num;

	END_CRITICAL_CODE;

#ifdef DEBUG
	if (zdebug) {
		register int i;

		for (i = 0; i < num_locs; i++)
			syslog(LOG_DEBUG, "%s/%d",
			       locations[i].zlt_user->string,
			       (int) locations[i].zlt_exposure);
	}
#endif
	/* all done */
	return;
}

/*
 * Send the locations for host for a brain dump
 */

/*ARGSUSED*/
Code_t
uloc_send_locations(host, vers)
     ZHostList_t *host;
     char *vers;
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
		lyst[0] = (char *) loc->zlt_machine->string;
		lyst[1] = (char *) loc->zlt_time;
		lyst[2] = (char *) loc->zlt_tty->string;

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
			       loc->zlt_user->string,
			       (int) loc->zlt_exposure);
			break;
		}
		retval = bdump_send_list_tcp(ACKED, loc->zlt_port,
					     LOGIN_CLASS,
					     (char *) loc->zlt_user->string, /* XXX */
					     exposure_level,
					     myname, "", lyst,
					     NUM_FIELDS);
		if (retval != ZERR_NONE) {
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

static int
ulogin_add_user(notice, exposure, who)
     ZNotice_t *notice;
     exposure_type exposure;
     struct sockaddr_in *who;
{
	ZLocation_t *oldlocs, newloc;
	register int i;

	if ((oldlocs = ulogin_find(notice,1)) != NULLZLT) {
#if 0
		zdbug((LOG_DEBUG,"ul_add: already here"));
#endif
		(void) ulogin_expose_user(notice, exposure);
		return 0;
	}

	oldlocs = locations;

	START_CRITICAL_CODE;
	
	locations = (ZLocation_t *) xmalloc((num_locs +1) *
					    sizeof(ZLocation_t));
	if (!locations) {
		syslog(LOG_ERR, "zloc mem alloc");
		locations = oldlocs;
		return 1;
	}

	if (num_locs == 0) {		/* first one */
		if (ulogin_setup(notice, locations, exposure, who)) {
		  xfree(locations);
		  locations = NULLZLT;
		  END_CRITICAL_CODE;
		  return 1;
		}
		num_locs = 1;
		goto dprnt;
	}

	/* not the first one, insert him */

	if (ulogin_setup(notice, &newloc, exposure, who)) {
		xfree(locations);
		locations = oldlocs;
		END_CRITICAL_CODE;
		return 1;
	}
	num_locs++;

	/* copy old locs */
	i = 0;
	while ((i < num_locs-1) &&
	       (comp_zstring(oldlocs[i].zlt_user,newloc.zlt_user) < 0)) {
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
	if (oldlocs)
		xfree(oldlocs);

 dprnt:
#if 0
	if (zdebug) {
		register int i;
		syslog(LOG_DEBUG, "ul_add: New Locations (%d)", num_locs);
		for (i = 0; i < num_locs; i++)
			syslog(LOG_DEBUG, "%s/%s/%s/%d",
			       locations[i].zlt_user->string,
			       locations[i].zlt_machine->string,
			       locations[i].zlt_tty->string,
			       (int) locations[i].zlt_exposure);
	}
#endif
	END_CRITICAL_CODE;
	return 0;
}

/*
 * Set up the location locs with the information in the notice.
 */ 

static int
ulogin_setup(notice, locs, exposure, who)
     ZNotice_t *notice;
     ZLocation_t *locs;
     exposure_type exposure;
     struct sockaddr_in *who;
{
	if (ulogin_parse(notice, locs))
		return(1);

	if (!locs->zlt_user) {
	  syslog(LOG_ERR, "zloc bad format: no user");
	  return(1);
	}
	if (!locs->zlt_machine) {
	  syslog(LOG_ERR, "zloc bad format: no machine");
	  free_zstring(locs->zlt_user);
	  return(1);
		
	}
	if (!locs->zlt_tty) {
	  syslog(LOG_ERR, "zloc bad format: no tty");
	  free_zstring(locs->zlt_user);
	  free_zstring(locs->zlt_machine);
	  return(1);
	}
	if (!locs->zlt_time) {
	  syslog(LOG_ERR, "zloc bad format: no time");
	  free_zstring(locs->zlt_user);
	  free_zstring(locs->zlt_machine);
	  free_zstring(locs->zlt_tty);
	  return(1);
	}
	locs->zlt_exposure = exposure;
	locs->zlt_addr = who->sin_addr;
	locs->zlt_port = notice->z_port;
	return(0);
}

/*
 * Parse the location information in the notice, and fill it into *locs
 */

static int
ulogin_parse(notice, locs)
     ZNotice_t *notice;
     ZLocation_t *locs;
{
	register char *cp, *base;
	register int nulls = 0;

	if (!notice->z_message_len) {
		syslog(LOG_ERR, "short ulogin");
		return(1);
	}

	base = notice->z_message;
	for (cp = base; cp < base + notice->z_message_len; cp++)
	    if (! *cp) nulls++;
	if (nulls < 3) {
	    syslog(LOG_ERR, "zloc bad format from user %s (only %d fields)",
		   notice->z_sender, nulls);
	    return 1;
	}

	locs->zlt_user = make_zstring(notice->z_class_inst,0);

	cp = base;
	locs->zlt_machine = make_zstring(cp,0);
#if 0
	zdbug((LOG_DEBUG, "ul_parse: mach %s", cp));
#endif

	cp += (strlen(cp) + 1);
	locs->zlt_time = strsave(cp);
#if 0
	zdbug((LOG_DEBUG, "ul_parse: time %s", cp));
#endif

	/* This field might not be null-terminated */
	cp += (strlen(cp) + 1);
#if 0
	if (nulls == 2) {
	    s = (char *)xmalloc(base + notice->z_message_len - cp + 1);
	    strncpy(s, cp);
	    locs->zlt_tty = make_zstring(s, 0);
	    xfree(s);
	} else
#endif
	    locs->zlt_tty = make_zstring(cp,0);
#if 0
	zdbug((LOG_DEBUG, "ul_parse: tty %s", locs->zlt_tty->string));
#endif

	return 0;
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
	ZLocation_t tmploc;
	int compar;
	ZSTRING *inst;

	if (!locations)
		return(NULLZLT);

	inst = make_zstring(notice->z_class_inst,0);

	/* i is the current loc we are checking */
	/* rlo is the lowest we will still check, rhi is the highest we will
	   still check */

	i = num_locs >> 1;		/* start in the middle */
	rlo = 0;
	rhi = num_locs - 1;		/* first index is 0 */

	while ((compar = comp_zstring(locations[i].zlt_user, inst)) != 0) {
#if 0
		zdbug ((LOG_DEBUG, "ulogin_find: comparing %s %s %s %d %d",
			notice->z_class_inst,
			locations[i].zlt_user->string,
			locations[i].zlt_tty->string,
			rlo, rhi));
#endif
		if (compar < 0)
			rlo = i + 1;
		else
			rhi = i - 1;
		if (rhi - rlo < 0) {
#if 0
			zdbug((LOG_DEBUG,"ul_find: %s not found",
			       inst->string));
#endif
			free_zstring(inst);
			return 0;
		}
		i = (rhi + rlo) >> 1; /* split the diff */
	}
#if 0
	zdbug((LOG_DEBUG, "ul_find: %s found at loc %d",
	       inst->string, i));
#endif
	if (strict && ulogin_parse(notice, &tmploc)) {
#if 1
		zdbug((LOG_DEBUG,"ul_find bad fmt"));
#endif
		free_zstring(inst);
		return 0;
	}
	/* back up to the first of this guy */
	while (i > 0 && (locations[i-1].zlt_user == inst)) {
	    i--;
#if 0
	    zdbug ((LOG_DEBUG,
		    "ulogin_find: backing up: %s %d %s %s",
		    inst->string, i,
		    locations[i].zlt_user->string,
		    locations[i].zlt_tty->string));
#endif
	}
	if (strict)
		while (i < num_locs
		       && !ul_equiv(&tmploc, &locations[i])
		       && (locations[i].zlt_user == inst)) {
			i++;
		}

	if ((i == num_locs) || (locations[i].zlt_user != inst)) {
#if 1
		zdbug((LOG_DEBUG,"ul_find final match loss"));
#endif
		free_zstring(inst);
		return 0;
	}
	if (strict)
	  free_loc(&tmploc);
	free_zstring(inst);
	return &locations[i];
}

static int
ul_equiv(l1, l2)
register ZLocation_t *l1, *l2;
{
        if (l1->zlt_machine != l2->zlt_machine)
                return(0);
        if (l1->zlt_tty != l2->zlt_tty)
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
	exposure_type quiet;

	*err_return = 0;
	if (!(loc2 = ulogin_find(notice, 1))) {
#if 0
		zdbug((LOG_DEBUG,"ul_rem: not here"));
#endif
		*err_return = NOLOC;
		return(NONE);
	}

	/* if unauthentic, the sender MUST be the same IP addr
	   that registered */
	if (!auth && loc2->zlt_addr.s_addr != who->sin_addr.s_addr) {
		*err_return = UNAUTH;
		return NONE;
	}

	quiet = loc2->zlt_exposure;

	START_CRITICAL_CODE;
	if (--num_locs == 0) {		/* last one */
#if 0
		zdbug((LOG_DEBUG,"last loc"));
#endif
		free_loc(locations);
		xfree(locations);
		locations = NULLZLT;
		END_CRITICAL_CODE;
		return(quiet);
	}

	loc = (ZLocation_t *) xmalloc(num_locs * sizeof(ZLocation_t));
	if (!loc) {
		syslog(LOG_CRIT, "ul_rem alloc");
		abort();
		/*NOTREACHED*/
	}

	/* copy old entries */
	while (i < num_locs && &locations[i] < loc2) {
		loc[i] = locations[i];
		i++;
	}

	/* free up this one */
	free_loc(&locations[i]);
	i++;				/* skip over this one */

	/* copy the rest */
	while (i <= num_locs) {
		loc[i - 1] = locations[i];
		i++;
	}

	xfree(locations);

	locations = loc;

	END_CRITICAL_CODE;

#if defined(DEBUG) && 0
	if (zdebug) {
		register int i;

		for (i = 0; i < num_locs; i++)
			syslog(LOG_DEBUG, "%s/%d",
			       locations[i].zlt_user->string,
			       (int) locations[i].zlt_exposure);
	}
#endif
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
	register ZLocation_t *loc, *loc2;
	register int i, j, num_match, num_left;

	i = num_match = num_left = 0;

	if (!(loc2 = ulogin_find(notice, 0))) {
#if 0
	    zdbug((LOG_DEBUG,"ul_rem: not here"));
#endif
	    return;
	}

	/* compute # locations left in the list, after loc2 (inclusive) */
	num_left = num_locs - (loc2 - locations);

	START_CRITICAL_CODE;

	while (num_left &&
	       !strcasecmp(loc2[num_match].zlt_user->string,
		       notice->z_class_inst)) {
		/* as long as we keep matching, march up the list */
		num_match++;
		num_left--;
	}
	if (num_locs == num_match) {	/* no other locations left */
#if 0
		zdbug((LOG_DEBUG,"last loc"));
#endif
		for (j = 0; j < num_match; j++)
			free_loc(&locations[j]); /* free storage */
		xfree (locations);
		locations = NULLZLT;
		num_locs = 0;
		END_CRITICAL_CODE;
		return;
	}

	loc = (ZLocation_t *) xmalloc((num_locs - num_match) *
				      sizeof(ZLocation_t));
	if (!loc) {
		syslog(LOG_CRIT, "ul_rem alloc");
		abort();
		/*NOTREACHED*/
	}

	/* copy old entries */
	while (i < num_locs && &locations[i] < loc2) {
	  loc[i] = locations[i];
	  i++;
	}
	
	for(j = 0; j < num_match; j++) {
	  free_loc(&locations[i]);
	  i++;
	}

	/* copy the rest */
	while (i < num_locs) {
		loc[i - num_match] = locations[i];
		i++;
	}

	xfree(locations);

	locations = loc;
	num_locs -= num_match;

	END_CRITICAL_CODE;
	
#ifdef DEBUG
	if (zdebug) {
		register int i;

		for (i = 0; i < num_locs; i++)
			syslog(LOG_DEBUG, "%s/%d",
			       locations[i].zlt_user->string,
			       (int) locations[i].zlt_exposure);
	}
#endif
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
	int idx, notfound = 1;

#if 0
	zdbug((LOG_DEBUG,"ul_expose: %s type %d", notice->z_sender,
	       (int) exposure));
#endif

	if (ulogin_parse(notice, &loc2))
		return(1);

	if (!(loc = ulogin_find(notice, 0))) {
#if 0
		zdbug((LOG_DEBUG,"ul_hide: not here"));
#endif
		return(1);
	}

	idx = loc -locations;

	while ((idx < num_locs) &&
	       locations[idx].zlt_user == loc2.zlt_user) {

		/* change exposure and owner for each loc on that host */
		if (locations[idx].zlt_machine == loc2.zlt_machine) {
			notfound = 0;
			locations[idx].zlt_exposure = exposure;
			locations[idx].zlt_port = notice->z_port;
			/* change time for the specific loc */
			if (locations[idx].zlt_tty == loc2.zlt_tty) {
			  xfree(locations[idx].zlt_time);
			  locations[idx].zlt_time = strsave(loc2.zlt_time);
			}
		}
		idx++;
	}
	return(notfound);
}


static void
ulogin_locate(notice, who, auth)
     ZNotice_t *notice;
     struct sockaddr_in *who;
     int auth;
{
	char **answer;
	int found;
	Code_t retval;
	struct sockaddr_in send_to_who;

	answer = ulogin_marshal_locs(notice, &found, auth);

	send_to_who = *who;
	send_to_who.sin_port = notice->z_port;

	if ((retval = ZSetDestAddr(&send_to_who)) != ZERR_NONE) {
		syslog(LOG_WARNING, "ulogin_locate set addr: %s",
		       error_message(retval));
		if (answer)
			xfree(answer);
		return;
	}

	notice->z_kind = ACKED;

	/* use xmit_frag() to send each piece of the notice */

	if ((retval = ZSrvSendRawList(notice, answer, found*NUM_FIELDS,
				      xmit_frag))
	    != ZERR_NONE) {
		syslog(LOG_WARNING, "ulog_locate xmit: %s",
		       error_message(retval));
	}
	if (answer)
		xfree(answer);
	return;
}

/*
 * Locate the user and collect the locations into an array.  Return the # of
 * locations in *found.
 */

static char **
ulogin_marshal_locs(notice, found, auth)
     ZNotice_t *notice;
     register int *found;
     int auth;
{
	ZLocation_t **matches = (ZLocation_t **) 0;
	ZLocation_t *loc;
	char **answer;
	register int i = 0;
	ZSTRING *inst;

	*found = 0;			/* # of matches */

	if (!(loc = ulogin_find(notice, 0)))
		/* not here anywhere */
		return((char **)0);

	i = loc - locations;

	inst = make_zstring(notice->z_class_inst,0);
	while (i < num_locs && (inst == locations[i].zlt_user)) {
		/* these locations match */
#if 0
		zdbug((LOG_DEBUG,"match %s", locations[i].zlt_user->string));
#endif
		switch (locations[i].zlt_exposure) {
		case OPSTAFF_VIS:
			i++;
			continue;
		case REALM_VIS:
		case REALM_ANN:
			if (!auth) {
			    i++;
			    continue;
			}
		case NET_VIS:
		case NET_ANN:
		default:
			break;
		}
		if (!*found) {
			if ((matches = (ZLocation_t **) xmalloc(sizeof(ZLocation_t *))) == (ZLocation_t **) 0) {
				syslog(LOG_ERR, "ulog_loc: no mem");
				break;	/* from the while */
			}
			matches[0] = &locations[i];
			(*found)++;
		} else {
			if ((matches = (ZLocation_t **) realloc((caddr_t) matches, (unsigned) ++(*found) * sizeof(ZLocation_t *))) == (ZLocation_t **) 0) {
				syslog(LOG_ERR, "ulog_loc: realloc no mem");
				*found = 0;
				break;	/* from the while */
			}
			matches[*found - 1] = &locations[i];
		}
		i++;
	}
	free_zstring(inst);

	/* OK, now we have a list of user@host's to return to the client
	   in matches */


#ifdef DEBUG
	if (zdebug) {
		for (i = 0; i < *found ; i++)
			zdbug((LOG_DEBUG,"found %s",
			       matches[i]->zlt_user->string));
	}
#endif

	/* coalesce the location information into a list of char *'s */
	if ((answer = (char **)xmalloc((*found) * NUM_FIELDS * sizeof(char *))) == (char **) 0) {
		syslog(LOG_ERR, "zloc no mem(answer)");
		*found = 0;
	} else
		for (i = 0; i < *found ; i++) {
			answer[i*NUM_FIELDS] = (char *) matches[i]->zlt_machine->string;
			answer[i*NUM_FIELDS + 1] = (char *) matches[i]->zlt_time;
			answer[i*NUM_FIELDS + 2] = (char *) matches[i]->zlt_tty->string;
		}

	if (matches)
	    xfree(matches);
	return(answer);
}

void
uloc_dump_locs(fp)
     register FILE *fp;
{
	register int i;
	char buf[BUFSIZ*3];
	static char *bufp;
	static Zconst char *cp;

	/* delay using stdio so that we can run FAST! */
	for (i = 0; i < num_locs; i++) {
		bufp = buf;
#define cpy(str) cp=(str);while(*cp){*bufp++ = *cp++;}
		cpy (locations[i].zlt_user->string);
		*bufp++ = '/';
		cpy (locations[i].zlt_machine->string);
		*bufp++ = '/';
		cpy (locations[i].zlt_time);
		*bufp++ = '/';
		cpy (locations[i].zlt_tty->string);
		switch (locations[i].zlt_exposure) {
		case OPSTAFF_VIS:
			cpy ("/OPSTAFF/");
			break;
		case REALM_VIS:
			cpy ("/RLM_VIS/");
			break;
		case REALM_ANN:
			cpy ("/RLM_ANN/");
			break;
		case NET_VIS:
			cpy ("/NET_VIS/");
			break;
		case NET_ANN:
			cpy ("/NET_ANN/");
			break;
		default:
			sprintf (bufp, "/? %d ?/", locations[i].zlt_exposure);
			while (*bufp)
			    bufp++;
			break;
		}
		cpy (inet_ntoa (locations[i].zlt_addr));
		*bufp++ = '/';
		sprintf(bufp, "%d", ntohs(locations[i].zlt_port));
		fputs(buf, fp);
		(void) putc('\n', fp);
#undef cpy
	}
	return;
}

static void
free_loc(loc)
     ZLocation_t *loc;
{
  free_zstring(loc->zlt_user);
  free_zstring(loc->zlt_machine);
  free_zstring(loc->zlt_tty);
  xfree(loc->zlt_time);
  return;
}
