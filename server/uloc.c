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
static char rcsid_uloc_c[] =
  "$Id$";
#endif

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

enum exposure_type {
	NONE,
	OPSTAFF_VIS,
	REALM_VIS,
	REALM_ANN,
	NET_VIS,
	NET_ANN
};

struct ZLocation_t {
	ZString zlt_user;
	ZString zlt_machine;
	ZString zlt_time;		/* in ctime format */
	ZString zlt_tty;
	struct in_addr zlt_addr;	/* IP addr of this loc */
	unsigned short zlt_port;	/* port of registering client--
					   for removing old entries */
#if defined(__GNUC__) || defined(__GNUG__)
	exposure_type zlt_exposure : 16;
#else
	exposure_type zlt_exposure;
#endif

#if !defined(__GNUG__) || defined(FIXED_GXX)
	void *operator new (unsigned int sz) { return zalloc (sz); }
	void operator delete (void *ptr) { zfree (ptr, sizeof (ZLocation_t)); }
#endif
};

inline int operator == (const ZLocation_t &l1, const ZLocation_t &l2) {
	return (!strcasecmp (l1.zlt_machine.value(), l2.zlt_machine.value())
		&& l1.zlt_tty == l2.zlt_tty);
}
inline int operator != (const ZLocation_t &l1, const ZLocation_t &l2) {
	return !(l1 == l2);
}

static ZLocation_t* const	NULLZLT = 0;
static const int		NOLOC	= 1;
static const int		QUIET	= -1;
static const int		UNAUTH	= -2;

static void ulogin_locate(ZNotice_t *, struct sockaddr_in *who, int auth),
    ulogin_add_user(ZNotice_t *notice, exposure_type exposure,
		    struct sockaddr_in *who),
    ulogin_flush_user(ZNotice_t *notice);
static ZLocation_t **ulogin_find(ZNotice_t *notice, int strict);
static int ulogin_setup(ZNotice_t *notice, ZLocation_t **locs,
			exposure_type exposure, struct sockaddr_in *who),
    ulogin_parse(ZNotice_t *notice, ZLocation_t **locs),
    ulogin_expose_user(ZNotice_t *notice, exposure_type exposure);
static exposure_type ulogin_remove_user(ZNotice_t *notice, int auth,
					struct sockaddr_in *who,
					int *err_return);
static void login_sendit(ZNotice_t *notice, int auth, struct sockaddr_in *who),
    sense_logout(ZNotice_t *notice, struct sockaddr_in *who);
static char **ulogin_marshal_locs(ZNotice_t *notice, int *found, int auth);

static ZLocation_t **locations = 0; /* ptr to first in array */
static int num_locs = 0;	/* number in array */

/*
 * Dispatch a LOGIN notice.
 */

Code_t
ulogin_dispatch(ZNotice_t *notice, int auth, struct sockaddr_in *who,
		ZServerDesc_t *server)
{
	exposure_type retval;
	int err_ret;
	ZHostList_t *host;

#if 1
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
				if (server == me_server) {
					clt_ack(notice, who, AUTH_FAILED);
					sense_logout(notice, who);
				}
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
	if (!auth || strcmp(notice->z_sender, notice->z_class_inst)) {
#if 1
		zdbug((LOG_DEBUG,"unauthentic ulogin: %d %s %s", auth,
		       notice->z_sender, notice->z_class_inst));
#endif
		sense_logout(notice, who);
		if (server == me_server)
			clt_ack(notice, who, AUTH_FAILED);
		if (!bdumping /* XXX: inter-server and tcp */)
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
#if 1
		zdbug((LOG_DEBUG,"opstaff"));
#endif
		ulogin_add_user(notice, OPSTAFF_VIS, who);
		if (server == me_server)
			ack(notice, who);
	} else if (!strcmp(notice->z_opcode, EXPOSE_REALMVIS)) {
#if 1
		zdbug((LOG_DEBUG,"realmvis"));
#endif
		ulogin_add_user(notice, REALM_VIS, who);
		if (server == me_server) /* realm vis is not broadcast,
					    so we ack it here */
			ack(notice, who);
	} else if (!strcmp(notice->z_opcode, EXPOSE_REALMANN)) {
#if 1
		zdbug((LOG_DEBUG,"realmann"));
#endif
		ulogin_add_user(notice, REALM_ANN, who);
		if (server == me_server) /* announce to the realm */
			login_sendit(notice, auth, who);
	} else if (!strcmp(notice->z_opcode, EXPOSE_NETVIS)) {
#if 1
		zdbug((LOG_DEBUG,"netvis"));
#endif
		ulogin_add_user(notice, NET_VIS, who);
		if (server == me_server) /* announce to the realm */
			login_sendit(notice, auth, who);
	} else if (!strcmp(notice->z_opcode, EXPOSE_NETANN)) {
#if 1
		zdbug((LOG_DEBUG,"netann"));
#endif
		ulogin_add_user(notice, NET_ANN, who);
		if (server == me_server) /* tell the world */
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
login_sendit(ZNotice_t *notice, int auth, struct sockaddr_in *who)
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


/*ARGSUSED*/
static void
sense_logout(ZNotice_t *notice, struct sockaddr_in *who)
{
	ZNotice_t sense_notice;
	ZLocation_t *loc, **locptr;
	struct sockaddr_in owner;
	char message[BUFSIZ];
	int retval, len;
	char *pkt;
	ZClient_t *client;

	/* XXX todo: have the messsage print the IP addr */
	/*
	  someone tried an unauthentic logout.  Try to send a message
	  to the person named in the message, warning them of this.
	  If there is nobody listening on that port, the retransmission
	  will eventually result in a flush of the location.
	 */

	locptr = ulogin_find (notice, 1);
	if (!locptr)
	    return;
	loc = *locptr;
	assert (loc != 0);

	/* fabricate an addr descriptor for him */
	owner = *who;
	owner.sin_addr.s_addr = loc->zlt_addr.s_addr;
	owner.sin_port = loc->zlt_port;

	sense_notice = *notice;		/* copy all fields */
	/* and change the ones we need to */
	sense_notice.z_kind = ACKED;
	sense_notice.z_port = loc->zlt_port;
	sense_notice.z_class = "MESSAGE";
	sense_notice.z_class_inst = "URGENT";
	sense_notice.z_opcode = "";
	sense_notice.z_sender = "Zephyr Server";
	sense_notice.z_recipient = (char *) loc->zlt_user.value ();
	sense_notice.z_default_format = "Urgent Message from $sender at $time:\n\n$1";
	(void) sprintf(message,
		       "Someone at host %s tried an unauthorized \nchange to your login information",
		       inet_ntoa(notice->z_sender_addr));
	sense_notice.z_message = message;
	sense_notice.z_message_len = strlen(message) + 1;

	/* we format the notice to generate a UID and other stuff */
	if ((retval = ZFormatNotice(&sense_notice, &pkt, &len, ZNOAUTH))
	    != ZERR_NONE) {
		syslog(LOG_ERR, "sense_logout: %s", error_message(retval));
		return;
	}
	xfree(pkt);			/* free packet */

	client = client_which_client(who, &sense_notice);
	/* transmit the message to the owning port of the location. */
	xmit(&sense_notice, &owner, 1, client);
	return;	
}
/*
 * Dispatch a LOCATE notice.
 */

Code_t
ulocate_dispatch(ZNotice_t *notice, int auth, struct sockaddr_in *who, ZServerDesc_t *server)
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
		/* we are talking to a current-rev client; send an
		   acknowledgement-message */
			ack(notice, who);
		ulogin_locate(notice, who, auth);
		return(ZERR_NONE);
	} else {
		syslog(LOG_ERR, "unknown uloc opcode %s", notice->z_opcode);
		if (server == me_server)
			nack(notice, who);
	}
	if (server == me_server) {
		server_forward(notice, auth, who);
		ack(notice, who);
	}
	return(ZERR_NONE);
}

/*
 * Flush all locations at the address.
 */

void
uloc_hflush(struct in_addr *addr)
{
	ZLocation_t **loc;
	register int i = 0, new_num = 0;
	int omask;

	if (num_locs == 0)
	    return;			/* none to flush */

	omask = sigblock(sigmask(SIGFPE)); /* don't do ascii dumps */

	/* slightly inefficient, assume the worst, and allocate enough space */
	loc = new ZLocation_t* [num_locs];
	if (!loc) {
		syslog(LOG_CRIT, "uloc_flush alloc");
		abort();
		/*NOTREACHED*/
	}

	/* copy entries which don't match */
	while (i < num_locs) {
		if (locations[i]->zlt_addr.s_addr != addr->s_addr)
			loc[new_num++] = locations[i];
		else {
#if 0
		    if (zdebug)
			syslog(LOG_DEBUG, "uloc hflushing %s/%s/%s",
			       locations[i]->zlt_user.value (),
			       locations[i]->zlt_machine.value(),
			       locations[i]->zlt_tty.value());
#endif
		    delete locations[i];
		}
		i++;
	}

	delete locations;

	if (!new_num) {
#if 0
		zdbug((LOG_DEBUG,"no more locs"));
#endif
		delete loc;
		loc = 0;
		(void) sigsetmask(omask);
		return;
	}
	locations = loc;
	num_locs = new_num;

	(void) sigsetmask(omask);
#ifdef DEBUG
	if (zdebug) {
		register int i;

		for (i = 0; i < num_locs; i++)
			syslog(LOG_DEBUG, "%s/%d",
			       locations[i]->zlt_user.value (),
			       (int) locations[i]->zlt_exposure);
	}
#endif
	/* all done */
	return;
}

void
uloc_flush_client(struct sockaddr_in *sin)
{
	ZLocation_t **loc;
	register int i = 0, new_num = 0;
	int omask;

	if (num_locs == 0)
	    return;			/* none to flush */

	omask = sigblock(sigmask(SIGFPE)); /* don't do ascii dumps */

	/* slightly inefficient, assume the worst, and allocate enough space */
	loc = new ZLocation_t* [num_locs];
	if (!loc) {
		syslog(LOG_CRIT, "uloc_flush_clt alloc");
		abort();
		/*NOTREACHED*/
	}

	/* copy entries which don't match */
	while (i < num_locs) {
		if ((locations[i]->zlt_addr.s_addr != sin->sin_addr.s_addr)
		     || (locations[i]->zlt_port != sin->sin_port))
			loc[new_num++] = locations[i];
		else {
#if 0
		    if (zdebug)
			syslog(LOG_DEBUG, "uloc cflushing %s/%s/%s",
			       locations[i]->zlt_user.value (),
			       locations[i]->zlt_machine.value(),
			       locations[i]->zlt_tty.value());
#endif
		    delete locations[i];
		}
		i++;
	}

	delete locations;

	if (!new_num) {
#if 0
		zdbug((LOG_DEBUG,"no more locs"));
#endif
		delete loc;
		loc = 0;
	}
	locations = loc;
	num_locs = new_num;

	(void) sigsetmask(omask);
#ifdef DEBUG
	if (zdebug) {
		register int i;

		for (i = 0; i < num_locs; i++)
			syslog(LOG_DEBUG, "%s/%d",
			       locations[i]->zlt_user.value (),
			       (int) locations[i]->zlt_exposure);
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
uloc_send_locations(ZHostList_t *host, char *vers)
{
	register ZLocation_t *loc;
	register int i;
	register struct in_addr *haddr = &host->zh_addr.sin_addr;
	char *lyst[NUM_FIELDS];
	char *exposure_level;
	Code_t retval;

	for (i = 0; i < num_locs; i++) {
		loc = locations[i];
		if (loc->zlt_addr.s_addr != haddr->s_addr)
			continue;
		lyst[0] = (char *) loc->zlt_machine.value();
		lyst[1] = (char *) loc->zlt_time.value();
		lyst[2] = (char *) loc->zlt_tty.value ();

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
			       loc->zlt_user.value (),
			       (int) loc->zlt_exposure);
			break;
		}
		retval = bdump_send_list_tcp(ACKED, loc->zlt_port,
					     LOGIN_CLASS,
					     (char *) loc->zlt_user.value (), /* XXX */
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

static void
ulogin_add_user(ZNotice_t *notice, exposure_type exposure, sockaddr_in *who)
{
	ZLocation_t **oldlocs, *newloc;
	register int i = 0;
	int omask;

#if 1
	zdbug((LOG_DEBUG,"ul_add: %s type %d", notice->z_sender,
	       (int) exposure));
#endif

	{
	    ZLocation_t **tmp = ulogin_find (notice, 1);
	    newloc = tmp ? *tmp : 0;
	}
	if (newloc) {
#if 1
		zdbug((LOG_DEBUG,"ul_add: already here"));
#endif
		(void) ulogin_expose_user(notice, exposure);
		return;
	}

	oldlocs = locations;

	omask = sigblock(sigmask(SIGFPE)); /* don't do ascii dumps */
	locations = new ZLocation_t* [num_locs + 1];
	if (!locations) {
		syslog(LOG_ERR, "zloc mem alloc");
		locations = oldlocs;
		return;
	}

	if (num_locs == 0) {		/* first one */
		if (ulogin_setup(notice, locations, exposure, who)) {
			delete locations;
			locations = 0;
		}
		else
			num_locs = 1;
		goto dprnt;
	}

	/* not the first one, insert him */

	if (ulogin_setup(notice, &newloc, exposure, who)) {
		(void) sigsetmask(omask);
		return;
	}
	num_locs++;

	/* copy old locs */
	while ((i < (num_locs - 1)) && oldlocs[i]->zlt_user < newloc->zlt_user) {
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
		delete oldlocs;

 dprnt:
	(void) sigsetmask(omask);
#ifdef DEBUG
	if (zdebug) {
		register int i;

		for (i = 0; i < num_locs; i++)
			syslog(LOG_DEBUG, "%s/%d",
			       locations[i]->zlt_user.value (),
			       (int) locations[i]->zlt_exposure);
	}
#endif
	return;
}

/*
 * Set up the location locs with the information in the notice.
 */ 

static int
ulogin_setup(ZNotice_t *notice, ZLocation_t **locs, exposure_type exposure, sockaddr_in *who)
{
	if (ulogin_parse(notice, locs))
		return(1);
	ZLocation_t *loc = *locs;
	if (!loc->zlt_user) {
	ret1:
		syslog(LOG_ERR, "zloc bad format");
		return 1;
	}
	if (!loc->zlt_machine) {
	ret2:
		loc->zlt_user = 0;
		goto ret1;
	}
	if (!loc->zlt_tty) {
	ret3:
		loc->zlt_machine = 0;
		goto ret2;
	}
	if (!loc->zlt_time) {
		loc->zlt_tty = 0;
		goto ret3;
	}
	loc->zlt_exposure = exposure;
	loc->zlt_addr = who->sin_addr;
	loc->zlt_port = notice->z_port;
	return 0;
}

/*
 * Parse the location information in the notice, and fill it into *locs
 */

static int
ulogin_parse(ZNotice_t *notice, ZLocation_t **locs)
{
	register char *cp, *base;
	ZLocation_t *loc = new ZLocation_t;
	*locs = 0;

	if (!notice->z_message_len) {
		syslog(LOG_ERR, "short ulogin");
		return(1);
	}

	loc->zlt_user = notice->z_class_inst;
	cp = base = notice->z_message;

#if 0
	zdbug((LOG_DEBUG,"user %s",notice->z_class_inst));
#endif

	loc->zlt_machine = cp;
#if 0
	zdbug((LOG_DEBUG,"mach %s",cp));
#endif

	cp += (strlen(cp) + 1);
	if (cp >= base + notice->z_message_len) {
		syslog(LOG_ERR, "zloc bad format 1");
		return(1);
	}
	loc->zlt_time = cp;
#if 0
	zdbug((LOG_DEBUG,"time %s",cp));
#endif

	cp += (strlen(cp) + 1);

	if (cp > base + notice->z_message_len) {
		syslog(LOG_ERR, "zloc bad format 2");
		return(1);
	} else {
		loc->zlt_tty = cp;
#if 0
		zdbug((LOG_DEBUG,"tty %s",cp));
#endif
		cp += loc->zlt_tty.length () + 1;
	}
	if (cp > base + notice->z_message_len) {
		syslog(LOG_ERR, "zloc bad format 3");
		return(1);
	}
	*locs = loc;
	return(0);
}	

/*
 * Find the username specified in notice->z_class_inst.
 * If strict, make sure the locations in notice and the table match.
 * Otherwise return a pointer to the first instance of this user@realm
 * in the table.
 */

static ZLocation_t **
ulogin_find(ZNotice_t *notice, int strict)
{
	register int i, rlo, rhi;
	ZLocation_t *tmploc = 0;

	if (num_locs == 0)
		return 0;

	ZString inst (notice->z_class_inst);

	/* i is the current loc we are checking */
	/* rlo is the lowest we will still check, rhi is the highest we will
	   still check */

	i = num_locs >> 1;		/* start in the middle */
	rlo = 0;
	rhi = num_locs - 1;		/* first index is 0 */

	while (locations[i]->zlt_user != inst) {
#if 1
		zdbug ((LOG_DEBUG, "ulogin_find: comparing %s %s %s %d %d",
			notice->z_class_inst,
			locations[i]->zlt_user.value (),
			locations[i]->zlt_tty.value (),
			rlo, rhi));
#endif
		if (locations[i]->zlt_user < inst)
			rlo = i + 1;
		else
			rhi = i - 1;
		if (rhi - rlo < 0) {
#if 1
			zdbug((LOG_DEBUG,"ul_find not found"));
#endif
			return 0;
		}
		i = (rhi + rlo) >> 1; /* split the diff */
	}
	if (strict  && ulogin_parse(notice, &tmploc)) {
#if 1
		zdbug((LOG_DEBUG,"ul_find bad fmt"));
#endif
		return 0;
	}
	/* back up to the first of this guy */
	if (i) {
		while (i > 0 && locations[--i]->zlt_user == inst) {
#if 0
			zdbug ((LOG_DEBUG,
				"ulogin_find: backing up: %s %d %s %s",
				inst.value (), i,
				locations[i]->zlt_user.value (),
				locations[i]->zlt_tty.value ()));
#endif
		}
		if (i || locations[i]->zlt_user != inst)
		  i++;
	}
	if (strict)
		while (i < num_locs
		       && *tmploc != *locations[i]
		       && locations[i]->zlt_user == inst) {
			i++;
		}

	if ((i == num_locs) || locations[i]->zlt_user != inst) {
#if 1
		zdbug((LOG_DEBUG,"ul_find final match loss"));
#endif
		if (tmploc)
		  delete tmploc;
		return 0;
	}
	if (tmploc)
	  delete tmploc;
	return &locations[i];
}

/*
 * remove the user specified in notice from the internal table
 */

static exposure_type
ulogin_remove_user(ZNotice_t *notice, int auth, sockaddr_in *who, int *err_return)
{
	ZLocation_t **loc, *loc2;
	register int i = 0;
	exposure_type quiet;
	int omask;

	*err_return = 0;
	loc = ulogin_find (notice, 1);
	if (!loc || !(loc2 = *loc)) {
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

	omask = sigblock(sigmask(SIGFPE)); /* don't let disk db dumps start */
	if (--num_locs == 0) {		/* last one */
#if 0
		zdbug((LOG_DEBUG,"last loc"));
#endif
		delete locations;
		locations = 0;
		(void) sigsetmask(omask);
		return(quiet);
	}

	loc = new ZLocation_t* [num_locs];
	if (!loc) {
		syslog(LOG_CRIT, "ul_rem alloc");
		abort();
		/*NOTREACHED*/
	}

	/* copy old entries */
	while (i < num_locs && locations[i] != loc2) {
		loc[i] = locations[i];
		i++;
	}

	/* free up this one */
	delete locations[i];
	i++;				/* skip over this one */

	/* copy the rest */
	while (i <= num_locs) {
		loc[i - 1] = locations[i];
		i++;
	}

	delete locations;

	locations = loc;

	(void) sigsetmask(omask);
#if defined(DEBUG) && 0
	if (zdebug) {
		register int i;

		for (i = 0; i < num_locs; i++)
			syslog(LOG_DEBUG, "%s/%d",
			       locations[i]->zlt_user.value(),
			       (int) locations[i]->zlt_exposure);
	}
#endif
	/* all done */
	return(quiet);
}

/*
 * remove all locs of the user specified in notice from the internal table
 */

static void
ulogin_flush_user(ZNotice_t *notice)
{
	register ZLocation_t **loc, **loc2, *loc3;
	register int i, j, num_match, num_left;
	int omask;

	num_match = num_left = 0;

	if (!(loc2 = ulogin_find(notice, 0))) {
#if 0
	    zdbug((LOG_DEBUG,"ul_rem: not here"));
#endif
	    return;
	}

	/* compute # locations left in the list, after loc2 (inclusive) */
	{
	    int k;
	    ZLocation_t *tmp = *loc2;
	    for (k = 0; locations[k] != tmp; k++)
		;
	    num_left = num_locs - k;
	}

	omask = sigblock(sigmask(SIGFPE)); /* don't let disk db dumps start */
	while (num_left &&
	       !strcmp(loc2[num_match]->zlt_user.value(),
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
			delete locations[j]; /* free storage */
		delete locations;
		locations = 0;
		num_locs = 0;
		(void) sigsetmask(omask);
		return;
	}

	loc = new ZLocation_t* [num_locs - num_match];
	if (!loc) {
		syslog(LOG_CRIT, "ul_rem alloc");
		abort();
		/*NOTREACHED*/
	}

	/* copy old entries */
	loc3 = *loc2;
	i = 0;
	while (1) {
	    ZLocation_t *tmp = locations[i];
	    if (tmp == loc3)
		break;
#if 0
	    if (i >= num_locs)
		break;
#endif
	    loc[i] = tmp;
	    i++;
	}

	/* skip over (and delete) matches */
	j = i + num_match;
	while (i < j)
	    delete locations[i++];

	/* copy the rest */
	while (i < num_locs) {
		/* XXX should bcopy */
		loc[i - num_match] = locations[i];
		i++;
	}

	delete locations;

	locations = loc;
	num_locs -= num_match;

	(void) sigsetmask(omask);
#ifdef DEBUG
	if (zdebug) {
		register int i;

		for (i = 0; i < num_locs; i++)
			syslog(LOG_DEBUG, "%s/%d",
			       locations[i]->zlt_user.value(),
			       (int) locations[i]->zlt_exposure);
	}
#endif
	/* all done */
	return;
}

/*
 * Set the user's exposure flag to exposure
 */

static int
ulogin_expose_user(ZNotice_t *notice, exposure_type exposure)
{
	ZLocation_t *loc, *loc2;
	int idx, notfound = 1;

#if 0
	zdbug((LOG_DEBUG,"ul_expose: %s type %d", notice->z_sender,
	       (int) exposure));
#endif

	if (ulogin_parse(notice, &loc2))
		return(1);

	{
	    ZLocation_t **tmp = ulogin_find (notice, 0);
	    loc = tmp ? *tmp : 0;
	}
	if (!loc) {
#if 0
		zdbug((LOG_DEBUG,"ul_hide: not here"));
#endif
		return(1);
	}
	for (idx = 0; locations[idx] != loc; idx++)
	  ;

	while ((idx < num_locs) &&
	       locations[idx]->zlt_user != loc2->zlt_user) {

		/* change exposure and owner for each loc on that host */
		if (!strcasecmp(locations[idx]->zlt_machine.value(), loc2->zlt_machine.value())) {
			notfound = 0;
			locations[idx]->zlt_exposure = exposure;
			locations[idx]->zlt_port = notice->z_port;
			/* change time for the specific loc */
			if (locations[idx]->zlt_tty == loc2->zlt_tty) {
				locations[idx]->zlt_time = loc2->zlt_time;
			}
		}
		idx++;
	}
	delete loc2;

	return(notfound);
}


static void
ulogin_locate(ZNotice_t *notice, sockaddr_in *who, int auth)
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
ulogin_marshal_locs(ZNotice_t *notice, register int *found, int auth)
{
	ZLocation_t **matches = (ZLocation_t **) 0;
	ZLocation_t *loc;
	char **answer;
	register int i = 0;

	*found = 0;			/* # of matches */

	{
	    ZLocation_t **tmp = ulogin_find (notice, 0);
	    loc = tmp ? *tmp : 0;
	}
	if (!loc)
		/* not here anywhere */
		return((char **)0);

	for (i = 0; locations[i] != loc; i++)
	    ;
	ZString inst (notice->z_class_inst);
	while (i < num_locs && inst == locations[i]->zlt_user) {
		/* these locations match */
#if 0
		zdbug((LOG_DEBUG,"match %s", locations[i]->zlt_user.value()));
#endif
		switch (locations[i]->zlt_exposure) {
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
			matches[0] = locations[i];
			(*found)++;
		} else {
			if ((matches = (ZLocation_t **) realloc((caddr_t) matches, (unsigned) ++(*found) * sizeof(ZLocation_t *))) == (ZLocation_t **) 0) {
				syslog(LOG_ERR, "ulog_loc: realloc no mem");
				*found = 0;
				break;	/* from the while */
			}
			matches[*found - 1] = locations[i];
		}
		i++;
	}

	/* OK, now we have a list of user@host's to return to the client
	   in matches */


#ifdef DEBUG
	if (zdebug) {
		for (i = 0; i < *found ; i++)
			zdbug((LOG_DEBUG,"found %s",
			       matches[i]->zlt_user.value()));
	}
#endif

	/* coalesce the location information into a list of char *'s */
	if ((answer = (char **)xmalloc((*found) * NUM_FIELDS * sizeof(char *))) == (char **) 0) {
		syslog(LOG_ERR, "zloc no mem(answer)");
		*found = 0;
	} else
		for (i = 0; i < *found ; i++) {
			answer[i*NUM_FIELDS] = (char *) matches[i]->zlt_machine.value ();
			answer[i*NUM_FIELDS + 1] = (char *) matches[i]->zlt_time.value();
			answer[i*NUM_FIELDS + 2] = (char *) matches[i]->zlt_tty.value();
		}

	if (matches)
	    xfree(matches);
	return(answer);
}

void
uloc_dump_locs(register FILE *fp)
{
	register int i;
	char buf[BUFSIZ*3];
	static char *bufp;
	static const char *cp;

	/* delay using stdio so that we can run FAST! */
	for (i = 0; i < num_locs; i++) {
		bufp = buf;
#define cpy(str) do{cp=(str);while(*cp){*bufp++=*cp++;}}while(0)
		cpy (locations[i]->zlt_user.value ());
		*bufp++ = '/';
		cpy (locations[i]->zlt_machine.value());
		*bufp++ = '/';
		cpy (locations[i]->zlt_time.value());
		*bufp++ = '/';
		cpy (locations[i]->zlt_tty.value());
		switch (locations[i]->zlt_exposure) {
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
			sprintf (bufp, "/? %d ?/", locations[i]->zlt_exposure);
			while (*bufp)
			    bufp++;
			break;
		}
		cpy (inet_ntoa (locations[i]->zlt_addr));
		*bufp++ = '/';
		sprintf(bufp, "%d", ntohs(locations[i]->zlt_port));
		fputs(buf, fp);
		(void) putc('\n', fp);
#undef cpy
	}
	return;
}
