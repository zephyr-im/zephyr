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
static char rcsid_uloc_c[] = "$Header$";
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
#ifdef OLD_COMPAT
#define	OLD_ZEPHYR_VERSION	"ZEPH0.0"
#define	LOGIN_QUIET_LOGIN	"QUIET_LOGIN"
#endif /* OLD_COMPAT */
#ifdef NEW_COMPAT
#define	NEW_OLD_ZEPHYR_VERSION	"ZEPH0.1"
#endif NEW_COMPAT
#if defined(OLD_COMPAT) || defined(NEW_COMPAT)
static void old_compat_ulogin_locate();
#endif /* OLD_COMPAT || NEW_COMPAT */

static void ulogin_locate(), ulogin_add_user(), ulogin_flush_user();
static ZLocation_t *ulogin_find();
static int ulogin_setup(), ulogin_parse(), ul_equiv(), ulogin_expose_user();
static exposure_type ulogin_remove_user();
static void login_sendit(), sense_logout(), free_loc();
static char **ulogin_marshal_locs();

static ZLocation_t *locations = NULLZLT; /* ptr to first in array */
static int num_locs = 0;		/* number in array */

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

	zdbug((LOG_DEBUG,"ulogin_disp"));

	host = hostm_find_host(&who->sin_addr);
	if (host && host->zh_locked)
		return(ZSRV_REQUEUE);

	if (!strcmp(notice->z_opcode, LOGIN_USER_LOGOUT)) {
		zdbug((LOG_DEBUG,"logout"));
		retval = ulogin_remove_user(notice, auth, who, &err_ret);
		switch (retval) {
		case NONE:
			if (err_ret == UNAUTH) {
				zdbug((LOG_DEBUG, "unauth logout: %s %d",
				       inet_ntoa(who->sin_addr),
				       ntohs(notice->z_port)));
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
	if (!auth) {
		zdbug((LOG_DEBUG,"unauthentic ulogin"));
		sense_logout(notice, who);
		if (server == me_server)
			clt_ack(notice, who, AUTH_FAILED);
		return(ZERR_NONE);
	}
#ifdef OLD_COMPAT
	if (!strcmp(notice->z_opcode, LOGIN_USER_LOGIN)) {
		zdbug((LOG_DEBUG, "old login"));
		/* map LOGIN's to realm-announced */
		ulogin_add_user(notice, REALM_ANN, who);
		if (server == me_server) /* announce to the realm */
			sendit(notice, auth, who);
	} else if (!strcmp(notice->z_opcode, LOGIN_QUIET_LOGIN)) {
		zdbug((LOG_DEBUG, "old quiet"));
		/* map LOGIN's to realm-announced */
		ulogin_add_user(notice, OPSTAFF_VIS, who);
		if (server == me_server) /* announce to the realm */
			ack(notice, who);
	} else
#endif /* OLD_COMPAT */
	if (!strcmp(notice->z_opcode, LOGIN_USER_FLUSH)) {
		zdbug((LOG_DEBUG, "user flush"));
		ulogin_flush_user(notice);
		if (server == me_server)
			ack(notice, who);
	} else if (!strcmp(notice->z_opcode, EXPOSE_NONE)) {
		zdbug((LOG_DEBUG,"no expose"));
		(void) ulogin_remove_user(notice, auth, who, &err_ret);
		if (err_ret == UNAUTH) {
			zdbug((LOG_DEBUG, "unauth noexpose: %s/%d",
			       inet_ntoa(who->sin_addr),
			       ntohs(notice->z_port)));
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
		zdbug((LOG_DEBUG,"opstaff"));
		ulogin_add_user(notice, OPSTAFF_VIS, who);
		if (server == me_server)
			ack(notice, who);
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
			login_sendit(notice, auth, who);
	} else if (!strcmp(notice->z_opcode, EXPOSE_NETVIS)) {
		zdbug((LOG_DEBUG,"netvis"));
		ulogin_add_user(notice, NET_VIS, who);
		if (server == me_server) /* announce to the realm */
			login_sendit(notice, auth, who);
	} else if (!strcmp(notice->z_opcode, EXPOSE_NETANN)) {
		zdbug((LOG_DEBUG,"netann"));
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


/*ARGSUSED*/
static void
sense_logout(notice, who)
ZNotice_t *notice;
struct sockaddr_in *who;
{
	ZNotice_t sense_notice;
	ZLocation_t *loc;
	struct sockaddr_in owner;
	char message[BUFSIZ];
	int retval, len;
	char *pkt;
	ZClient_t *client;

	(void) bzero((char *)&sense_notice, sizeof(sense_notice));
	/* XXX todo: have the messsage print the IP addr */
	/*
	  someone tried an unauthentic logout.  Try to send a message
	  to the person named in the message, warning them of this.
	  If there is nobody listening on that port, the retransmission
	  will eventually result in a flush of the location.
	 */

	   
	if (!(loc = ulogin_find(notice, 1)))
		return;

	/* fabricate an addr descriptor for him */
	owner = *who;
	owner.sin_addr.s_addr = loc->zlt_addr.s_addr;
	owner.sin_port = loc->zlt_port;

	sense_notice.z_kind = ACKED;
	sense_notice.z_port = loc->zlt_port;
	sense_notice.z_class = "MESSAGE";
	sense_notice.z_class_inst = "URGENT";
	sense_notice.z_opcode = "";
	sense_notice.z_sender = "Zephyr Server";
	sense_notice.z_recipient = loc->zlt_user;
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
ulocate_dispatch(notice, auth, who, server)
ZNotice_t *notice;
int auth;
struct sockaddr_in *who;
ZServerDesc_t *server;
{
	zdbug((LOG_DEBUG,"ulocate_disp"));

#ifdef OLD_COMPAT
	if (!strcmp(notice->z_version, OLD_ZEPHYR_VERSION) &&
	    !strcmp(notice->z_opcode, LOCATE_LOCATE)) {
		/* we support locates on the old version */
		zdbug((LOG_DEBUG,"old locate"));
		ulogin_locate(notice, who);
		/* does xmit and ack itself, so return */
		return(ZERR_NONE);
	}
#endif /* OLD_COMPAT */
	if (!auth) {
		zdbug((LOG_DEBUG,"unauthentic ulocate"));
		if (server == me_server)
			clt_ack(notice, who, AUTH_FAILED);
		return(ZERR_NONE);
	}
#ifdef OLD_COMPAT
	if (!strcmp(notice->z_version, OLD_ZEPHYR_VERSION)) {
		ZHostList_t *host = hostm_find_host(&who->sin_addr);
		if (host && host->zh_locked) /* process later if locked */
			return(ZSRV_REQUEUE);

		if (!strcmp(notice->z_opcode, LOCATE_HIDE)) {
			zdbug((LOG_DEBUG,"old hide"));
			if (ulogin_expose_user(notice, OPSTAFF_VIS)) {
				if (server == me_server)
					clt_ack(notice, who, NOT_FOUND);
				return(ZERR_NONE);
			}
		} else if (!strcmp(notice->z_opcode, LOCATE_UNHIDE)) {
			zdbug((LOG_DEBUG,"old unhide"));
			if (ulogin_expose_user(notice, REALM_VIS)) {
				if (server == me_server)
					clt_ack(notice, who, NOT_FOUND);
				return(ZERR_NONE);
			}
		}
	} else
#endif /* OLD_COMPAT */
	if (!strcmp(notice->z_opcode, LOCATE_LOCATE)) {
		zdbug((LOG_DEBUG,"locate"));
#if defined(NEW_COMPAT) || defined(OLD_COMPAT)
		if (strcmp(notice->z_version, NEW_OLD_ZEPHYR_VERSION) &&
		    strcmp(notice->z_version, OLD_ZEPHYR_VERSION))
#endif /* NEW_COMPAT || OLD_COMPAT */
		/* we are talking to a current-rev client; send an
		   acknowledgement-message */
			ack(notice, who);
		ulogin_locate(notice, who);
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
uloc_hflush(addr)
struct in_addr *addr;
{
	ZLocation_t *loc;
	register int i = 0, new_num = 0;
	int omask = sigblock(sigmask(SIGFPE)); /* don't do ascii dumps */

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
		else if (zdebug)
			syslog(LOG_DEBUG, "uloc hflushing %s/%s/%s",
			       locations[i].zlt_user,
			       locations[i].zlt_machine,
			       locations[i].zlt_tty);
		free_loc(&locations[i]);
		i++;
	}

	xfree(locations);

	if (!new_num) {
		zdbug((LOG_DEBUG,"no more locs"));
		xfree(loc);
		locations = NULLZLT;
		num_locs = new_num;
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
	int omask = sigblock(sigmask(SIGFPE)); /* don't do ascii dumps */

	/* slightly inefficient, assume the worst, and allocate enough space */
	if (!(loc = (ZLocation_t *) xmalloc(num_locs * sizeof(ZLocation_t)))) {
		syslog(LOG_CRIT, "uloc_flush_clt malloc");
		abort();
		/*NOTREACHED*/
	}

	/* copy entries which don't match */
	while (i < num_locs) {
		if ((locations[i].zlt_addr.s_addr != sin->sin_addr.s_addr)
		     || (locations[i].zlt_port != sin->sin_port))
			loc[new_num++] = locations[i];
		else if (zdebug)
			syslog(LOG_DEBUG, "uloc cflushing %s/%s/%s",
			       locations[i].zlt_user,
			       locations[i].zlt_machine,
			       locations[i].zlt_tty);
		free_loc(&locations[i]);
		i++;
	}

	xfree(locations);

	if (!new_num) {
		zdbug((LOG_DEBUG,"no more locs"));
		xfree(loc);
		locations = NULLZLT;
		num_locs = new_num;
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
		lyst[0] = loc->zlt_machine;
		lyst[1] = loc->zlt_time;
		lyst[2] = loc->zlt_tty;


#ifdef OLD_COMPAT
		if (!strcmp(vers, OLD_ZEPHYR_VERSION))
			/* the other server is using the old
			   protocol version; send old-style
			   location/login information */
			switch(loc->zlt_exposure) {
			case OPSTAFF_VIS:
				exposure_level = LOGIN_QUIET_LOGIN;
				break;
			case REALM_VIS:
			case REALM_ANN:
			case NET_VIS:
			case NET_ANN:
				exposure_level = LOGIN_USER_LOGIN;
				break;
			default:
				syslog(LOG_ERR,"broken location state %s/%d",
				       loc->zlt_user, (int) loc->zlt_exposure);
				break;
			}
		else
#endif /* OLD_COMPAT */
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
	int omask;

	zdbug((LOG_DEBUG,"ul_add: %s type %d", notice->z_sender,
	       (int) exposure));

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

	omask = sigblock(sigmask(SIGFPE)); /* don't do ascii dumps */
	if (num_locs == 0) {		/* first one */
		if (ulogin_setup(notice, locations, exposure, who)) {
			xfree(locations);
			locations = NULLZLT;
			(void) sigsetmask(omask);
			return;
		}
		num_locs = 1;
		(void) sigsetmask(omask);
#ifdef DEBUG
		goto dprnt;
#else
		return;
#endif DEBUG
	}

	/* not the first one, insert him */

	if (ulogin_setup(notice, &newloc, exposure, who)) {
		(void) sigsetmask(omask);
		return;
	}
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
	
	(void) sigsetmask(omask);
#ifdef DEBUG
 dprnt:
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
	if (!locs->zlt_user) {
		syslog(LOG_ERR, "zloc bad format");
		return(1);
	}
	locs->zlt_user = strsave(locs->zlt_user);
	if (!locs->zlt_machine) {
		syslog(LOG_ERR, "zloc bad format");
		xfree(locs->zlt_user);
		return(1);
	}
	locs->zlt_machine = strsave(locs->zlt_machine);
	if (!locs->zlt_tty) {
		syslog(LOG_ERR, "zloc bad format");
		xfree(locs->zlt_user);
		xfree(locs->zlt_machine);
		return(1);
	}
	locs->zlt_tty = strsave(locs->zlt_tty);
	if (!locs->zlt_time) {
		syslog(LOG_ERR, "zloc bad format");
		xfree(locs->zlt_user);
		xfree(locs->zlt_machine);
		xfree(locs->zlt_tty);
		return(1);
	}
	locs->zlt_time = strsave(locs->zlt_time);
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
register ZNotice_t *notice;
register ZLocation_t *locs;
{
	register char *cp, *base;

	if (!notice->z_message_len) {
		syslog(LOG_ERR, "short ulogin");
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

#ifdef OLD_COMPAT
	if (cp == base + notice->z_message_len) {
		/* no tty--for backwards compat, we allow this */
		zdbug((LOG_DEBUG, "no tty"));
		locs->zlt_tty = "";
	} else 
#endif OLD_COMPAT
	if (cp > base + notice->z_message_len) {
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
	exposure_type quiet;
	int omask;

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

	omask = sigblock(sigmask(SIGFPE)); /* don't let disk db dumps start */
	if (--num_locs == 0) {		/* last one */
		zdbug((LOG_DEBUG,"last loc"));
		xfree(locations);
		locations = NULLZLT;
		(void) sigsetmask(omask);
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

	(void) sigsetmask(omask);
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
	int omask;

	i = num_match = num_left = 0;

	if (!(loc2 = ulogin_find(notice, 0))) {
		zdbug((LOG_DEBUG,"ul_rem: not here"));
		return;
	}

	num_left = num_locs - (loc2 - locations);

	omask = sigblock(sigmask(SIGFPE)); /* don't let disk db dumps start */
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
		(void) sigsetmask(omask);
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

	for (j = 0; j < num_match; j++) {
	    free_loc(&locations[i]);
	    i++;			/* skip over the matches */
	}

	/* copy the rest */
	while (i <= num_locs) {
		loc[i - num_match] = locations[i];
		i++;
	}

	xfree(locations);

	locations = loc;

	(void) sigsetmask(omask);
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
	int idx, notfound = 1;

	zdbug((LOG_DEBUG,"ul_expose: %s type %d", notice->z_sender,
	       (int) exposure));

	if (ulogin_parse(notice, &loc2))
		return(1);

	if (!(loc = ulogin_find(notice, 0))) {
		zdbug((LOG_DEBUG,"ul_hide: not here"));
		return(1);
	}
	idx = loc - locations;

	while ((idx < num_locs) &&
	       !strcmp(locations[idx].zlt_user, loc2.zlt_user)) {

		/* change exposure and owner for each loc on that host */
		if (!strcmp(locations[idx].zlt_machine, loc2.zlt_machine)) {
			notfound = 0;
			locations[idx].zlt_exposure = exposure;
			locations[idx].zlt_port = notice->z_port;
			/* change time for the specific loc */
			if (!strcmp(locations[idx].zlt_tty, loc2.zlt_tty)) {
				xfree(locations[idx].zlt_time);
				locations[idx].zlt_time =
					strsave(loc2.zlt_time);
			}
		}
		idx++;
	}

	return(notfound);
}


static void
ulogin_locate(notice, who)
ZNotice_t *notice;
struct sockaddr_in *who;
{
	char **answer;
	int found;
	Code_t retval;
	struct sockaddr_in send_to_who;

#if defined(NEW_COMPAT) || defined(OLD_COMPAT)
	if (!strcmp(notice->z_version, NEW_OLD_ZEPHYR_VERSION) ||
	    !strcmp(notice->z_version, OLD_ZEPHYR_VERSION)) {
		/* we are talking to a new old client; use the new-old-style
		   acknowledgement-message */
		old_compat_ulogin_locate(notice, who);
		return;
	}
#endif /* NEW_COMPAT || OLD_COMPAT */
	answer = ulogin_marshal_locs(notice, &found);

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
ulogin_marshal_locs(notice, found)
ZNotice_t *notice;
register int *found;
{
	ZLocation_t **matches = (ZLocation_t **) 0;
	ZLocation_t *loc;
	char **answer;
	register int i = 0;

	*found = 0;			/* # of matches */

	if (!(loc = ulogin_find(notice, 0)))
		/* not here anywhere */
		return((char **)0);

	i = loc - locations;
	while ((i < num_locs) &&
	       !strcmp(notice->z_class_inst, locations[i].zlt_user)) {
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

	/* OK, now we have a list of user@host's to return to the client
	   in matches */



#ifdef DEBUG
	if (zdebug) {
		for (i = 0; i < *found ; i++)
			zdbug((LOG_DEBUG,"found %s", matches[i]->zlt_user));
	}
#endif DEBUG

	/* coalesce the location information into a list of char *'s */
	if ((answer = (char **)xmalloc((*found) * NUM_FIELDS * sizeof(char *))) == (char **) 0) {
		syslog(LOG_ERR, "zloc no mem(answer)");
		*found = 0;
	} else
		for (i = 0; i < *found ; i++) {
			answer[i*NUM_FIELDS] = matches[i]->zlt_machine;
			answer[i*NUM_FIELDS + 1] = matches[i]->zlt_time;
			answer[i*NUM_FIELDS + 2] = matches[i]->zlt_tty;
		}

	if (matches)
	    xfree(matches);
	return(answer);
}

#if defined(OLD_COMPAT) || defined(NEW_COMPAT)
static void
old_compat_ulogin_locate(notice, who)
ZNotice_t *notice;
struct sockaddr_in *who;
{
	char **answer;
	int found;
	int packlen;
	ZPacket_t reppacket;
	ZNotice_t reply;
	Code_t retval;

	answer = ulogin_marshal_locs(notice, &found);

	reply = *notice;
	reply.z_kind = SERVACK;

	while ((retval = ZFormatSmallRawNoticeList(&reply,
					      answer,
					      found * NUM_FIELDS,
					      reppacket,
					      &packlen)) == ZERR_PKTLEN)
		found--;

	if (retval != ZERR_NONE) {
		syslog(LOG_ERR, "old_ulog_locate format: %s",
		       error_message(retval));
		if (answer)
		    xfree(answer);
		return;
	}
	if ((retval = ZSetDestAddr(who)) != ZERR_NONE) {
		syslog(LOG_WARNING, "old_ulog_locate set addr: %s",
		       error_message(retval));
		if (answer)
		    xfree(answer);
		return;
	}
	if ((retval = ZSendPacket(reppacket, packlen, 0)) != ZERR_NONE) {
		syslog(LOG_WARNING, "old_ulog_locate xmit: %s",
		       error_message(retval));
		if (answer)
		    xfree(answer);
		return;
	}
	zdbug((LOG_DEBUG,"ulog_loc acked"));
	if (answer)
	    xfree(answer);
	return;
}
#endif /* OLD_COMPAT || NEW_COMPAT */

void
uloc_dump_locs(fp)
register FILE *fp;
{
	register int i;

	/* avoid using printf so that we can run FAST! */
	for (i = 0; i < num_locs; i++) {
		fputs(locations[i].zlt_user, fp);
		fputs("/", fp);
		fputs(locations[i].zlt_machine, fp);
		fputs("/",fp);
		fputs(locations[i].zlt_time, fp);
		fputs("/", fp);
		fputs(locations[i].zlt_tty, fp);
		switch (locations[i].zlt_exposure) {
		case OPSTAFF_VIS:
			fputs("/OPSTAFF/", fp);
			break;
		case REALM_VIS:
			fputs("/RLM_VIS/", fp);
			break;
		case REALM_ANN:
			fputs("/RLM_ANN/", fp);
			break;
		case NET_VIS:
			fputs("/NET_VIS/", fp);
			break;
		case NET_ANN:
			fputs("/NET_ANN/", fp);
			break;
		default:
			fprintf(fp, "/?? %d ??/", locations[i].zlt_exposure);
			break;
		}
		fputs(inet_ntoa(locations[i].zlt_addr), fp);
		fputs("/", fp);
		fprintf(fp, "%d", ntohs(locations[i].zlt_port));
		(void) putc('\n', fp);
	}
	return;
}

static void
free_loc(loc)
register ZLocation_t *loc;
{
    xfree(loc->zlt_user);
    xfree(loc->zlt_machine);
    xfree(loc->zlt_tty);
    xfree(loc->zlt_time);
    return;
}
