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
#include "zserver.h"
#include <sys/socket.h>

#ifndef lint
#ifndef SABER
static const char rcsid_uloc_c[] =
"$Id$";
#endif /* SABER */
#endif /* lint */

/*
 * The user locator functions.
 *
 * External functions:
 *
 * void ulocate_dispatch(notice, auth, who, server)
 *	ZNotice_t *notice;
 *	int auth;
 *	struct sockaddr_in *who;
 *	Server *server;
 *
 * void ulogin_dispatch(notice, auth, who, server)
 *	ZNotice_t *notice;
 *	int auth;
 *	struct sockaddr_in *who;
 *	Server *server;
 *
 * void uloc_hflush(addr)
 *	struct in_addr *addr;
 *
 * void uloc_flush_client(sin)
 *	struct sockaddr_in *sin;
 *
 * Code_t uloc_send_locations()
 *
 * void uloc_dump_locs(fp)
 *	FILE *fp;
 */

/*
 * The user locator.
 * We maintain an array of Location sorted by user (so we can do
 * binary searches), growing and shrinking it as necessary.
 */

/* WARNING: make sure this is the same as the number of strings you */
/* plan to hand back to the user in response to a locate request, */
/* else you will lose.  See ulogin_locate() and uloc_send_locations() */  
#define	NUM_FIELDS	3

typedef enum _Exposure_type {
    NONE,
    OPSTAFF_VIS,
    REALM_VIS,
    REALM_ANN,
    NET_VIS,
    NET_ANN
} Exposure_type;

typedef struct _Location {
    String *user;
    String *machine;
    char *time;			/* in ctime format */
    String *tty;
    struct sockaddr_in addr;	/* IP address and port of location */
    Exposure_type exposure;
} Location;

#define NOLOC		1
#define QUIET		-1
#define UNAUTH		-2

static void ulogin_locate __P((ZNotice_t *notice, struct sockaddr_in *who,
			       int auth)),
ulogin_flush_user __P((ZNotice_t *notice));
static Location *ulogin_find __P((ZNotice_t *notice, int strict));
static int ulogin_setup __P((ZNotice_t *notice, Location *locs,
			     Exposure_type exposure, struct sockaddr_in *who)),
ulogin_add_user __P((ZNotice_t *notice, Exposure_type exposure,
		     struct sockaddr_in *who)),
ulogin_parse __P((ZNotice_t *notice, Location *locs)),
ulogin_expose_user __P((ZNotice_t *notice, Exposure_type exposure));
static Exposure_type ulogin_remove_user __P((ZNotice_t *notice, int auth,
					     struct sockaddr_in *who,
					     int *err_return));
static void login_sendit __P((ZNotice_t *notice, int auth,
			      struct sockaddr_in *who, int external));
static char **ulogin_marshal_locs __P((ZNotice_t *notice, int *found,
				       int auth));

static int ul_equiv __P((Location *l1, Location *l2));

static void free_loc __P((Location *loc));
static void ulogin_locate_forward __P((ZNotice_t *notice,
				       struct sockaddr_in *who, Realm *realm));

static Location *locations = NULL; /* ptr to first in array */
static int num_locs = 0;	/* number in array */

/*
 * Dispatch a LOGIN notice.
 */

Code_t
ulogin_dispatch(notice, auth, who, server)
    ZNotice_t *notice;
    int auth;
    struct sockaddr_in *who;
    Server *server;
{
    Exposure_type retval;
    int err_ret;

#if 0
    zdbug((LOG_DEBUG,
	   "ulogin_dispatch: opc=%s from=%s/%d auth=%d who=%s/%d",
	   notice->z_opcode, notice->z_sender, ntohs (notice->z_port),
	   auth, inet_ntoa (who->sin_addr), ntohs (who->sin_port)));
#endif

    if (strcmp(notice->z_opcode, LOGIN_USER_LOGOUT) == 0) {
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
		return ZERR_NONE;
	    } else if (err_ret == NOLOC) {
		if (server == me_server)
		    clt_ack(notice, who, NOT_FOUND);
		return ZERR_NONE;
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
	    if (server == me_server)
		sendit(notice, 1, who, 0);
	    break;
	  case NET_ANN:
	    /* currently no distinction between these.
	       just announce */
	    /* we assume that if this user is at a certain
	       IP address, we can trust the logout to be
	       authentic.  ulogin_remove_user checks the
	       ip addrs */
	    if (server == me_server)
		sendit(notice, 1, who, 1);
	    break;
	  default:
	    syslog(LOG_ERR,"bogus location exposure %d/%s",
		   (int) retval, notice->z_sender);
	    break;
	}
	if (server == me_server) /* tell the other servers */
	    server_forward(notice, auth, who);
	return ZERR_NONE;
    }
    if (!bdumping && 
	(!auth || strcmp(notice->z_sender, notice->z_class_inst) != 0))  {
#if 1
	zdbug((LOG_DEBUG,"unauthentic ulogin: %d %s %s", auth,
	       notice->z_sender, notice->z_class_inst));
#endif
	if (server == me_server)
	    clt_ack(notice, who, AUTH_FAILED);
	return ZERR_NONE;
    }
    if (strcmp(notice->z_opcode, LOGIN_USER_FLUSH) == 0) {
#if 0
	zdbug((LOG_DEBUG, "user flush"));
#endif
	ulogin_flush_user(notice);
	if (server == me_server)
	    ack(notice, who);
    } else if (strcmp(notice->z_opcode, EXPOSE_NONE) == 0) {
#if 0
	zdbug((LOG_DEBUG,"no expose"));
#endif
	ulogin_remove_user(notice, auth, who, &err_ret);
	if (err_ret == UNAUTH) {
#if 0
	    zdbug((LOG_DEBUG, "unauth noexpose: %s/%d",
		   inet_ntoa(who->sin_addr), ntohs(notice->z_port)));
#endif
	    if (server == me_server)
		clt_ack(notice, who, AUTH_FAILED);
	    return ZERR_NONE;
	} else if (err_ret == NOLOC) {
	    if (server == me_server)
		clt_ack(notice, who, NOT_FOUND);
	    return ZERR_NONE;
	}
	if (server == me_server) {
	    ack(notice, who);
	    server_forward(notice, auth, who);
	}
	return ZERR_NONE;
    } else if (strcmp(notice->z_opcode, EXPOSE_OPSTAFF) == 0) {
#if 0
	zdbug((LOG_DEBUG,"opstaff"));
#endif
	err_ret = ulogin_add_user(notice, OPSTAFF_VIS, who);
	if (server == me_server) {
	    if (err_ret)
		nack(notice, who);
	    else
		ack(notice, who);
	}
    } else if (strcmp(notice->z_opcode, EXPOSE_REALMVIS) == 0) {
#if 0
	zdbug((LOG_DEBUG,"realmvis"));
#endif
	err_ret = ulogin_add_user(notice, REALM_VIS, who);
	if (server == me_server) { /* realm vis is not broadcast,
				      so we ack it here */
	    if (err_ret)
		nack(notice, who);
	    else
		ack(notice, who);
	}
    } else if (!strcmp(notice->z_opcode, EXPOSE_REALMANN)) {
#if 0
	zdbug((LOG_DEBUG,"realmann"));
#endif
	err_ret = ulogin_add_user(notice, REALM_ANN, who);
	if (server == me_server) { /* announce to the realm */
	    if (err_ret)
		nack(notice, who);
	    else
		login_sendit(notice, auth, who, 0);
	}
    } else if (!strcmp(notice->z_opcode, EXPOSE_NETVIS)) {
#if 0
	zdbug((LOG_DEBUG,"netvis"));
#endif
	err_ret = ulogin_add_user(notice, NET_VIS, who);
	if (server == me_server) { /* announce to the realm */
	    if (err_ret)
		nack(notice, who);
	    else
		login_sendit(notice, auth, who, 0);
	}
    } else if (!strcmp(notice->z_opcode, EXPOSE_NETANN)) {
#if 0
	zdbug((LOG_DEBUG,"netann"));
#endif
	err_ret = ulogin_add_user(notice, NET_ANN, who);
	if (server == me_server) { /* tell the world */
	    if (err_ret)
		nack(notice, who);
	    else
		login_sendit(notice, auth, who, 1);
	}
    } else {
	syslog(LOG_ERR, "unknown ulog opcode %s", notice->z_opcode);
	if (server == me_server)
	    nack(notice, who);
	return ZERR_NONE;
    }
    if (server == me_server)
	server_forward(notice, auth, who);
    return ZERR_NONE;
}

static void
login_sendit(notice, auth, who, external)
    ZNotice_t *notice;
    int auth;
    struct sockaddr_in *who;
    int external;
{
    ZNotice_t log_notice;

    /* we must copy the notice struct here because we need the original
       for forwarding.  We needn't copy the private data of the notice,
       since that isn't modified by sendit and its subroutines. */

    log_notice = *notice;

    log_notice.z_opcode = LOGIN_USER_LOGIN;
    sendit(&log_notice, auth, who, external);
}


/*
 * Dispatch a LOCATE notice.
 */
Code_t
ulocate_dispatch(notice, auth, who, server)
    ZNotice_t *notice;
    int auth;
    struct sockaddr_in *who;
    Server *server;
{
    char *cp;
    Realm *realm;

#if 0
    zdbug((LOG_DEBUG,"ulocate_disp"));
#endif

#if 0				/* Now we support unauthentic locate for net-visible.  */
    if (!auth) {
#if 0
	zdbug((LOG_DEBUG,"unauthentic ulocate"));
#endif
	if (server == me_server)
	    clt_ack(notice, who, AUTH_FAILED);
	return ZERR_NONE;
    }
#endif
    if (!strcmp(notice->z_opcode, LOCATE_LOCATE)) {
#if 0
	zdbug((LOG_DEBUG,"locate"));
#endif
	/* we are talking to a current-rev client; send an ack */
	ack(notice, who);
	cp = strchr(notice->z_class_inst, '@');
	if (cp && (realm = realm_get_realm_by_name(cp + 1)))
	    ulogin_locate_forward(notice, who, realm);
	else
	    ulogin_locate(notice, who, auth);
	return ZERR_NONE;
    } else {
	syslog(LOG_ERR, "unknown uloc opcode %s", notice->z_opcode);
	if (server == me_server)
	    nack(notice, who);
	return ZERR_NONE;
    }
#if 0
    if (server == me_server) {
	server_forward(notice, auth, who);
	ack(notice, who);
    }
    return ZERR_NONE;
#endif
}

/*
 * Flush all locations at the address.
 */

void
uloc_hflush(addr)
    struct in_addr *addr;
{
    Location *loc;
    int i = 0, new_num = 0;

    if (num_locs == 0)
	return;			/* none to flush */

    /* slightly inefficient, assume the worst, and allocate enough space */
    loc = (Location *) malloc(num_locs *sizeof(Location));
    if (!loc) {
	syslog(LOG_CRIT, "uloc_flush alloc");
	abort();
    }

    /* copy entries which don't match */
    while (i < num_locs) {
	if (locations[i].addr.sin_addr.s_addr != addr->s_addr) {
	    loc[new_num++] = locations[i];
	} else {
#if 0
	    if (zdebug)
		syslog(LOG_DEBUG, "uloc hflushing %s/%s/%s",
		       locations[i].user->string,
		       locations[i].machine->string,
		       locations[i].tty->string);
#endif
	    free_loc(&locations[i]);
	}
	i++;
    }

    free(locations);
    locations = NULL;

    if (!new_num) {
#if 0
	zdbug((LOG_DEBUG,"no more locs"));
#endif
	free(loc);
	loc = NULL;
	num_locs = new_num;

	return;
    }
    locations = loc;
    num_locs = new_num;

    /* all done */
    return;
}

void
uloc_flush_client(sin)
    struct sockaddr_in *sin;
{
    Location *loc;
    int i = 0, new_num = 0;

    if (num_locs == 0)
	return;			/* none to flush */

    /* slightly inefficient, assume the worst, and allocate enough space */
    loc = (Location *) malloc(num_locs *sizeof(Location));
    if (!loc) {
	syslog(LOG_CRIT, "uloc_flush_clt alloc");
	abort();
    }

    /* copy entries which don't match */
    while (i < num_locs) {
	if ((locations[i].addr.sin_addr.s_addr != sin->sin_addr.s_addr)
	    || (locations[i].addr.sin_port != sin->sin_port)) {
	    loc[new_num++] = locations[i];
	} else {
#if 0
	    if (zdebug)
		syslog(LOG_DEBUG, "uloc cflushing %s/%s/%s",
		       locations[i].user->string,
		       locations[i].machine->string,
		       locations[i].tty->string);
#endif
	    free_loc(&locations[i]);
	}
	i++;
    }

    free(locations);
    locations = NULL;

    if (!new_num) {
#if 0
	zdbug((LOG_DEBUG,"no more locs"));
#endif
	free(loc);
	loc = NULL;
	num_locs = new_num;

	return;
    }
    locations = loc;
    num_locs = new_num;

#ifdef DEBUG
    if (zdebug) {
	int i;

	for (i = 0; i < num_locs; i++) {
	    syslog(LOG_DEBUG, "%s/%d", locations[i].user->string,
		   (int) locations[i].exposure);
	}
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
uloc_send_locations()
{
    Location *loc;
    int i;
    char *lyst[NUM_FIELDS];
    char *exposure_level;
    Code_t retval;

    for (i = 0, loc = locations; i < num_locs; i++, loc++) {
	lyst[0] = (char *) loc->machine->string;
	lyst[1] = (char *) loc->time;
	lyst[2] = (char *) loc->tty->string;

	switch (loc->exposure) {
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
		   loc->user->string, (int) loc->exposure);
	    break;
	}
	retval = bdump_send_list_tcp(ACKED, &loc->addr, LOGIN_CLASS,
				     loc->user->string, exposure_level, myname,
				     "", lyst, NUM_FIELDS);
	if (retval != ZERR_NONE) {
	    syslog(LOG_ERR, "uloc_send_locs: %s", error_message(retval));
	    return(retval);
	}
    }
    return ZERR_NONE;
}

/*
 * Add the user to the internal table of locations.
 */

static int
ulogin_add_user(notice, exposure, who)
    ZNotice_t *notice;
    Exposure_type exposure;
    struct sockaddr_in *who;
{
    Location *oldlocs, newloc;
    int i;

    if ((oldlocs = ulogin_find(notice,1)) != NULL) {
#if 0
	zdbug((LOG_DEBUG,"ul_add: already here"));
#endif
	ulogin_expose_user(notice, exposure);
	return 0;
    }

    oldlocs = locations;

    locations = (Location *) malloc((num_locs + 1) * sizeof(Location));
    if (!locations) {
	syslog(LOG_ERR, "zloc mem alloc");
	locations = oldlocs;
	return 1;
    }

    if (num_locs == 0) {	/* first one */
	if (ulogin_setup(notice, locations, exposure, who)) {
	    free(locations);
	    locations = NULL;
	    return 1;
	}
	num_locs = 1;
	goto dprnt;
    }

    /* not the first one, insert him */

    if (ulogin_setup(notice, &newloc, exposure, who)) {
	free(locations);
	locations = oldlocs;
	return 1;
    }
    num_locs++;

    /* copy old locs */
    i = 0;
    while ((i < num_locs-1) &&
	   (comp_string(oldlocs[i].user,newloc.user) < 0)) {
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
	free(oldlocs);

  dprnt:
#if 0
    if (zdebug) {
	int i;
	syslog(LOG_DEBUG, "ul_add: New Locations (%d)", num_locs);
	for (i = 0; i < num_locs; i++) {
	    syslog(LOG_DEBUG, "%s/%s/%s/%d", locations[i].user->string,
		   locations[i].machine->string, locations[i].tty->string,
		   (int) locations[i].exposure);
	}
    }
#endif
    return 0;
}

/*
 * Set up the location locs with the information in the notice.
 */ 

static int
ulogin_setup(notice, locs, exposure, who)
    ZNotice_t *notice;
    Location *locs;
    Exposure_type exposure;
    struct sockaddr_in *who;
{
    if (ulogin_parse(notice, locs))
	return 1;

    locs->exposure = exposure;
    locs->addr.sin_family = AF_INET;
    locs->addr.sin_addr.s_addr = who->sin_addr.s_addr;
    locs->addr.sin_port = notice->z_port;
    return(0);
}

/*
 * Parse the location information in the notice, and fill it into *locs
 */

static int
ulogin_parse(notice, locs)
    ZNotice_t *notice;
    Location *locs;
{
    char *cp, *base;
    int nulls = 0;

    if (!notice->z_message_len) {
	syslog(LOG_ERR, "short ulogin");
	return 1;
    }

    base = notice->z_message;
    for (cp = base; cp < base + notice->z_message_len; cp++) {
	if (!*cp)
	    nulls++;
    }
    if (nulls < 3) {
	syslog(LOG_ERR, "zloc bad format from user %s (only %d fields)",
	       notice->z_sender, nulls);
	return 1;
    }

    locs->user = make_string(notice->z_class_inst,0);

    cp = base;
    locs->machine = make_string(cp,0);
#if 0
    zdbug((LOG_DEBUG, "ul_parse: mach %s", cp));
#endif

    cp += (strlen(cp) + 1);
    locs->time = strsave(cp);
#if 0
    zdbug((LOG_DEBUG, "ul_parse: time %s", cp));
#endif

    /* This field might not be null-terminated */
    cp += (strlen(cp) + 1);
    locs->tty = make_string(cp, 0);
#if 0
    zdbug((LOG_DEBUG, "ul_parse: tty %s", locs->tty->string));
#endif

    return 0;
}	

/*
 * Find the username specified in notice->z_class_inst.
 * If strict, make sure the locations in notice and the table match.
 * Otherwise return a pointer to the first instance of this user@realm
 * in the table.
 */

static Location *
ulogin_find(notice, strict)
    ZNotice_t *notice;
    int strict;
{
    int i, rlo, rhi;
    Location tmploc;
    int compar;
    String *inst;

    if (!locations)
	return(NULL);

    inst = make_string(notice->z_class_inst, 0);

    /* i is the current loc we are checking */
    /* rlo is the lowest we will still check, rhi is the highest we will
       still check */

    i = num_locs >> 1;		/* start in the middle */
    rlo = 0;
    rhi = num_locs - 1;		/* first index is 0 */

    while ((compar = comp_string(locations[i].user, inst)) != 0) {
#if 0
	zdbug ((LOG_DEBUG, "ulogin_find: comparing %s %s %s %d %d",
		notice->z_class_inst, locations[i].user->string,
		locations[i].tty->string, rlo, rhi));
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
	    free_string(inst);
	    return 0;
	}
	i = (rhi + rlo) >> 1;	/* split the diff */
    }
#if 0
    zdbug((LOG_DEBUG, "ul_find: %s found at loc %d",
	   inst->string, i));
#endif
    if (strict && ulogin_parse(notice, &tmploc)) {
#if 1
	zdbug((LOG_DEBUG,"ul_find bad fmt"));
#endif
	free_string(inst);
	return 0;
    }
    /* back up to the first of this guy */
    while (i > 0 && (locations[i-1].user == inst)) {
	i--;
#if 0
	zdbug((LOG_DEBUG, "ulogin_find: backing up: %s %d %s %s", inst->string,
	       i, locations[i].user->string, locations[i].tty->string));
#endif
    }
    if (strict) {
	while (i < num_locs && !ul_equiv(&tmploc, &locations[i])
	       && (locations[i].user == inst))
	    i++;
    }
    if (strict)
	free_loc(&tmploc);
    if (i == num_locs || locations[i].user != inst) {
#if 1
	zdbug((LOG_DEBUG,"ul_find final match loss"));
#endif
	free_string(inst);
	return 0;
    }
    free_string(inst);
    return &locations[i];
}

static int
ul_equiv(l1, l2)
    Location *l1, *l2;
{
    if (l1->machine != l2->machine)
	return 0;
    if (l1->tty != l2->tty)
	return 0;
    return 1;
}

/*
 * remove the user specified in notice from the internal table
 */

static Exposure_type
ulogin_remove_user(notice, auth, who, err_return)
    ZNotice_t *notice;
    int auth;
    struct sockaddr_in *who;
    int *err_return;
{
    Location *new_locs, *loc;
    int i = 0;
    Exposure_type quiet;

    *err_return = 0;
    loc = ulogin_find(notice, 1);
    if (!loc) {
#if 0
	zdbug((LOG_DEBUG,"ul_rem: not here"));
#endif
	*err_return = NOLOC;
	return NONE;
    }

    /* if unauthentic, the sender MUST be the same IP addr that registered */
    if (!auth && loc->addr.sin_addr.s_addr != who->sin_addr.s_addr) {
	*err_return = UNAUTH;
	return NONE;
    }

    quiet = loc->exposure;

    if (--num_locs == 0) {	/* last one */
#if 0
	zdbug((LOG_DEBUG,"last loc"));
#endif
	free_loc(locations);
	free(locations);
	locations = NULL;
	return quiet;
    }

    new_locs = (Location *) malloc(num_locs * sizeof(Location));
    if (!new_locs) {
	syslog(LOG_CRIT, "ul_rem alloc");
	abort();
    }

    /* copy old entries */
    while (i < num_locs && &locations[i] < loc) {
	new_locs[i] = locations[i];
	i++;
    }

    /* free up this one */
    free_loc(&locations[i]);
    i++;			/* skip over this one */

    /* copy the rest */
    while (i <= num_locs) {
	new_locs[i - 1] = locations[i];
	i++;
    }

    free(locations);

    locations = new_locs;

#if defined(DEBUG) && 0
    if (zdebug) {
	int i;

	for (i = 0; i < num_locs; i++) {
	    syslog(LOG_DEBUG, "%s/%d", locations[i].user->string,
		   (int) locations[i].exposure);
	}
    }
#endif
    /* all done */
    return quiet;
}

/*
 * remove all locs of the user specified in notice from the internal table
 */

static void
ulogin_flush_user(notice)
    ZNotice_t *notice;
{
    Location *loc, *loc2;
    int i, j, num_match, num_left;

    i = num_match = num_left = 0;

    if (!(loc2 = ulogin_find(notice, 0))) {
#if 0
	zdbug((LOG_DEBUG,"ul_rem: not here"));
#endif
	return;
    }

    /* compute # locations left in the list, after loc2 (inclusive) */
    num_left = num_locs - (loc2 - locations);

    while (num_left &&
	   !strcasecmp(loc2[num_match].user->string,
		       notice->z_class_inst)) {
	/* as long as we keep matching, march up the list */
	num_match++;
	num_left--;
    }
    if (num_locs == num_match) { /* no other locations left */
#if 0
	zdbug((LOG_DEBUG,"last loc"));
#endif
	for (j = 0; j < num_match; j++)
	    free_loc(&locations[j]); /* free storage */
	free (locations);
	locations = NULL;
	num_locs = 0;
	return;
    }

    loc = (Location *) malloc((num_locs - num_match) * sizeof(Location));
    if (!loc) {
	syslog(LOG_CRIT, "ul_rem alloc");
	abort();
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

    free(locations);

    locations = loc;
    num_locs -= num_match;

#ifdef DEBUG
    if (zdebug) {
	int i;

	for (i = 0; i < num_locs; i++) {
	    syslog(LOG_DEBUG, "%s/%d", locations[i].user->string,
		   (int) locations[i].exposure);
	}
    }
#endif
}

/*
 * Set the user's exposure flag to exposure
 */

static int
ulogin_expose_user(notice, exposure)
    ZNotice_t *notice;
    Exposure_type exposure;
{
    Location *loc, loc2;
    int idx, notfound = 1;

#if 0
    zdbug((LOG_DEBUG,"ul_expose: %s type %d", notice->z_sender,
	   (int) exposure));
#endif

    loc = ulogin_find(notice, 0);
    if (!loc) {
#if 0
		zdbug((LOG_DEBUG,"ul_hide: not here"));
#endif
		return 1;
    }

    if (ulogin_parse(notice, &loc2))
	return 1;

    idx = loc -locations;

    while (idx < num_locs && locations[idx].user == loc2.user) {

	/* change exposure and owner for each loc on that host */
	if (locations[idx].machine == loc2.machine) {
	    notfound = 0;
	    locations[idx].exposure = exposure;
	    locations[idx].addr.sin_port = notice->z_port;
	    /* change time for the specific loc */
	    if (locations[idx].tty == loc2.tty) {
		free(locations[idx].time);
		locations[idx].time = strsave(loc2.time);
	    }
	}
	idx++;
    }

    free_loc(&loc2);
    return notfound;
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

    retval = ZSetDestAddr(&send_to_who);
    if (retval != ZERR_NONE) {
	syslog(LOG_WARNING, "ulogin_locate set addr: %s",
	       error_message(retval));
	if (answer)
	    free(answer);
	return;
    }

    notice->z_kind = ACKED;

    /* use xmit_frag() to send each piece of the notice */

    retval = ZSrvSendRawList(notice, answer, found * NUM_FIELDS, xmit_frag);
    if (retval != ZERR_NONE)
	syslog(LOG_WARNING, "ulog_locate xmit: %s", error_message(retval));
    if (answer)
	free(answer);
}

/*
 * Locate the user and collect the locations into an array.  Return the # of
 * locations in *found.
 */

static char **
ulogin_marshal_locs(notice, found, auth)
    ZNotice_t *notice;
    int *found;
    int auth;
{
    Location **matches = (Location **) 0;
    Location *loc;
    char **answer;
    int i = 0;
    String *inst;
    int local = sender_in_realm(notice);

    *found = 0;			/* # of matches */

    loc = ulogin_find(notice, 0);
    if (!loc)
	return(NULL);

    i = loc - locations;

    inst = make_string(notice->z_class_inst,0);
    while (i < num_locs && (inst == locations[i].user)) {
	/* these locations match */
#if 0
	zdbug((LOG_DEBUG,"match %s", locations[i].user->string));
#endif
	switch (locations[i].exposure) {
	  case OPSTAFF_VIS:
	    i++;
	    continue;
	  case REALM_VIS:
	  case REALM_ANN:
	    if (!local) {
		i++;
		continue;
	    }
	  case NET_VIS:
	  case NET_ANN:
	  default:
	    break;
	}
	if (!*found) {
	    matches = (Location **) malloc(sizeof(Location *));
	    if (!matches) {
		syslog(LOG_ERR, "ulog_loc: no mem");
		break;	/* from the while */
	    }
	    matches[0] = &locations[i];
	    (*found)++;
	} else {
	    matches = (Location **) realloc(matches,
					    ++(*found) * sizeof(Location *));
	    if (!matches) {
		syslog(LOG_ERR, "ulog_loc: realloc no mem");
		*found = 0;
		break;	/* from the while */
	    }
	    matches[*found - 1] = &locations[i];
	}
	i++;
    }
    free_string(inst);

    /* OK, now we have a list of user@host's to return to the client
       in matches */
	
	
#ifdef DEBUG
    if (zdebug) {
	for (i = 0; i < *found ; i++)
	    zdbug((LOG_DEBUG,"found %s",
		   matches[i]->user->string));
    }
#endif
	
    /* coalesce the location information into a list of char *'s */
    answer = (char **) malloc((*found) * NUM_FIELDS * sizeof(char *));
    if (!answer) {
	syslog(LOG_ERR, "zloc no mem(answer)");
	*found = 0;
    } else
	for (i = 0; i < *found ; i++) {
	    answer[i * NUM_FIELDS] = matches[i]->machine->string;
	    answer[i * NUM_FIELDS + 1] = matches[i]->time;
	    answer[i * NUM_FIELDS + 2] = matches[i]->tty->string;
	}
	
    if (matches)
	free(matches);
    return answer;
}

void
uloc_dump_locs(fp)
    FILE *fp;
{
    int i;

    for (i = 0; i < num_locs; i++) {
	fputs("'", fp);
	dump_quote(locations[i].user->string, fp);
	fputs("' '", fp);
	dump_quote(locations[i].machine->string, fp);
	fputs("' '", fp);
	dump_quote(locations[i].time, fp);
	fputs("' '", fp);
	dump_quote(locations[i].tty->string, fp);
	fputs("' ", fp);
	switch (locations[i].exposure) {
	  case OPSTAFF_VIS:
	    fputs("OPSTAFF", fp);
	    break;
	  case REALM_VIS:
	    fputs("RLM_VIS", fp);
	    break;
	  case REALM_ANN:
	    fputs("RLM_ANN", fp);
	    break;
	  case NET_VIS:
	    fputs("NET_VIS", fp);
	    break;
	  case NET_ANN:
	    fputs("NET_ANN", fp);
	    break;
	  default:
	    fprintf(fp, "? %d ?", locations[i].exposure);
	    break;
	}
	fprintf(fp, " %s/%d\n", inet_ntoa(locations[i].addr.sin_addr),
		ntohs(locations[i].addr.sin_port));
    }
}

static void
free_loc(loc)
    Location *loc;
{
    free_string(loc->user);
    free_string(loc->machine);
    free_string(loc->tty);
    free(loc->time);
    return;
}

static void
ulogin_locate_forward(notice, who, realm)
    ZNotice_t *notice;
    struct sockaddr_in *who;
    Realm *realm;
{
    ZNotice_t lnotice;

    lnotice = *notice;
    lnotice.z_opcode = REALM_REQ_LOCATE;
  
    realm_handoff(&lnotice, 1, who, realm, 0);
}

void
ulogin_realm_locate(notice, who, realm)
    ZNotice_t *notice;
    struct sockaddr_in *who;
    Realm *realm;
{
  char **answer;
  int found;
  Code_t retval;
  ZNotice_t lnotice;
  char *pack;
  int packlen;
  
#ifdef DEBUG
  if (zdebug)
    zdbug((LOG_DEBUG, "ulogin_realm_locate"));
#endif
  
  answer = ulogin_marshal_locs(notice, &found, 0/*AUTH*/);
  
  lnotice = *notice;
  lnotice.z_opcode = REALM_ANS_LOCATE;
  
  if ((retval = ZFormatRawNoticeList(&lnotice, answer, found * NUM_FIELDS, &pack, &packlen)) != ZERR_NONE) {
    syslog(LOG_WARNING, "ulog_rlm_loc format: %s",
           error_message(retval));
    
    if (answer)
      free(answer);
    return;
  }
  if (answer)
    free(answer);
  
  if ((retval = ZParseNotice(pack, packlen, &lnotice)) != ZERR_NONE) {
    syslog(LOG_WARNING, "subscr_rlm_sendit parse: %s",
           error_message(retval));
    free(pack);
    return;
  }
  
  realm_handoff(&lnotice, 1, who, realm, 0);
  free(pack);
  
  return;
}

void
ulogin_relay_locate(notice, who)
    ZNotice_t *notice;
    struct sockaddr_in *who;
{
  ZNotice_t lnotice;
  Code_t retval;
  struct sockaddr_in newwho;
  char *pack;
  int packlen;
  
  newwho.sin_addr.s_addr = notice->z_sender_addr.s_addr;
  newwho.sin_port = notice->z_port;
  newwho.sin_family = AF_INET;
  
  if ((retval = ZSetDestAddr(&newwho)) != ZERR_NONE) {
    syslog(LOG_WARNING, "uloc_relay_loc set addr: %s",
           error_message(retval));
    return;
  }
  
  lnotice = *notice;
  lnotice.z_opcode = LOCATE_LOCATE;
  lnotice.z_kind = ACKED;
  
  if ((retval = ZFormatRawNotice(&lnotice, &pack, &packlen)) != ZERR_NONE) {
    syslog(LOG_WARNING, "ulog_relay_loc format: %s",
           error_message(retval));
    return;
  }
  
  if ((retval = ZSendPacket(pack, packlen, 0)) != ZERR_NONE) {
    syslog(LOG_WARNING, "ulog_relay_loc xmit: %s",
           error_message(retval));
  }
  free(pack);
}

