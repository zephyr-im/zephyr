/* This file is part of the Project Athena Zephyr Notification System.
 * It contains functions for dumping server state between servers.
 *
 *	Created by:	John T. Kohl
 *
 *	$Source$
 *	$Id$
 *	$Author$
 *
 *	Copyright (c) 1987,1988,1991 by the Massachusetts Institute of Technology.
 *	For copying and distribution information, see the file
 *	"mit-copyright.h". 
 */
 
#include <zephyr/mit-copyright.h>
 
#ifndef lint
#ifndef SABER
static char rcsid_bdump_c[] = "$Id$";
#endif /* SABER */
#endif /* lint */
 
#include "zserver.h"
#include <sys/socket.h>
#include <signal.h>
#include <sys/param.h>		/* for BSD */
 
/* inconsistent header files... */
#ifdef SignalIgnore
#undef SIG_IGN
#define SIG_IGN SignalIgnore
#undef SIG_DFL
#define SIG_DFL SignalDefault
#endif

/*
 * External functions are:
 *
 * void bdump_offer(who)
 *	strut sockaddr_in *who;
 *
 * void bdump_send()
 *
 * void bdump_get(notice, auth, who, server)
 *	ZNotice_t *notice;
 *	int auth;
 *	struct sockaddr_in *who;
 *	ZServerDesc_t *server;
 *
 * Code_t bdump_send_list_tcp(kind, port, class, inst, opcode,
 *			    sender, recip, lyst, num)
 *	ZNotice_Kind_t kind;
 *	u_short port;
 *	char *class, *inst, *opcode, *sender, *recip;
 *	char *lyst[];
 *	int num;
 */
 
#ifdef __STDC__
# define        P(s) s
#else
# define P(s) ()
#endif

static void close_bdump P((void* arg)),
    cleanup P((ZServerDesc_t *server, int omask));
static Code_t bdump_send_loop P((register ZServerDesc_t *server, char *vers)),
    bdump_ask_for P((char *inst)),
    bdump_recv_loop P((ZServerDesc_t *server));
static void bdump_get_v1 P((ZNotice_t *, int, struct sockaddr_in *,
			    ZServerDesc_t *));
static void bdump_get_v1a P((ZNotice_t *notice, int auth,
			    struct sockaddr_in *who, ZServerDesc_t *server));
static Code_t get_packet P((caddr_t packet, int len, int *retlen));
static Code_t extract_sin P((ZNotice_t *notice, struct sockaddr_in *target));
static Code_t send_done P((void));
static Code_t send_list P((ZNotice_Kind_t kind, int port, char *class_name,
			char *inst, char *opcode, char *sender, char *recip,
			char **lyst, int num));
static Code_t send_host_register P((ZHostList_t *host));
static Code_t sbd_loop P((struct sockaddr_in *from));
static Code_t gbd_loop P((ZServerDesc_t *server));
static Code_t send_normal_tcp P((ZNotice_Kind_t kind, int port,
				 char *class_name,
				 char *inst, char *opcode, char *sender,
				 char *recip, char *message, int len));
static int net_read P((FILE *f, register char *buf, register int len));
static int net_write P((FILE *f, register char *buf, int len));
static int setup_file_pointers  P((void));
static void shutdown_file_pointers  P((void));

#ifdef KERBEROS
static int get_tgt P((void));
static long ticket_time;
static char my_realm[REALM_SZ];

#define TKTLIFETIME	96
#define tkt_lifetime(val) ((long) val * 5L * 60L)
#endif /* KERBEROS */

#undef P

static timer bdump_timer;
static int bdump_inited;
static int live_socket = -1;
static FILE *input, *output;
static struct sockaddr_in bdump_sin;
#ifdef notdef
static int cancel_outgoing_dump;
#endif

int bdumping;
extern char *bdump_version;
 
/*
 * Functions for performing a brain dump between servers.
 */
 
/*
 * offer the brain dump to another server
 */
 
void
bdump_offer(who)
     struct sockaddr_in *who;
{
	Code_t retval;
	char buf[512], *addr, *lyst[2];
#ifndef KERBEROS
	int bdump_port = IPPORT_RESERVED - 1;
#endif /* !KERBEROS */
#if 1
	zdbug((LOG_DEBUG, "bdump_offer"));
#endif
#ifdef KERBEROS
	/* 
	 * when using Kerberos server-server authentication, we can
	 * use any random local address 
	 */
	if ((bdump_socket = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		syslog(LOG_ERR,"bdump_offer: socket: %m");
		bdump_socket = -1;
		return;
	}
	bzero((caddr_t) &bdump_sin, sizeof(bdump_sin));
	/* a port field of 0 makes the UNIX
	   kernel choose an appropriate port/address pair */
 
	bdump_sin.sin_port = 0;
	bdump_sin.sin_addr = my_addr;
	bdump_sin.sin_family = AF_INET;
	if ((retval = bind(bdump_socket, (struct sockaddr *) &bdump_sin, sizeof(bdump_sin))) < 0) {
		syslog(LOG_ERR, "bdump_offer: bind: %m");
		(void) close(bdump_socket);
		bdump_socket = -1;
		return;
	}
	if (!bdump_sin.sin_port) {
		int len = sizeof(bdump_sin);
		if (getsockname(bdump_socket,
				(struct sockaddr *)&bdump_sin, &len)) {
			syslog(LOG_ERR, "bdump_offer: getsockname: %m");
			(void) close(bdump_socket);
			bdump_socket = -1;
			return;
		}
	}
#else /* !KERBEROS */
	/*
	 * when not using Kerberos, we can't use any old port, we use
	 * Internet reserved ports instead (rresvport)
	 */
	if ((bdump_socket = rresvport(&bdump_port)) < 0) {
		syslog(LOG_ERR,"bdump_offer: socket: %m");
		bdump_socket = -1;
		return;
	}
	bzero((caddr_t) &bdump_sin, sizeof(bdump_sin));
	bdump_sin.sin_port = htons((unsigned short)bdump_port);
	bdump_sin.sin_addr = my_addr;
	bdump_sin.sin_family = AF_INET;
 
#endif /* KERBEROS */
	(void) listen(bdump_socket, 1);
 
	bdump_timer = timer_set_rel(20L, close_bdump, (void *) 0);
	FD_SET(bdump_socket, &interesting);
	nfildes = max(bdump_socket, srv_socket) + 1;
 
 
	addr = inet_ntoa(bdump_sin.sin_addr);
	(void) sprintf(buf, "%d", ntohs(bdump_sin.sin_port));
	lyst[0] = addr;
	lyst[1] = buf;
 
	if ((retval = ZSetDestAddr(who)) != ZERR_NONE) {
		syslog(LOG_WARNING, "bdump_offer: ZSetDestAddr: %s",
		       error_message(retval));
		return;
	}
 
	/* myname is the hostname */
	/* the class instance is the version number, here it is */
	/* bdump_version, which is set in main */
	(void) send_list(ACKED, sock_sin.sin_port, ZEPHYR_ADMIN_CLASS,
			 bdump_version, ADMIN_BDUMP, myname, "", lyst, 2);
	
#if 1
	zdbug((LOG_DEBUG,"bdump_offer: address is %s/%d\n",
	       inet_ntoa(bdump_sin.sin_addr),
	       ntohs(bdump_sin.sin_port)));
#endif
	return;
}
 
/*
 * Accept a connection, and send the brain dump to the other server
 */
 
void
bdump_send(void)
{
	struct sockaddr_in from;
	ZServerDesc_t *server;
	Code_t retval;
	int fromlen = sizeof(from);
	int omask;
	int on = 1;
#ifdef _POSIX_SOURCE
	struct sigaction action;
    /* Set up sigaction structure */
    /* This is all done because the RS/6000 emulation of signal sets the */
    /* signal action back to the default action when the signal handler is */
    /* called, instead of leaving well enough alone.. */
#endif /* _POSIX_SOURCE */

#ifdef KERBEROS
	KTEXT_ST ticket;
	AUTH_DAT kdata;
#else
	unsigned short fromport;
#endif /* KERBEROS */
 
#if 1
	zdbug((LOG_DEBUG, "bdump_send"));
#endif
	/* accept the connection, and send the brain dump */
	if ((live_socket = accept(bdump_socket, (struct sockaddr *)&from,
				  &fromlen)) < 0) {
		syslog(LOG_ERR,"bdump_send: accept: %m");
		return;
	}
	if (setsockopt(live_socket, SOL_SOCKET, SO_KEEPALIVE, (char *)&on,
	    sizeof (on)) < 0)
		syslog(LOG_WARNING,
		       "bdump_send: setsockopt (SO_KEEPALIVE): %m");
 
#ifndef KERBEROS
	fromport = ntohs(from.sin_port);
#endif /* !KERBEROS */
 
	omask = sigblock(sigmask(SIGFPE)); /* don't let ascii dumps start */
 
#ifdef _POSIX_SOURCE
	action.sa_flags = 0;
	sigemptyset(&action.sa_mask);
	action.sa_handler = SIG_IGN;
	sigaction(SIGPIPE, &action, NULL);
#else
	(void) signal(SIGPIPE, SIG_IGN); /* so we can detect failures */
#endif /* _POSIX_SOURCE */
 
	from.sin_port = sock_sin.sin_port; /* we don't care what port
					    it came from, and we need to
					    fake out server_which_server() */
	server = server_which_server(&from);
	if (!server) {
		syslog(LOG_ERR, "bdump_send: unknown server?");
		server = limbo_server;
	}
#if 1
	zdbug((LOG_DEBUG, "bdump_send: connection from %s/%d",
	       inet_ntoa (from.sin_addr), ntohs (from.sin_port)));
#endif

#ifdef notdef
	if (bdumping) {
	    /* Already bdumping; punt one of the two.  If this is a
	       new host, punt this connection.  If it's one we're
	       already trying to talk to... arbitrary decision: The
	       connection with the listener at the lower IP address
	       will be punted.  */
	    if (!server->zs_dumping) {
		zdbug ((LOG_INFO,
"bdump_send: already dumping; breaking new bdump connection from %s",
			inet_ntoa (from.sin_addr)));
		(void) close (live_socket);
		return;
	    }
	    /* Should be safe now to get rid of listener socket.  */
	    (void) close (bdump_socket);
	    FD_CLR (bdump_socket, &interesting);
	    bdump_socket = -1;
	    timer_reset(bdump_timer);
	    if (ntohl (bdump_sin.sin_addr.s_addr) < ntohl (from.sin_addr.s_addr)) {
		/* My address is lower; punt incoming connection.  */
		(void) close (live_socket);
		return;
	    }
	    else
		cancel_outgoing_dump = 1;
	}
#endif

	bdumping = 1;
	server->zs_dumping = 1;

	if (bdump_socket >= 0) {
	    /* shut down the listening socket and the timer */
	    FD_CLR(bdump_socket, &interesting);
	    (void) close(bdump_socket);
	    nfildes = srv_socket + 1;
	    bdump_socket = -1;
	    timer_reset(bdump_timer);
	}
 
	/* Now begin the brain dump. */
 
#ifdef KERBEROS
	/* receive the authenticator */
	if ((retval = GetKerberosData(live_socket, from.sin_addr, &kdata,
				      "zephyr", ZEPHYR_SRVTAB)) != KSUCCESS) {
	  syslog(LOG_ERR, "bdump_send: getkdata: %s",
		 krb_err_txt[retval]);
	  cleanup(server, omask);
	  return;
	}
	if (strcmp(kdata.pname,"zephyr") || strcmp(kdata.pinst,"zephyr")) {
		syslog(LOG_ERR, "bdump_send: peer not zephyr: %s.%s@%s",
		       kdata.pname, kdata.pinst,kdata.prealm);
		cleanup(server, omask);
		return;
	}
	/* authenticate back */
	if (get_tgt()) {
		cleanup(server, omask);
		return;
	}
	if ((retval = SendKerberosData(live_socket, &ticket, "zephyr",
				      "zephyr"))) {
	  syslog(LOG_ERR,"bdump_send: SendKerberosData: %s",
		 error_message (retval));
	  cleanup(server, omask);
	  return;
	}
#else /* !KERBEROS */
	if ((fromport > IPPORT_RESERVED) ||
	    (fromport < (IPPORT_RESERVED / 2))) {
		syslog(LOG_ERR, "bdump_send: bad port from peer: %d",
		       fromport);
		cleanup(server, omask);
		return;
	}
#endif /* KERBEROS */

	if ((retval = setup_file_pointers())) {
	    syslog (LOG_WARNING, "bdump_send: can't set up file pointers: %s",
		    error_message (retval));
	    cleanup (server, omask);
	    return;
	}
	if ((retval = sbd_loop(&from)) != ZERR_NONE) {
		syslog(LOG_WARNING, "bdump_send: sbd_loop failed: %s",
		       error_message(retval));
		cleanup(server, omask);
		return;
	}
	if ((retval = gbd_loop(server)) != ZERR_NONE) {
	    syslog(LOG_WARNING, "bdump_send: gbd_loop failed: %s",
		   error_message(retval));
	    cleanup(server, omask);
	    return;
	}
#if 1
	zdbug((LOG_DEBUG, "bdump_send: finished"));
#endif
	if (server != limbo_server) {
	    /* set this guy to be up, and schedule a hello */
	    server->zs_state  = SERV_UP;
	    timer_reset(server->zs_timer);
	    server->zs_timer = timer_set_rel(0L, server_timo, (void *) server);
	}
#if 0
	zdbug((LOG_DEBUG,"cleanup sbd"));
#endif
	shutdown_file_pointers ();

#ifdef _POSIX_SOURCE
	action.sa_handler = SIG_DFL;
	sigaction(SIGPIPE, &action, NULL);
#else
	(void) signal(SIGPIPE, SIG_DFL);
#endif /* _POSIX_SOURCE */
	bdump_inited = 1;
	bdumping = 0;
	server->zs_dumping = 0;
#ifdef CONCURRENT
	/* Now that we are finished dumping, send all the queued packets */
	server_send_queue(server);
#endif /* CONCURRENT */
 
	(void) sigsetmask(omask);
	return;
}

/*ARGSUSED*/
static void
bdump_get_v1_guts (notice, auth, who, server)
     ZNotice_t *notice;
     int auth;
     struct sockaddr_in *who;
     ZServerDesc_t *server;
{
	struct sockaddr_in from;
	Code_t retval;
	int omask;
	int on = 1;
#ifdef _POSIX_SOURCE
	struct sigaction action;
#endif /* _POSIX_SOURCE */
#ifdef KERBEROS
	KTEXT_ST ticket;
	AUTH_DAT kdata;
#else /* !KERBEROS */
	int reserved_port = IPPORT_RESERVED - 1;
#endif /* KERBEROS */
    
	bdumping = 1;
	server->zs_dumping = 1;
 
#ifdef _POSIX_SOURCE
	action.sa_flags = 0;
	sigemptyset(&action.sa_mask);
	action.sa_handler = SIG_IGN;
	sigaction(SIGPIPE, &action, NULL);
#else
	(void) signal(SIGPIPE, SIG_IGN); /* so we can detect problems */
#endif /* _POSIX_SOURCE */
 
	if (bdump_socket >= 0) {
		/* We cannot go get a brain dump when someone may
		   potentially be connecting to us (if that other
		   server is the server to whom we are connecting,
		   we will deadlock. so we shut down the listening
		   socket and the timer */
	  FD_CLR(bdump_socket, &interesting);
	  (void) close(bdump_socket);
	  nfildes = srv_socket+1;
	  bdump_socket = -1;
	  timer_reset(bdump_timer);
	}

	if ((retval = extract_sin(notice, &from)) != ZERR_NONE) {
		syslog(LOG_ERR, "bdump_get: sin: %s", error_message(retval));
#ifdef _POSIX_SOURCE
		action.sa_handler = SIG_DFL;
		sigaction(SIGPIPE, &action, NULL);
#else
		(void) signal(SIGPIPE, SIG_DFL);
#endif /* _POSIX_SOURCE */
		bdumping = 0;
		server->zs_dumping = 0;
		return;
	}
	omask = sigblock(sigmask(SIGFPE)); /* don't let ascii dumps start */
#ifndef KERBEROS
	if (ntohs(from.sin_port) > IPPORT_RESERVED ||
	    ntohs(from.sin_port) < IPPORT_RESERVED / 2) {
		syslog(LOG_ERR, "bdump_get: port not reserved: %d",
		       ntohs(from.sin_port));
		cleanup(server, omask);
		return;
	}
	live_socket = rresvport(&reserved_port);
#else /* !KERBEROS */
	live_socket = socket(AF_INET, SOCK_STREAM, 0);
#endif /* KERBEROS */
	if (live_socket < 0) {
		syslog(LOG_ERR, "bdump_get: socket: %m");
		cleanup(server, omask);
		return;
	}
	if (connect(live_socket, (struct sockaddr *) &from, sizeof(from))) {
		syslog(LOG_ERR, "bdump_get: connect: %m");
		cleanup(server, omask);
		return;
	}
	if (setsockopt(live_socket, SOL_SOCKET, SO_KEEPALIVE, (char *)&on,
	    sizeof (on)) < 0)
		syslog(LOG_WARNING,
		       "bdump_get: setsockopt (SO_KEEPALIVE): %m");
#if 1
	zdbug((LOG_DEBUG, "bdump_get: connected"));
#endif
 
	/* Now begin the brain dump. */

#ifdef KERBEROS
	/* send an authenticator */
	if (get_tgt()) {
		cleanup(server, omask);
		return;
	}
	if ((retval = SendKerberosData(live_socket, &ticket, "zephyr",
				       "zephyr"))) {
		syslog(LOG_ERR,"bdump_get: %s",
		       error_message (retval));
		cleanup(server, omask);
		return;
	}
#if 1
	zdbug((LOG_DEBUG, "bdump_get: SendKerberosData ok"));
#endif
 
	/* get his authenticator */
	if ((retval = GetKerberosData(live_socket, from.sin_addr, &kdata, "zephyr",
				      ZEPHYR_SRVTAB)) != KSUCCESS) {
		syslog(LOG_ERR, "bdump_get getkdata: %s",krb_err_txt[retval]);
		cleanup(server, omask);
		return;
	}
	/* my_realm is filled in inside get_tgt() */
	if (strcmp(kdata.pname,"zephyr") || strcmp(kdata.pinst,"zephyr")
	    || strcmp(kdata.prealm, my_realm)) {
		syslog(LOG_ERR,
		       "bdump_get: peer not zephyr in lrealm: %s.%s@%s",
		       kdata.pname, kdata.pinst,kdata.prealm);
		cleanup(server, omask);
		return;
	}
#endif /* KERBEROS */
	if ((retval = setup_file_pointers())) {
	    syslog (LOG_WARNING, "bdump_get: can't set up file pointers: %s",
		    error_message (retval));
	    cleanup (server, omask);
	    return;
	}
	if ((retval = gbd_loop(server)) != ZERR_NONE) {
		syslog(LOG_WARNING, "bdump_get: gbd_loop failed: %s",
		       error_message(retval));
		cleanup(server, omask);
		return;
	}
#if 1
	zdbug((LOG_DEBUG,"bdump_get: gbdl ok"));
#endif
	if ((retval = sbd_loop(&from)) != ZERR_NONE) {
	    syslog(LOG_WARNING, "sbd_loop failed: %s",
		   error_message(retval));
	    cleanup(server, omask);
	    return;
	}
#if 1
	zdbug((LOG_DEBUG, "bdump_get: gbd finished"));
#endif
	/* set this guy to be up, and schedule a hello */
	server->zs_state = SERV_UP;
	timer_reset(server->zs_timer);
	server->zs_timer = timer_set_rel(0L, server_timo, (void *) server);

#if 1
	zdbug((LOG_DEBUG,"cleanup gbd"));
#endif
	shutdown_file_pointers ();
#ifdef _POSIX_SOURCE
	action.sa_handler = SIG_DFL;
	sigaction(SIGPIPE, &action, NULL);
#else
	(void) signal(SIGPIPE, SIG_DFL);
#endif
	bdump_inited = 1;
	bdumping = 0;
	server->zs_dumping = 0;
#ifdef CONCURRENT
	/* Now that we are finished dumping, send all the queued packets */
	server_send_queue(server);
#endif /* CONCURRENT */

	(void) sigsetmask(omask);
	return;
}
 
static void
#ifdef __STDC__
bdump_get_v1(ZNotice_t *notice, int auth, struct sockaddr_in *who,
	     ZServerDesc_t *server)
#else
bdump_get_v1(notice, auth, who, server)
     ZNotice_t *notice;
     int auth;
     struct sockaddr_in *who;
     ZServerDesc_t *server;
#endif
{
    if (bdump_socket >= 0) {
	/* We cannot go get a brain dump when someone may
	   potentially be connecting to us (if that other
	   server is the server to whom we are connecting,
	   we will deadlock. so we shut down the listening
	   socket and the timer */
	FD_CLR(bdump_socket, &interesting);
	(void) close(bdump_socket);
	nfildes = srv_socket + 1;
	bdump_socket = -1;
	timer_reset(bdump_timer);
    }

    bdump_get_v1_guts (notice, auth, who, server);
}

static void
#ifdef __STDC__
bdump_get_v1a( ZNotice_t *notice, int auth, struct sockaddr_in *who,
	      ZServerDesc_t *server)
#else
bdump_get_v1a(notice, auth, who, server)
     ZNotice_t *notice;
     int auth;
     struct sockaddr_in *who;
     ZServerDesc_t *server;
#endif
{
    /* In version 1A, leave the listening file descriptor open; if we
       get a connection while we're dumping, one of the two will be
       punted.  */
    bdump_get_v1_guts (notice, auth, who, server);
}

void
bdump_get(notice, auth, who, server)
     ZNotice_t *notice;
     int auth;
     struct sockaddr_in *who;
     ZServerDesc_t *server;
{
#ifdef __STDC__
# define        P(s) s
#else
# define P(s) ()
#endif

  void (*proc) P((ZNotice_t *, int, struct sockaddr_in *, ZServerDesc_t *));

#undef P
  proc = NULL;

#if 1
	if (zdebug)
		syslog(LOG_DEBUG, "bdump_get: bdump v%s avail %s",
		       notice->z_class_inst, inet_ntoa(who->sin_addr));
#endif
	if (!strcmp (notice->z_class_inst, "1")
	    || !strcmp (notice->z_class_inst, ""))
	    proc = bdump_get_v1;
	if (!strcmp (notice->z_class_inst, "1A"))
	    proc = bdump_get_v1a;

	if (proc)
	    (*proc) (notice, auth, who, server);
	else
	    syslog(LOG_WARNING,
		   "bdump_get: Incompatible bdump version '%s' from %s",
		   notice->z_class_inst,
		   inet_ntoa(who->sin_addr));
}

/*
 * Send a list off as the specified notice
 */
 
int
bdump_send_list_tcp(kind, port, class_name, inst, opcode, sender, recip,
		    lyst, num)
     ZNotice_Kind_t kind;
     int port;
     char *class_name;
     char *inst;
     char *opcode;
     char *sender;
     char *recip;
     char **lyst;
     int num;
{
	ZNotice_t notice;
	register ZNotice_t *pnotice = &notice; /* speed hack */
	char *pack;
	int packlen, count;
	Code_t retval;
	u_short length;

	pnotice->z_kind = kind;
 
	pnotice->z_port = port;
	pnotice->z_class = class_name;
	pnotice->z_class_inst = inst;
	pnotice->z_opcode = opcode;
	pnotice->z_sender = sender;
	pnotice->z_recipient = recip;
	pnotice->z_default_format = "";
	pnotice->z_num_other_fields = 0;
 
	if ((retval = ZFormatNoticeList(pnotice, (char **) lyst, num, &pack, &packlen, ZNOAUTH)) != ZERR_NONE)
		return(retval);
	
	length = htons((u_short) packlen);
 
	if ((count = net_write(output, (caddr_t) &length, sizeof(length))) != sizeof(length))
		if (count < 0) {
			xfree(pack);	/* free allocated storage */
			return(errno);
		} else {
			syslog(LOG_WARNING, "slt (length) xmit: %d vs %d",
			       sizeof(length),count);
			xfree(pack);	/* free allocated storage */
			return(ZSRV_PKSHORT);
		}
 
	if ((count = net_write(output, pack, packlen)) != packlen)
		if (count < 0) {
			xfree(pack);	/* free allocated storage */
			return(errno);
		} else {
			syslog(LOG_WARNING, "slt (packet) xmit: %d vs %d",
			       packlen, count);
			xfree(pack);	/* free allocated storage */
			return(ZSRV_PKSHORT);
		}
	xfree(pack);			/* free allocated storage */
	return(ZERR_NONE);
}
 
static void
shutdown_file_pointers () {
    if (input) {
	(void) fclose (input);
	input = 0;
    }
    if (output) {
	(void) fclose (output);
	output = 0;
    }
    if (live_socket >= 0) {
	(void) close (live_socket);
	live_socket = -1;
    }
}

static void
cleanup(server, omask)
     ZServerDesc_t *server;
     int omask;
{
#ifdef _POSIX_SOURCE
	struct sigaction action;
#endif /* _POSIX_SOURCE */

#if 1
	zdbug((LOG_DEBUG, "bdump cleanup"));
#endif
	if (server != limbo_server) {
		server->zs_state = SERV_DEAD;
		timer_reset(server->zs_timer);
		server->zs_timer =
			timer_set_rel(0L, server_timo, (void *) server);
	}
	shutdown_file_pointers ();
#ifdef _POSIX_SOURCE
	action.sa_flags = 0;
	sigemptyset(&action.sa_mask);
	action.sa_handler = SIG_DFL;
	sigaction(SIGPIPE,&action, NULL);
#else
	(void) signal(SIGPIPE, SIG_DFL);
#endif /* _POSIX_SOURCE */
	bdumping = 0;
	server->zs_dumping = 0;
#ifdef CONCURRENT
	/* XXX need to flush the server and the updates to it */
#endif /* CONCURRENT */
	(void) sigsetmask(omask);
	return;
}
  
#ifdef KERBEROS
static int
get_tgt()
{
	int retval;
	if (!*my_realm)
		if ((retval = krb_get_lrealm(my_realm, 1)) != KSUCCESS) {
			syslog(LOG_ERR,"krb_get_lrealm: %s",
			       krb_err_txt[retval]);
			*my_realm = '\0';
			return(1);
		}
	/* have they expired ? */
	if (ticket_time < NOW - tkt_lifetime(TKTLIFETIME) + 15L) {
		/* +15 for leeway */
#if 0
		zdbug((LOG_DEBUG,"get new tickets: %d %d %d",
		       ticket_time, NOW,
		       NOW - tkt_lifetime(TKTLIFETIME) + 15L));
#endif
		(void) dest_tkt();

		{
		    /*
		     * XXX One version of krb_get_svc_in_tkt wants
		     * this argument writable and at least INST_SZ
		     * bytes long.
		     */
		    static char buf[INST_SZ+1] = "zephyr";

		    retval = krb_get_svc_in_tkt ("zephyr", buf/*XXX*/,
						 my_realm, "zephyr", "zephyr",
						 TKTLIFETIME, ZEPHYR_SRVTAB);
		}
		if (retval != KSUCCESS) {
			syslog(LOG_ERR,"get_tkt: %s",
			       krb_err_txt[retval]);
			ticket_time = 0L;
			return(1);
		} else
			ticket_time = NOW;
	}
	return(0);
}
#endif /* KERBEROS */
 
static Code_t
sbd_loop(from)
     struct sockaddr_in *from;
{
	ZNotice_t bd_notice;
	ZPacket_t pack;
	ZServerDesc_t *server;
	int packlen = sizeof(pack);
	Code_t retval;
	struct sockaddr_in bogus_from;
	char *zeph_version = NULL;
 
	bogus_from = *from;
	bogus_from.sin_port = sock_sin.sin_port;

	while (1) {
		packlen = sizeof(pack);
		if ((retval = get_packet(pack, packlen, &packlen)) != ZERR_NONE) {
			syslog(LOG_ERR, "sbd_loop: notice get: %s",
			       error_message(retval));
			return(retval);
		}
		if ((retval = ZParseNotice(pack, packlen, &bd_notice)) != ZERR_NONE) {
			syslog(LOG_ERR, "sbd notice parse: %s",
			       error_message(retval));
			return(retval);
		}
		if (!zeph_version) {
		  zeph_version = strsave(bd_notice.z_version);
		}
#ifdef DEBUG
		if (zdebug) {
			char buf[4096];
		
			(void) sprintf(buf,
				       "bdump:%s '%s' '%s' '%s' '%s' '%s'",
				       ZNoticeKinds[(int) bd_notice.z_kind],
				       bd_notice.z_class,
				       bd_notice.z_class_inst,
				       bd_notice.z_opcode,
				       bd_notice.z_sender,
				       bd_notice.z_recipient);
			syslog(LOG_DEBUG, buf);
		}
#endif /* DEBUG */
		if (!strcmp(bd_notice.z_class_inst, ADMIN_LIMBO)) {
			/* he wants limbo */
#if 1
			zdbug((LOG_DEBUG, "limbo req"));
#endif
			if ((retval = bdump_send_loop(limbo_server,
						      zeph_version))
			    != ZERR_NONE)
				return(retval);
			continue;
		} else if (!strcmp(bd_notice.z_class_inst, ADMIN_ME)) {
			/* he wants his state */
#if 1
			zdbug((LOG_DEBUG, "his state req"));
#endif
			if (server = server_which_server(&bogus_from)) {
				if ((retval = bdump_send_loop(server,
							      zeph_version))
				    != ZERR_NONE)
					return(retval);
			} else {
				syslog(LOG_ERR,"sbd_loop: no state");
				if ((retval = send_done()) != ZERR_NONE)
					return(retval);
			}
			continue;
		} else if (!strcmp(bd_notice.z_class_inst, ADMIN_YOU)) {
			/* he wants my state */
#if 1
			zdbug((LOG_DEBUG, "my state req"));
#endif
			if ((retval = bdump_send_loop(me_server, zeph_version))
			    != ZERR_NONE)
				return(retval);
			break;
		} else if (!strcmp(bd_notice.z_class_inst, ADMIN_DONE)) {
			break;
		} else {
			/* what does he want? */
#if 1
			zdbug((LOG_DEBUG, "unknown req"));
#endif
			break;
		}
	}
	if (zeph_version)
	    xfree(zeph_version);
	return(ZERR_NONE);
}
 
static Code_t
gbd_loop(server)
     ZServerDesc_t *server;
{
	Code_t retval;
 
	/* 
	 * if we have no hosts in the 'limbo' state (on the limbo server),
	 * ask for the other server to send us the limbo state.
	 * Thus we keep track of all the hosts which haven't spoken in a while,
	 * even in the face of server failure.
	 */
	if (otherservers[limbo_server_idx()].zs_hosts->q_forw ==
	    otherservers[limbo_server_idx()].zs_hosts) {
		if ((retval = bdump_ask_for(ADMIN_LIMBO)) != ZERR_NONE)
			return(retval);
		if ((retval = bdump_recv_loop(&otherservers[limbo_server_idx()])) != ZERR_NONE)
			return(retval);
	}

	/* Have I been given my own startup info yet?  */
	if (!bdump_inited) {
		if ((retval = bdump_ask_for(ADMIN_ME)) != ZERR_NONE)
			return(retval);
		if ((retval = bdump_recv_loop(me_server)) != ZERR_NONE)
			return(retval);
	}
	if ((retval = bdump_ask_for(ADMIN_YOU)) != ZERR_NONE)
		return(retval);
	retval = bdump_recv_loop(server);
	return(retval);
}

/*
 * The braindump offer wasn't taken, so we retract it.
 */
 
/*ARGSUSED*/
static void
close_bdump(arg)
     void * arg;
{
	if (bdump_socket >= 0) {
		FD_CLR(bdump_socket, &interesting);
		(void) close(bdump_socket);
		nfildes = srv_socket + 1;
		bdump_socket = -1;
#if 1
		zdbug((LOG_DEBUG, "bdump not used"));
#endif
	} else {
#if 1
		zdbug((LOG_DEBUG, "bdump not open"));
#endif
	}
	return;
}
 
/*
 * Ask the other server to send instruction packets for class instance
 * inst
 */
 
static Code_t
bdump_ask_for(inst)
     char *inst;
{
	Code_t retval;
 
	/* myname is the hostname */
	retval = send_normal_tcp(ACKED, bdump_sin.sin_port, ZEPHYR_ADMIN_CLASS,
				 inst, ADMIN_BDUMP, myname, "",
				 (char *) NULL, 0);
	return(retval);
}
 
/*
 * Start receiving instruction notices from the brain dump socket
 */
 
static Code_t
bdump_recv_loop(server)
     ZServerDesc_t *server;
{
	ZNotice_t notice;
	ZPacket_t packet;
	int len;
	Code_t retval;
	ZClient_t *client = NULLZCNT;
	struct sockaddr_in current_who;
	int who_valid = 0;
	int flushing_subs = 0;
#ifdef KERBEROS
	register char *cp;
#endif /* KERBEROS */
#ifdef CONCURRENT
	fd_set readable, initial;
	int fd_ready;
 	struct timeval tv;
#endif /* CONCURRENT */
 
#if 1
	zdbug((LOG_DEBUG, "bdump recv loop"));
#endif
	
#ifdef CONCURRENT
	FD_ZERO(&initial);
	FD_SET(srv_socket, &initial);
#endif /* CONCURRENT */
 
	/* do the inverse of bdump_send_loop, registering stuff on the fly */
	while (1) {
#ifdef CONCURRENT
		readable = initial;
		tv.tv_sec = tv.tv_usec = 0;

		if (msgs_queued()) {
#if 1
			zdbug((LOG_DEBUG, "brl msgqued"));
#endif
			fd_ready = 1;
		} else
			fd_ready = select(srv_socket + 1, &readable,
					  (fd_set *)0,
					  (fd_set *)0, &tv);
		/* 
		 * if there are packets to be processed, do them.
		 * We needn't worry about locking since we don't
		 * know what's coming our way.
		 */
		if (fd_ready > 0) {
#if 1
			zdbug((LOG_DEBUG, "brl fdready"));
#endif
			handle_packet();
#ifdef notdef
			if (cancel_outgoing_dump) {
			    cancel_outgoing_dump = 0;
			    return EWOULDBLOCK; /* maybe in a warped sort
						   of way */
			}
#endif
		} else if (fd_ready < 0)
			syslog(LOG_ERR, "brl select: %m");
#endif /* CONCURRENT */
		len = sizeof(packet);
		if ((retval = get_packet(packet, len, &len)) != ZERR_NONE) {
			syslog(LOG_ERR, "brl get pkt: %s",
			       error_message(retval));
			return(retval);
		}

		if ((retval = ZParseNotice(packet, len, &notice)) != ZERR_NONE) {
			syslog(LOG_ERR, "brl notice parse: %s",
			       error_message(retval));
			return(retval);
		}
#if defined (DEBUG)
		if (zdebug) {
			char buf[4096];

			(void) sprintf(buf,
				       "bdump:%s '%s' '%s' '%s' '%s' '%s'",
				       ZNoticeKinds[(int) notice.z_kind],
				       notice.z_class,
				       notice.z_class_inst,
				       notice.z_opcode,
				       notice.z_sender,
				       notice.z_recipient);
			syslog(LOG_DEBUG, buf);
		}
#endif /* DEBUG */
		if (notice.z_kind == HMCTL) {
			/* host register */
			if ((retval = extract_sin(&notice, &current_who)) !=
			    ZERR_NONE) {
				syslog(LOG_ERR, "brl hmctl sin: %s",
				       error_message(retval));
				return(retval);
			}
			who_valid = 1;
			/* 1 = tell it we are authentic */
			if ((retval = hostm_dispatch(&notice, 1,
						    &current_who, server))
			     != ZERR_NONE) {
				syslog(LOG_ERR,"brl hm_disp failed: %s",
				       error_message(retval));
				return(retval);
			}
		} else if (!strcmp(notice.z_opcode, ADMIN_DONE)) {
			/* end of brain dump */
		  return(ZERR_NONE);
		} else if (!who_valid) {
			syslog(LOG_ERR, "brl: no current host");
			return(ZSRV_HNOTFOUND);
		} else if (!strcmp(notice.z_class, LOGIN_CLASS)) {
			/* 1 = tell it we are authentic */
			if ((retval = ulogin_dispatch(&notice, 1,
						     &current_who, server))
			     != ZERR_NONE) {
				syslog(LOG_ERR, "brl ul_disp failed: %s",
				       error_message(retval));
				return(retval);
			}
		} else if (!strcmp(notice.z_opcode, ADMIN_NEWCLT)) {
			/* register a new client */
			notice.z_port = htons((u_short)atoi(notice.z_message));
			if (ntohs(notice.z_port) == 0) {
			    /* this is a bogus client from an older rev.
			       server, so we just flush it. */
			    syslog(LOG_ERR, "brl flushing %s/0",
				   inet_ntoa(current_who.sin_addr));
			    flushing_subs = 1;
			    continue;	/* while loop */
			}
			flushing_subs = 0;
			if ((retval = client_register(&notice,
						      &current_who,
						      &client,
						      server,
						      0)) != ZERR_NONE) {
				syslog(LOG_ERR,"brl register failed: %s",
				       error_message(retval));
				return(retval);
			}
#ifdef KERBEROS
			bzero((caddr_t) client->zct_cblock,
					      sizeof(C_Block));
			if (*notice.z_class_inst) {
				/* a C_Block is there */
				cp = notice.z_message +
					strlen(notice.z_message) + 1;
				retval = ZReadAscii(cp,strlen(cp),
						    client->zct_cblock,
						    sizeof(C_Block));
				if (retval != ZERR_NONE) {
					bzero((caddr_t) client->zct_cblock,
					      sizeof(C_Block));
					syslog(LOG_ERR,"brl bad cblk read: %s (%s)",
					       error_message(retval),
					       cp);
				}
			}
#endif /* KERBEROS */
		} else if (!strcmp(notice.z_opcode, CLIENT_SUBSCRIBE)) { 
			if (flushing_subs)
			    continue;	/* while loop */
			/* a subscription packet */
			if (!client) {
				syslog(LOG_ERR, "brl no client");
				return(ZSRV_NOCLT);
			}
			if ((retval = subscr_subscribe(client, &notice)) != ZERR_NONE) {
				syslog(LOG_WARNING, "brl subscr failed: %s",
				       error_message(retval));
				return(retval);
			}
		} else {
			syslog(LOG_ERR, "brl bad opcode %s",notice.z_opcode);
			return(ZSRV_UNKNOWNOPCODE);
		}
	}
}
 
/*
 * Send all the state from server to the peer.
 */
 
static Code_t
bdump_send_loop(server, vers)
     ZServerDesc_t *server;
     char *vers;
{
	register ZHostList_t *host;
	register ZClientList_t *clist;
	Code_t retval;
#ifdef CONCURRENT
	fd_set readable, initial;
	int fd_ready;
	struct timeval tv;
#endif /* CONCURRENT */
 
#if 1
	zdbug((LOG_DEBUG, "bdump send loop"));
#endif
 
 
#ifdef CONCURRENT
	FD_ZERO(&initial);
	FD_SET(srv_socket, &initial);
#endif /* CONCURRENT */
 
	for (host = server->zs_hosts->q_forw;
	     host != server->zs_hosts;
	     host = host->q_forw) {
		/* for each host */
#ifdef CONCURRENT
		host->zh_locked = 1;
 
		readable = initial;
		tv.tv_sec = tv.tv_usec = 0;
 
		if (msgs_queued())
			fd_ready = 1;
		else
			fd_ready = select(srv_socket + 1, &readable,
					  (fd_set *)0,
					  (fd_set *)0, &tv);
		/* 
		 * if there are packets to be processed, do them.
		 * locking the host above insures nothing we are working on
		 * gets trashed.
		 */
		if (fd_ready > 0) {
			handle_packet();
#ifdef notdef
			if (cancel_outgoing_dump) {
			    cancel_outgoing_dump = 0;
			    return EWOULDBLOCK;
			}
#endif
		} else if (fd_ready < 0)
			syslog(LOG_ERR, "bsl select: %m");
 
#endif /* CONCURRENT */
		if ((retval = send_host_register(host)) != ZERR_NONE) {
			host->zh_locked = 0;
			return(retval);
		}
		if ((retval = uloc_send_locations(host, vers)) != ZERR_NONE) {
			host->zh_locked = 0;
			return(retval);
		}
		if (!host->zh_clients) {
			host->zh_locked = 0;
			continue;
		}
		for (clist = host->zh_clients->q_forw;
		     clist != host->zh_clients;
		     clist = clist->q_forw) {
			/* for each client */
			if (!clist->zclt_client->zct_subs) {
				host->zh_locked = 0;
				continue;
			}
			if ((retval = subscr_send_subs(clist->zclt_client,
						       vers)) != ZERR_NONE) {
				host->zh_locked = 0;
				return(retval);
			}
		}
		host->zh_locked = 0;
	}
	retval = send_done();
	return(retval);
}
 
/*
 * Send a host boot packet to the other server
 */
 
static Code_t
send_host_register(host)
     ZHostList_t *host;
{
	char buf[512], *addr, *lyst[2];
	Code_t retval;
 
#if 0
	zdbug((LOG_DEBUG, "bdump_host_register"));
#endif
	addr = inet_ntoa(host->zh_addr.sin_addr);
	(void) sprintf(buf, "%d", ntohs(host->zh_addr.sin_port));
	lyst[0] = addr;
	lyst[1] = buf;
 
	/* myname is the hostname */
	retval = bdump_send_list_tcp (HMCTL, (int) bdump_sin.sin_port,
				      ZEPHYR_CTL_CLASS, ZEPHYR_CTL_HM,
				      HM_BOOT, myname, "", lyst, 2);
	if (retval != ZERR_NONE)
		syslog(LOG_ERR, "shr send: %s",error_message(retval));
	return(retval);
}
 
/*
 * Send a sync indicating end of this host
 */
 
static Code_t
send_done()
{
	Code_t retval;
 
#if 1
	zdbug((LOG_DEBUG, "send_done"));
#endif
	retval = send_normal_tcp(SERVACK, bdump_sin.sin_port,
				 ZEPHYR_ADMIN_CLASS, "", ADMIN_DONE, myname,
				 "", (char *) NULL, 0);
	return(retval);
}
 
 
/*
 * Send a list off as the specified notice
 */
 
static Code_t
send_list(kind, port, class_name, inst, opcode, sender, recip, lyst, num)
     ZNotice_Kind_t kind;
     int port;
     char *class_name;
     char *inst;
     char *opcode;
     char *sender;
     char *recip;
     char **lyst;
     int num;
{
	ZNotice_t notice;
	register ZNotice_t *pnotice; /* speed hack */
	char *pack;
	int packlen;
	Code_t retval;
 
	pnotice = &notice;
 
	pnotice->z_kind = kind;
 
	pnotice->z_port = port;
	pnotice->z_class = class_name;
	pnotice->z_class_inst = inst;
	pnotice->z_opcode = opcode;
	pnotice->z_sender = sender;
	pnotice->z_recipient = recip;
	pnotice->z_default_format = "";
	pnotice->z_num_other_fields = 0;
	
	if ((retval = ZFormatNoticeList(pnotice, lyst, num, &pack, &packlen, ZNOAUTH)) != ZERR_NONE) {
		syslog(LOG_WARNING, "sl format: %s", error_message(retval));
		return(retval);
	}
	
	if ((retval = ZSendPacket(pack, packlen, 0)) != ZERR_NONE) {
		syslog(LOG_WARNING, "sl xmit: %s", error_message(retval));
		xfree(pack);		/* free allocated storage */
		return(retval);
	}
	xfree(pack);			/* free allocated storage */
	return(ZERR_NONE);
}
 
/*
 * Send a message off as the specified notice, via TCP
 */
 
static Code_t
send_normal_tcp(kind, port, class_name, inst, opcode, sender, recip,
		message, len)
     ZNotice_Kind_t kind;
     int port;
     char *class_name;
     char *inst;
     char *opcode;
     char *sender;
     char *recip;
     char *message;
     int len;
{
	ZNotice_t notice;
	register ZNotice_t *pnotice; /* speed hack */
	char *pack;
	int packlen, count;
	Code_t retval;
	u_short length;
 
	pnotice = &notice;
 
	pnotice->z_kind = kind;
 
	pnotice->z_port = port;
	pnotice->z_class = class_name;
	pnotice->z_class_inst = inst;
	pnotice->z_opcode = opcode;
	pnotice->z_sender = sender;
	pnotice->z_recipient = recip;
	pnotice->z_default_format = "";
	pnotice->z_message = message;
	pnotice->z_message_len = len;
	pnotice->z_num_other_fields = 0;
 
	if ((retval = ZFormatNotice(pnotice, &pack, &packlen, ZNOAUTH)) != ZERR_NONE) {
		syslog(LOG_WARNING, "sn format: %s", error_message(retval));
		return(retval);
	}
 
	length = htons((u_short) packlen);
 
	if ((count = net_write(output, (caddr_t) &length, sizeof(length))) != sizeof(length)) {
		if (count < 0) {
			syslog(LOG_WARNING, "snt xmit/len: %m");
			xfree(pack);	/* free allocated storage */
			return(errno);
		} else {
			syslog(LOG_WARNING, "snt xmit: %d vs %d",sizeof(length),count);
			xfree(pack);	/* free allocated storage */
			return(ZSRV_LEN);
		}
	}
	if ((count = net_write(output, pack, packlen)) != packlen)
		if (count < 0) {
			syslog(LOG_WARNING, "snt xmit: %m");
			xfree(pack);	/* free allocated storage */
			return(errno);
		} else {
			syslog(LOG_WARNING, "snt xmit: %d vs %d",packlen, count);
			xfree(pack);	/* free allocated storage */
			return(ZSRV_LEN);
		}
	xfree(pack);			/* free allocated storage */
	return(ZERR_NONE);
}
 
/*
 * get a packet from the TCP socket
 * return 0 if successful, error code else
 */
 
static Code_t
get_packet(packet, len, retlen)
     caddr_t packet;
     int len;
     int *retlen;
{
	u_short length;
	int result;
 
	if ((result = net_read(input, (caddr_t) &length, sizeof(u_short))) < sizeof(short)) {
		if (result < 0)
			return(errno);
		else {
			syslog(LOG_ERR, "get_pkt len: %d vs %d (%m)", result, sizeof(short));
			return(ZSRV_LEN);
		}
	}
	
	length = ntohs(length);
	if (len < length)
		return(ZSRV_BUFSHORT);
	if ((result = net_read(input, packet, (int) length)) < length) {
		if (result < 0)
			return(errno);
		else {
			syslog(LOG_ERR, "get_pkt: %d vs %d (%m)",result, length);
			return(ZSRV_LEN);
		}
	}
	*retlen = (int) length;
	return(ZERR_NONE);
}
 
static Code_t
extract_sin(notice, target)
     ZNotice_t *notice;
     struct sockaddr_in *target;
{
	register char *cp = notice->z_message;
	char *buf;

	buf = cp;
	if (!notice->z_message_len || *buf == '\0') {
#if 0
		zdbug((LOG_DEBUG,"no addr"));
#endif
		return(ZSRV_PKSHORT);
	}
	target->sin_addr.s_addr = inet_addr(cp);
 
	cp += (strlen(cp) + 1); /* past the null */
	if ((cp >= notice->z_message + notice->z_message_len)
	    || (*cp == '\0')) {
#if 0
		zdbug((LOG_DEBUG, "no port"));
#endif
		return(ZSRV_PKSHORT);
	}
	target->sin_port = htons((u_short) atoi(cp));
	target->sin_family = AF_INET;
	return(ZERR_NONE);
}
 
static int
net_read(f, buf, len)
     FILE *f;
     register char *buf;
     register int len;
{
    int cc, len2 = 0;
 
    fflush (output);
    do {
	errno = 0;
	cc = fread (buf, 1, len, f);
	if (cc == 0)
	    return -1;
	buf += cc;
	len2 += cc;
	len -= cc;
    } while (len > 0);
    return len2;
}
 
static int
net_write(f, buf, len)
     FILE *f;
     register char *buf;
     int len;
{
    int cc;
    register int wrlen = len;
    do {
	cc = fwrite (buf, 1, wrlen, f);
	if (cc == 0)
	    return -1;
	buf += cc;
	wrlen -= cc;
    } while (wrlen > 0);
    return len;
}

static int
setup_file_pointers ()
{
  int fd;

    input = fdopen (live_socket, "r");
    if (!input)
	return errno;

    fd = dup (live_socket);
    if (fd < 0)
	return errno;
    output = fdopen (fd, "w");
    if (!output)
	return errno;

    return 0;
}
