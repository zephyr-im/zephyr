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
#include "zserver.h"
#include <sys/socket.h>
#include <com_err.h>

#ifndef lint
static const char rcsid_bdump_c[] = "$Id$";
#endif /* lint */

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
 *	Server *server;
 *
 * Code_t bdump_send_list_tcp(kind, port, class, inst, opcode,
 *			    sender, recip, lyst, num)
 *	ZNotice_Kind_t kind;
 *	u_short port;
 *	char *class, *inst, *opcode, *sender, *recip;
 *	char *lyst[];
 *	int num;
 */

static void close_bdump __P((void* arg));
static Code_t bdump_send_loop __P((Server *server)),
bdump_ask_for __P((char *inst)),
bdump_recv_loop __P((Server *server));
static void bdump_get_v12 __P((ZNotice_t *, int, struct sockaddr_in *,
			       Server *));
static Code_t get_packet __P((void *packet, int len, int *retlen));
static Code_t extract_sin __P((ZNotice_t *notice, struct sockaddr_in *target));
static Code_t send_done __P((void));
static Code_t send_list __P((ZNotice_Kind_t kind, int port, char *class_name,
			     char *inst, char *opcode, char *sender,
			     char *recip, char **lyst, int num));
static Code_t send_normal_tcp __P((ZNotice_Kind_t kind, int port,
				   char *class_name,
				   char *inst, char *opcode, char *sender,
				   char *recip, char *message, int len));
static int net_read __P((FILE *f, char *buf, int len));
static int net_write __P((FILE *f, char *buf, int len));
static int setup_file_pointers __P((void));
static void shutdown_file_pointers __P((void));
static void cleanup __P((Server *server));

#ifdef ZEPHYR_USES_KERBEROS
static int get_tgt __P((void));
static long ticket_time;
static char my_realm[REALM_SZ];

#define TKTLIFETIME	120
#define tkt_lifetime(val) ((long) val * 5L * 60L)

#ifndef NOENCRYPTION
extern C_Block	serv_key;
extern Sched	serv_ksched;
#endif
#endif /* ZEPHYR_USES_KERBEROS */

static Timer *bdump_timer;
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
#ifndef ZEPHYR_USES_KERBEROS
    int bdump_port = IPPORT_RESERVED - 1;
#endif /* !ZEPHYR_USES_KERBEROS */
#if 1
    zdbug((LOG_DEBUG, "bdump_offer"));
#endif
#ifdef ZEPHYR_USES_KERBEROS
    /* 
     * when using ZEPHYR_USES_KERBEROS server-server authentication, we can
     * use any random local address 
     */
    bdump_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (bdump_socket < 0) {
	syslog(LOG_ERR,"bdump_offer: socket: %m");
	bdump_socket = -1;
	return;
    }
    memset(&bdump_sin, 0, sizeof(bdump_sin));
    /* a port field of 0 makes the UNIX
     * kernel choose an appropriate port/address pair */
 
    bdump_sin.sin_port = 0;
    bdump_sin.sin_addr = my_addr;
    bdump_sin.sin_family = AF_INET;
    retval = bind(bdump_socket, (struct sockaddr *) &bdump_sin,
		  sizeof(bdump_sin));
    if (retval < 0) {
	syslog(LOG_ERR, "bdump_offer: bind: %m");
	close(bdump_socket);
	bdump_socket = -1;
	return;
    }
    if (!bdump_sin.sin_port) {
	int len = sizeof(bdump_sin);

	if (getsockname(bdump_socket,
			(struct sockaddr *) &bdump_sin, &len) < 0) {
	    syslog(LOG_ERR, "bdump_offer: getsockname: %m");
	    close(bdump_socket);
	    bdump_socket = -1;
	    return;
	}
    }
#else  /* !ZEPHYR_USES_KERBEROS */
    /*
     * when not using ZEPHYR_USES_KERBEROS, we can't use any old port, we use
     * Internet reserved ports instead (rresvport)
     */
    bdump_socket = rresvport(&bdump_port);
    if (bdump_socket < 0) {
	syslog(LOG_ERR,"bdump_offer: socket: %m");
	bdump_socket = -1;
	return;
    }
    memset(&bdump_sin, 0, sizeof(bdump_sin));
    bdump_sin.sin_port = htons((unsigned short) bdump_port);
    bdump_sin.sin_addr = my_addr;
    bdump_sin.sin_family = AF_INET;
#endif				/* ZEPHYR_USES_KERBEROS */

    listen(bdump_socket, 1);
 
    bdump_timer = timer_set_rel(20L, close_bdump, NULL);
    FD_SET(bdump_socket, &interesting);
    nfds = max(bdump_socket, srv_socket) + 1;

    addr = inet_ntoa(bdump_sin.sin_addr);
    sprintf(buf, "%d", ntohs(bdump_sin.sin_port));
    lyst[0] = addr;
    lyst[1] = buf;
 
    retval = ZSetDestAddr(who);
    if (retval != ZERR_NONE) {
	syslog(LOG_WARNING, "bdump_offer: ZSetDestAddr: %s",
	       error_message(retval));
	return;
    }
 
    /* myname is the hostname */
    /* the class instance is the version number, here it is */
    /* bdump_version, which is set in main */
    send_list(ACKED, srv_addr.sin_port, ZEPHYR_ADMIN_CLASS, bdump_version,
	      ADMIN_BDUMP, myname, "", lyst, 2);
	
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
bdump_send()
{
    struct sockaddr_in from;
    Server *server;
    Code_t retval;
    int fromlen = sizeof(from);
    int on = 1;
#ifdef _POSIX_VERSION
    struct sigaction action;
#endif

#ifdef ZEPHYR_USES_KERBEROS
    KTEXT_ST ticket;
    AUTH_DAT kdata;
#else
    unsigned short fromport;
#endif /* ZEPHYR_USES_KERBEROS */
 
#if 1
    zdbug((LOG_DEBUG, "bdump_send"));
#endif
    /* accept the connection, and send the brain dump */
    live_socket = accept(bdump_socket, (struct sockaddr *) &from, &fromlen);
    if (live_socket < 0) {
	syslog(LOG_ERR,"bdump_send: accept: %m");
	return;
    }
    if (setsockopt(live_socket, SOL_SOCKET, SO_KEEPALIVE, (char *) &on,
		   sizeof(on)) < 0)
	syslog(LOG_WARNING, "bdump_send: setsockopt (SO_KEEPALIVE): %m");
 
#ifndef ZEPHYR_USES_KERBEROS
    fromport = ntohs(from.sin_port);
#endif
 
#ifdef _POSIX_VERSION
    sigemptyset(&action.sa_mask);
    action.sa_flags = 0;
    action.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &action, NULL);

#else
    signal(SIGPIPE, SIG_IGN);	/* so we can detect failures */
#endif
 
    from.sin_port = srv_addr.sin_port; /* we don't care what port
					* it came from, and we need to
					* fake out server_which_server() */
    server = server_which_server(&from);
    if (!server) {
	syslog(LOG_ERR, "bdump_send: unknown server?");
	server = limbo_server;
    }
#if 1
    zdbug((LOG_DEBUG, "bdump_send: connection from %s/%d",
	   inet_ntoa(from.sin_addr), ntohs(from.sin_port)));
#endif

    bdumping = 1;
    server->dumping = 1;

    if (bdump_socket >= 0) {
	/* shut down the listening socket and the timer. */
	FD_CLR(bdump_socket, &interesting);
	close(bdump_socket);
	nfds = srv_socket + 1;
	bdump_socket = -1;
	timer_reset(bdump_timer);
    }
 
    /* Now begin the brain dump. */
 
#ifdef ZEPHYR_USES_KERBEROS
    /* receive the authenticator */
    retval = GetKerberosData(live_socket, from.sin_addr, &kdata,
			     SERVER_SERVICE, srvtab_file);
    if (retval != KSUCCESS) {
	syslog(LOG_ERR, "bdump_send: getkdata: %s",
	       krb_get_err_text(retval));
	cleanup(server);
	return;
    }
    if (get_tgt()) {
	cleanup(server);
	return;
    }
    if (strcmp(kdata.pname, SERVER_SERVICE) ||
	strcmp(kdata.pinst, SERVER_INSTANCE) ||
	strcmp(kdata.prealm, my_realm)) {
	syslog(LOG_ERR, "bdump_send: peer not zephyr: %s.%s@%s",
	       kdata.pname, kdata.pinst, kdata.prealm);
	cleanup(server);
	return;
    }
    /* authenticate back */
    retval = SendKerberosData(live_socket, &ticket, SERVER_SERVICE,
			      SERVER_INSTANCE);
    if (retval != 0) {
	syslog(LOG_ERR,"bdump_send: SendKerberosData: %s",
	       error_message (retval));
	cleanup(server);
	return;
    }
#else  /* !ZEPHYR_USES_KERBEROS */
    if (fromport > IPPORT_RESERVED || fromport < IPPORT_RESERVED / 2) {
	syslog(LOG_ERR, "bdump_send: bad port from peer: %d", fromport);
	cleanup(server);
	return;
    }
#endif /* ZEPHYR_USES_KERBEROS */

    retval = setup_file_pointers();
    if (retval != 0) {
	syslog (LOG_WARNING, "bdump_send: can't set up file pointers: %s",
		error_message(retval));
	cleanup(server);
	return;
    }
    retval = bdump_send_loop(server);
    if (retval != ZERR_NONE) {
	syslog(LOG_WARNING, "bdump_send: bdump_send_loop failed: %s",
	       error_message(retval));
	cleanup(server);
	return;
    }
    retval = bdump_recv_loop(server);
    if (retval != ZERR_NONE) {
	syslog(LOG_WARNING, "bdump_send: bdump_recv_loop failed: %s",
	       error_message(retval));
	cleanup(server);
	return;
    }
#if 1
    zdbug((LOG_DEBUG, "bdump_send: finished"));
#endif
    if (server != limbo_server) {
	/* set this guy to be up, and schedule a hello */
	server->state = SERV_UP;
	timer_reset(server->timer);
	server->timer = timer_set_rel(0L, server_timo, server);
    }
#if 0
    zdbug((LOG_DEBUG,"cleanup sbd"));
#endif
    shutdown_file_pointers();

#ifdef _POSIX_VERSION
    action.sa_handler = SIG_DFL;
    sigaction(SIGPIPE, &action, NULL);
#else
    signal(SIGPIPE, SIG_DFL);
#endif
    bdumping = 0;
    server->dumping = 0;
    /* Now that we are finished dumping, send all the queued packets */
    server_send_queue(server);
    return;
}

/*ARGSUSED*/
static void
bdump_get_v12 (notice, auth, who, server)
    ZNotice_t *notice;
    int auth;
    struct sockaddr_in *who;
    Server *server;
{
    struct sockaddr_in from;
    Code_t retval;
    int on = 1;
#ifdef _POSIX_VERSION
    struct sigaction action;
#endif
#ifdef ZEPHYR_USES_KERBEROS
    KTEXT_ST ticket;
    AUTH_DAT kdata;
#else  /* !ZEPHYR_USES_KERBEROS */
    int reserved_port = IPPORT_RESERVED - 1;
#endif /* ZEPHYR_USES_KERBEROS */
    
    bdumping = 1;
    server->dumping = 1;
 
#ifdef _POSIX_VERSION
    action.sa_flags = 0;
    sigemptyset(&action.sa_mask);
    action.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &action, NULL);
#else
    signal(SIGPIPE, SIG_IGN);	/* so we can detect problems */
#endif /* _POSIX_VRESION */
 
    if (bdump_socket >= 0) {
	/* We cannot go get a brain dump when someone may
	   potentially be connecting to us (if that other
	   server is the server to whom we are connecting,
	   we will deadlock. so we shut down the listening
	   socket and the timer. */
	FD_CLR(bdump_socket, &interesting);
	close(bdump_socket);
	nfds = srv_socket+1;
	bdump_socket = -1;
	timer_reset(bdump_timer);
    }

    retval = extract_sin(notice, &from);
    if (retval != ZERR_NONE) {
	syslog(LOG_ERR, "bdump_get: sin: %s", error_message(retval));
#ifdef _POSIX_VERSION
	action.sa_handler = SIG_DFL;
	sigaction(SIGPIPE, &action, NULL);
#else
	signal(SIGPIPE, SIG_DFL);
#endif
	bdumping = 0;
	server->dumping = 0;
	return;
    }
#ifndef ZEPHYR_USES_KERBEROS
    if (ntohs(from.sin_port) > IPPORT_RESERVED ||
	ntohs(from.sin_port) < IPPORT_RESERVED / 2) {
	syslog(LOG_ERR, "bdump_get: port not reserved: %d",
	       ntohs(from.sin_port));
	cleanup(server);
	return;
    }
    live_socket = rresvport(&reserved_port);
#else  /* !ZEPHYR_USES_KERBEROS */
    live_socket = socket(AF_INET, SOCK_STREAM, 0);
#endif /* ZEPHYR_USES_KERBEROS */
    if (live_socket < 0) {
	syslog(LOG_ERR, "bdump_get: socket: %m");
	cleanup(server);
	return;
    }
    if (connect(live_socket, (struct sockaddr *) &from, sizeof(from))) {
	syslog(LOG_ERR, "bdump_get: connect: %m");
	cleanup(server);
	return;
    }
    if (setsockopt(live_socket, SOL_SOCKET, SO_KEEPALIVE, (char *)&on,
		   sizeof(on)) < 0)
	syslog(LOG_WARNING, "bdump_get: setsockopt (SO_KEEPALIVE): %m");
#if 1
    zdbug((LOG_DEBUG, "bdump_get: connected"));
#endif
 
    /* Now begin the brain dump. */

#ifdef ZEPHYR_USES_KERBEROS
    /* send an authenticator */
    if (get_tgt()) {
	cleanup(server);
	return;
    }
    retval = SendKerberosData(live_socket, &ticket, SERVER_SERVICE,
			      SERVER_INSTANCE);
    if (retval != 0) {
	syslog(LOG_ERR,"bdump_get: %s", error_message(retval));
	cleanup(server);
	return;
    }
#if 1
    zdbug((LOG_DEBUG, "bdump_get: SendKerberosData ok"));
#endif
 
    /* get his authenticator */
    retval = GetKerberosData(live_socket, from.sin_addr, &kdata,
			     SERVER_SERVICE, srvtab_file);
    if (retval != KSUCCESS) {
	syslog(LOG_ERR, "bdump_get getkdata: %s",krb_get_err_text(retval));
	cleanup(server);
	return;
    }
    /* my_realm is filled in inside get_tgt() */
    if (strcmp(kdata.pname, SERVER_SERVICE) ||
	strcmp(kdata.pinst, SERVER_INSTANCE) ||
	strcmp(kdata.prealm, my_realm)) {
	syslog(LOG_ERR, "bdump_get: peer not zephyr in lrealm: %s.%s@%s",
	       kdata.pname, kdata.pinst,kdata.prealm);
	cleanup(server);
	return;
    }
#endif /* ZEPHYR_USES_KERBEROS */
    retval = setup_file_pointers();
    if (retval != 0) {
	syslog(LOG_WARNING, "bdump_get: can't set up file pointers: %s",
	       error_message (retval));
	cleanup(server);
	return;
    }
    retval = bdump_recv_loop(server);
    if (retval != ZERR_NONE) {
	syslog(LOG_WARNING, "bdump_get: bdump_recv_loop failed: %s",
	       error_message(retval));
	cleanup(server);
	return;
    }
#if 1
    zdbug((LOG_DEBUG,"bdump_get: gbdl ok"));
#endif
    retval = bdump_send_loop(server);
    if (retval != ZERR_NONE) {
	syslog(LOG_WARNING, "bdump_send_loop failed: %s",
	       error_message(retval));
	cleanup(server);
	return;
    }
#if 1
    zdbug((LOG_DEBUG, "bdump_get: gbd finished"));
#endif
    /* set this guy to be up, and schedule a hello */
    server->state = SERV_UP;
    timer_reset(server->timer);
    server->timer = timer_set_rel(0L, server_timo, server);

#if 1
    zdbug((LOG_DEBUG,"cleanup gbd"));
#endif
    shutdown_file_pointers();
#ifdef _POSIX_VERSION
    action.sa_handler = SIG_DFL;
    sigaction(SIGPIPE, &action, NULL);
#else
    signal(SIGPIPE, SIG_DFL);
#endif
    bdumping = 0;
    server->dumping = 0;
    /* Now that we are finished dumping, send all the queued packets */
    server_send_queue(server);

    return;
}

void
bdump_get(notice, auth, who, server)
    ZNotice_t *notice;
    int auth;
    struct sockaddr_in *who;
    Server *server;
{
    void (*proc) __P((ZNotice_t *, int, struct sockaddr_in *, Server *));

    proc = NULL;

#if 1
    if (zdebug) {
	syslog(LOG_DEBUG, "bdump_get: bdump v%s avail %s",
	       notice->z_class_inst, inet_ntoa(who->sin_addr));
    }
#endif
    if (strcmp (notice->z_class_inst, "1.2") == 0)
	proc = bdump_get_v12;

    if (proc) {
	(*proc)(notice, auth, who, server);
    } else {
	syslog(LOG_WARNING,
	       "bdump_get: Incompatible bdump version '%s' from %s",
	       notice->z_class_inst,
	       inet_ntoa(who->sin_addr));
    }
}

/*
 * Send a list off as the specified notice
 */

Code_t
bdump_send_list_tcp(kind, addr, class_name, inst, opcode, sender, recip, lyst,
		    num)
    ZNotice_Kind_t kind;
    struct sockaddr_in *addr;
    int num;
    char *class_name, *inst, *opcode, *sender, *recip, **lyst;
{
    ZNotice_t notice;
    char *pack, addrbuf[100];
    int packlen, count;
    Code_t retval;
    u_short length;

    retval = ZMakeAscii(addrbuf, sizeof(addrbuf),
			(unsigned char *) &addr->sin_addr,
			sizeof(struct in_addr));
    if (retval != ZERR_NONE)
	return retval;
    notice.z_kind = kind;
 
    notice.z_port = addr->sin_port;
    notice.z_class = class_name;
    notice.z_class_inst = inst;
    notice.z_opcode = opcode;
    notice.z_sender = sender;
    notice.z_recipient = recip;
    notice.z_default_format = "";
    notice.z_num_other_fields = 1;
    notice.z_other_fields[0] = addrbuf;
 
    retval = ZFormatNoticeList(&notice, lyst, num, &pack, &packlen, ZNOAUTH);
    if (retval != ZERR_NONE)
	return retval;
	
    length = htons((u_short) packlen);
 
    count = net_write(output, (char *) &length, sizeof(length));
    if (count != sizeof(length)) {
	if (count < 0) {
	    free(pack);
	    return(errno);
	} else {
	    syslog(LOG_WARNING, "slt (length) xmit: %d vs %d",
		   sizeof(length), count);
	    free(pack);
	    return(ZSRV_PKSHORT);
	}
    }
 
    count = net_write(output, pack, packlen);
    if (count != packlen) {
	if (count < 0) {
	    free(pack);
	    return(errno);
	} else {
	    syslog(LOG_WARNING, "slt (packet) xmit: %d vs %d",
		   packlen, count);
	    free(pack);
	    return(ZSRV_PKSHORT);
	}
    }
    free(pack);
    return(ZERR_NONE);
}

static void
shutdown_file_pointers() {
    if (input) {
	fclose(input);
	input = 0;
    }
    if (output) {
	fclose(output);
	output = 0;
    }
    if (live_socket >= 0) {
	close(live_socket);
	live_socket = -1;
    }
}

static void
cleanup(server)
    Server *server;
{
#ifdef _POSIX_VERSION
    struct sigaction action;
#endif

#if 1
    zdbug((LOG_DEBUG, "bdump cleanup"));
#endif
    if (server != limbo_server) {
	server->state = SERV_DEAD;
	timer_reset(server->timer);
	server->timer = timer_set_rel(0L, server_timo, server);
    }
    shutdown_file_pointers ();
#ifdef _POSIX_VERSION
    action.sa_flags = 0;
    sigemptyset(&action.sa_mask);
    action.sa_handler = SIG_DFL;
    sigaction(SIGPIPE,&action, NULL);
#else
    signal(SIGPIPE, SIG_DFL);
#endif /* _POSIX_VERSION */
    bdumping = 0;
    server->dumping = 0;
}

#ifdef ZEPHYR_USES_KERBEROS
static int
get_tgt()
{
    int retval;
#ifndef NOENCRYPTION
    Sched *s;
#endif
	
    if (!*my_realm) {
	retval = krb_get_lrealm(my_realm, 1);
	if (retval != KSUCCESS) {
	    syslog(LOG_ERR,"krb_get_lrealm: %s", krb_get_err_text(retval));
	    *my_realm = '\0';
	    return(1);
	}
    }
    /* have they expired ? */
    if (ticket_time < NOW - tkt_lifetime(TKTLIFETIME) + 15L) {
	/* +15 for leeway */
#if 0
	zdbug((LOG_DEBUG,"get new tickets: %d %d %d", ticket_time, NOW,
	       NOW - tkt_lifetime(TKTLIFETIME) + 15L));
#endif
	dest_tkt();

	{
	    /*
	     * XXX One version of krb_get_svc_in_tkt wants
	     * this argument writable and at least INST_SZ
	     * bytes long.
	     */
	    static char buf[INST_SZ + 1] = SERVER_INSTANCE;

	    retval = krb_get_svc_in_tkt(SERVER_SERVICE, buf, my_realm,
					SERVER_SERVICE,SERVER_INSTANCE,
					TKTLIFETIME, srvtab_file);
	}
	if (retval != KSUCCESS) {
	    syslog(LOG_ERR,"get_tgt: krb_get_svc_in_tkt: %s",
		   krb_get_err_text(retval));
	    ticket_time = 0L;
	    return(1);
	} else {
	    ticket_time = NOW;
	}

#ifndef NOENCRYPTION
	retval = read_service_key(SERVER_SERVICE, SERVER_INSTANCE,
				  my_realm, 0 /*kvno*/,
				  srvtab_file, serv_key);
	if (retval != KSUCCESS) {
	    syslog(LOG_ERR, "get_tgt: read_service_key: %s",
		   krb_get_err_text(retval));
	    return 1;
	}
	s = (Sched *) check_key_sched_cache(serv_key);
	if (s) {
	    serv_ksched = *s;
	} else {
	    des_key_sched(serv_key, serv_ksched.s);
	    add_to_key_sched_cache(serv_key, &serv_ksched);
	}
#endif /* !NOENCRYPTION */
    }
    return(0);
}
#endif /* ZEPHYR_USES_KERBEROS */

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
	close(bdump_socket);
	nfds = srv_socket + 1;
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
 * Start receiving instruction notices from the brain dump socket
 */
 
static Code_t
bdump_recv_loop(server)
    Server *server;
{
    ZNotice_t notice;
    ZPacket_t packet;
    int len;
    Code_t retval;
    Client *client = NULL;
    struct sockaddr_in who;
#ifdef ZEPHYR_USES_KERBEROS
    char *cp;
    C_Block cblock;
#endif /* ZEPHYR_USES_KERBEROS */
 
#if 1
    zdbug((LOG_DEBUG, "bdump recv loop"));
#endif
	
    /* do the inverse of bdump_send_loop, registering stuff on the fly */
    while (1) {
	if (packets_waiting())
	    handle_packet();
	len = sizeof(packet);
	retval = get_packet(packet, len, &len);
	if (retval != ZERR_NONE) {
	    syslog(LOG_ERR, "brl get pkt: %s", error_message(retval));
	    return retval;
	}

	retval = ZParseNotice(packet, len, &notice);
	if (retval != ZERR_NONE) {
	    syslog(LOG_ERR, "brl notice parse: %s", error_message(retval));
	    return retval;
	}
#if defined (DEBUG)
	if (zdebug) {
	    char buf[4096];

	    sprintf(buf, "bdump:%s '%s' '%s' '%s' '%s' '%s'",
		    ZNoticeKinds[(int) notice.z_kind], notice.z_class,
		    notice.z_class_inst, notice.z_opcode, notice.z_sender,
		    notice.z_recipient);
	    syslog(LOG_DEBUG, buf);
	}
#endif /* DEBUG */
	if (notice.z_num_other_fields >= 1) {
	    retval = ZReadAscii(notice.z_other_fields[0],
				strlen(notice.z_other_fields[0]),
				(unsigned char *) &who.sin_addr,
				sizeof(struct in_addr));
	    if (retval != ZERR_NONE) {
		syslog(LOG_ERR, "brl zreadascii failed: %s",
		       error_message(retval));
		return retval;
	    }
	} else {
	    who.sin_addr.s_addr = notice.z_sender_addr.s_addr;
	}
	who.sin_family = AF_INET;
	who.sin_port = notice.z_port;

	if (strcmp(notice.z_opcode, ADMIN_DONE) == 0) {
	    /* end of brain dump */
	    return ZERR_NONE;
	} else if (strcmp(notice.z_class, LOGIN_CLASS) == 0) {
	    /* 1 = tell it we are authentic */
	    retval = ulogin_dispatch(&notice, 1, &who, server);
	    if (retval != ZERR_NONE) {
		syslog(LOG_ERR, "brl ul_disp failed: %s",
		       error_message(retval));
		return retval;
	    }
	} else if (strcmp(notice.z_opcode, ADMIN_NEWCLT) == 0) {
	    /* a new client */
	    notice.z_port = htons((u_short) atoi(notice.z_message));
	    retval = client_register(&notice, &who.sin_addr, &client, 0);
	    if (retval != ZERR_NONE) {
		syslog(LOG_ERR,"brl failed: %s", error_message(retval));
		return retval;
	    }
#ifdef ZEPHYR_USES_KERBEROS
	    memset(client->session_key, 0, sizeof(C_Block));
	    if (*notice.z_class_inst) {
		/* a C_Block is there */
		cp = notice.z_message + strlen(notice.z_message) + 1;
		retval = ZReadAscii(cp, strlen(cp), cblock, sizeof(C_Block));
		if (retval != ZERR_NONE) {
		    syslog(LOG_ERR,"brl bad cblk read: %s (%s)",
			   error_message(retval), cp);
		} else {
#ifdef NOENCRYPTION
		    memcpy(cblock, client->session_key, sizeof(C_Block));
#else
		    des_ecb_encrypt(cblock, client->session_key, serv_ksched.s,
				    DES_DECRYPT);
#endif
		}
	    }
#endif /* ZEPHYR_USES_KERBEROS */
	} else if (strcmp(notice.z_opcode, CLIENT_SUBSCRIBE) == 0) { 
	    /* a subscription packet */
	    if (!client) {
		syslog(LOG_ERR, "brl no client");
		return ZSRV_NOCLT;
	    }
	    retval = subscr_subscribe(client, &notice);
	    if (retval != ZERR_NONE) {
		syslog(LOG_WARNING, "brl subscr failed: %s",
		       error_message(retval));
		return retval;
	    }
	} else {
	    syslog(LOG_ERR, "brl bad opcode %s",notice.z_opcode);
	    return ZSRV_UNKNOWNOPCODE;
	}
    }
}

/*
 * Send all the state to the peer.
 */

static Code_t
bdump_send_loop(server)
    Server *server;
{
    Code_t retval;

#if 1
    zdbug((LOG_DEBUG, "bdump send loop"));
#endif

    retval = uloc_send_locations();
    if (retval != ZERR_NONE)
	return retval;
    retval = client_send_clients();
    if (retval != ZERR_NONE)
	return retval;
    return send_done();
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
    retval = send_normal_tcp(SERVACK, bdump_sin.sin_port, ZEPHYR_ADMIN_CLASS,
			     "", ADMIN_DONE, myname, "", NULL, 0);
    return retval;
}


/*
 * Send a list off as the specified notice
 */

static Code_t
send_list(kind, port, class_name, inst, opcode, sender, recip, lyst, num)
    ZNotice_Kind_t kind;
    int port, num;
    char *class_name, *inst, *opcode, *sender, *recip, **lyst;
{
    ZNotice_t notice;
    char *pack;
    int packlen;
    Code_t retval;
 
    notice.z_kind = kind;
    notice.z_port = port;
    notice.z_class = class_name;
    notice.z_class_inst = inst;
    notice.z_opcode = opcode;
    notice.z_sender = sender;
    notice.z_recipient = recip;
    notice.z_default_format = "";
    notice.z_num_other_fields = 0;
	
    retval = ZFormatNoticeList(&notice, lyst, num, &pack, &packlen, ZNOAUTH);
    if (retval != ZERR_NONE) {
	syslog(LOG_WARNING, "sl format: %s", error_message(retval));
	return retval;
    }
	
    retval = ZSendPacket(pack, packlen, 0);
    if (retval != ZERR_NONE)
	syslog(LOG_WARNING, "sl xmit: %s", error_message(retval));
    free(pack);
    return retval;
}

/*
 * Send a message off as the specified notice, via TCP
 */

static Code_t
send_normal_tcp(kind, port, class_name, inst, opcode, sender, recip,
		message, len)
    ZNotice_Kind_t kind;
    int port, len;
    char *class_name, *inst, *opcode, *sender, *recip, *message;
{
    ZNotice_t notice;
    char *pack;
    int packlen, count;
    Code_t retval;
    u_short length;
 
    notice.z_kind = kind;
    notice.z_port = port;
    notice.z_class = class_name;
    notice.z_class_inst = inst;
    notice.z_opcode = opcode;
    notice.z_sender = sender;
    notice.z_recipient = recip;
    notice.z_default_format = "";
    notice.z_message = message;
    notice.z_message_len = len;
    notice.z_num_other_fields = 0;
 
    retval = ZFormatNotice(&notice, &pack, &packlen, ZNOAUTH);
    if (retval != ZERR_NONE) {
	syslog(LOG_WARNING, "sn format: %s", error_message(retval));
	return retval;
    }
 
    length = htons((u_short) packlen);
 
    count = net_write(output, (char *) &length, sizeof(length));
    if (count != sizeof(length)) {
	if (count < 0) {
	    syslog(LOG_WARNING, "snt xmit/len: %m");
	    free(pack);
	    return errno;
	} else {
	    syslog(LOG_WARNING, "snt xmit: %d vs %d",sizeof(length),count);
	    free(pack);
	    return ZSRV_LEN;
	}
    }
    count = net_write(output, pack, packlen);
    if (count != packlen) {
	if (count < 0) {
	    syslog(LOG_WARNING, "snt xmit: %m");
	    free(pack);
	    return errno;
	} else {
	    syslog(LOG_WARNING, "snt xmit: %d vs %d",packlen, count);
	    free(pack);
	    return ZSRV_LEN;
	}
    }
    free(pack);
    return ZERR_NONE;
}

/*
 * get a packet from the TCP socket
 * return 0 if successful, error code else
 */

static Code_t
get_packet(packet, len, retlen)
    void *packet;
    int len;
    int *retlen;
{
    u_short length;
    int result;
 
    result = net_read(input, (char *) &length, sizeof(u_short));
    if (result < sizeof(short)) {
	if (result < 0) {
	    return errno;
	} else {
	    syslog(LOG_ERR, "get_pkt len: %d vs %d (%m)", result,
		   sizeof(short));
	    return ZSRV_LEN;
	}
    }
	
    length = ntohs(length);
    if (len < length)
	return ZSRV_BUFSHORT;
    result = net_read(input, packet, (int) length);
    if (result < length) {
	if (result < 0) {
	    return errno;
	} else {
	    syslog(LOG_ERR, "get_pkt: %d vs %d (%m)", result, length);
	    return ZSRV_LEN;
	}
    }
    *retlen = length;
    return ZERR_NONE;
}

static Code_t
extract_sin(notice, target)
    ZNotice_t *notice;
    struct sockaddr_in *target;
{
    char *cp = notice->z_message;
    char *buf;

    buf = cp;
    if (!notice->z_message_len || *buf == '\0') {
#if 0
	zdbug((LOG_DEBUG,"no addr"));
#endif
	return ZSRV_PKSHORT;
    }
    target->sin_addr.s_addr = inet_addr(cp);
 
    cp += (strlen(cp) + 1);	/* past the null */
    if ((cp >= notice->z_message + notice->z_message_len) || (*cp == '\0')) {
#if 0
	zdbug((LOG_DEBUG, "no port"));
#endif
	return(ZSRV_PKSHORT);
    }
    target->sin_port = htons((u_short) atoi(cp));
    target->sin_family = AF_INET;
    return ZERR_NONE;
}

static int
net_read(f, buf, len)
    FILE *f;
    char *buf;
    int len;
{
    int cc, len2 = 0;
 
    fflush (output);
    do {
	errno = 0;
	cc = fread(buf, 1, len, f);
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
    char *buf;
    int len;
{
    int cc;
    int wrlen = len;
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
