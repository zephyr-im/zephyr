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

#ifndef lint
static const char rcsid_bdump_c[] = "$Id$";
#endif /* lint */

#ifndef MIN
#define MIN(x, y)               ((x) < (y) ? (x) : (y))
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

static void close_bdump(void* arg);
static Code_t bdump_send_loop(Server *server);
static Code_t bdump_recv_loop(Server *server);
static void bdump_get_v12(ZNotice_t *, int, struct sockaddr_in *,
			       Server *);
static Code_t get_packet(char **packet, int *len, int *retlen);
static Code_t extract_sin(ZNotice_t *notice, struct sockaddr_in *target);
static Code_t send_done(void);
static Code_t send_list(ZNotice_Kind_t kind, int port, char *class_name,
			     char *inst, char *opcode, char *sender,
			     char *recip, char **lyst, int num);
static Code_t send_normal_tcp(ZNotice_Kind_t kind, int port,
				   char *class_name,
				   char *inst, char *opcode, char *sender,
				   char *recip, char *message, int len);
static int net_read(FILE *f, char *buf, int len);
static int net_write(FILE *f, char *buf, int len);
static int setup_file_pointers(void);
static void shutdown_file_pointers(void);
static void cleanup(Server *server);
static Code_t transmit_tcp(char *pack, int packlen);

#ifdef HAVE_KRB5
static int des_service_decrypt(unsigned char *in, unsigned char *out);
#endif
#ifdef HAVE_KRB5
static long ticket5_time;
#define TKT5LIFETIME 8*60*60
#define tkt5_lifetime(val) (val)
#endif

#ifdef HAVE_KRB5
krb5_keyblock	*server_key;
#endif

static Timer *bdump_timer;
static int live_socket = -1;
static FILE *input, *output;
static struct sockaddr_in bdump_sin;
#ifdef HAVE_KRB5
static krb5_auth_context bdump_ac;
#endif
static Z_AuthProc bdump_auth_proc;

int bdumping;
int bdump_concurrent;

/*
 * Functions for performing a brain dump between servers.
 */

/*
 * offer the brain dump to another server
 */

void
bdump_offer(struct sockaddr_in *who)
{
    Code_t retval;
    char buf[512], *addr, *lyst[2];
#ifndef HAVE_KRB5
    int bdump_port = IPPORT_RESERVED - 1;
#endif /* !HAVE_KRB5 */

    zdbug((LOG_DEBUG, "bdump_offer"));

#ifdef HAVE_KRB5
    /*
     * when using kerberos server-server authentication, we can
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
	unsigned int len = sizeof(bdump_sin);

	if (getsockname(bdump_socket,
			(struct sockaddr *) &bdump_sin, &len) < 0) {
	    syslog(LOG_ERR, "bdump_offer: getsockname: %m");
	    close(bdump_socket);
	    bdump_socket = -1;
	    return;
	}
    }
#else  /* !HAVE_KRB5 */
    /*
     * when not using HAVE_KRB5, we can't use any old port, we use
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
#endif				/* HAVE_KRB5 */

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
    /* bdump_version, which is set in global.c */
    send_list(ACKED, srv_addr.sin_port, ZEPHYR_ADMIN_CLASS, bdump_version,
	      ADMIN_BDUMP, myname, "", lyst, 2);

    zdbug((LOG_DEBUG,"bdump_offer: address is %s/%d\n",
	   inet_ntoa(bdump_sin.sin_addr),
	   ntohs(bdump_sin.sin_port)));
    return;
}

/*
 * Accept a connection, and send the brain dump to the other server
 */

void
bdump_send(void)
{
    struct sockaddr_in from;
    Server *server;
    Code_t retval;
    unsigned int fromlen = sizeof(from);
    int on = 1;
#ifdef _POSIX_VERSION
    struct sigaction action;
#endif
#ifdef HAVE_KRB5
    char *data = NULL;
    int len = 0;
    int proto = 0;
#endif
#ifdef HAVE_KRB5
    /* may be moved into kstuff.c */
    krb5_principal principal;
    krb5_data k5data;
    krb5_keytab kt;
#endif
#ifndef HAVE_KRB5
    unsigned short fromport;
#endif /* HAVE_KRB5 */

    zdbug((LOG_DEBUG, "bdump_send"));

    /* accept the connection, and send the brain dump */
    live_socket = accept(bdump_socket, (struct sockaddr *) &from, &fromlen);
    if (live_socket < 0) {
	syslog(LOG_ERR,"bdump_send: accept: %m");
	return;
    }
    if (setsockopt(live_socket, SOL_SOCKET, SO_KEEPALIVE, (char *) &on,
		   sizeof(on)) < 0)
	syslog(LOG_WARNING, "bdump_send: setsockopt (SO_KEEPALIVE): %m");

#ifndef HAVE_KRB5
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

    zdbug((LOG_INFO, "bdump_send: connection from %s/%d",
	   inet_ntoa(from.sin_addr), ntohs(from.sin_port)));

    bdumping = 1;
    server->dumping = 1;
    bdump_auth_proc = ZNOAUTH;

    if (bdump_socket >= 0) {
	/* shut down the listening socket and the timer. */
	FD_CLR(bdump_socket, &interesting);
	close(bdump_socket);
	nfds = srv_socket + 1;
	bdump_socket = -1;
	timer_reset(bdump_timer);
    }

    /* Now begin the brain dump. */
#ifdef HAVE_KRB5
    retval = ReadKerberosData(live_socket, &len, &data, &proto);

    if (retval != 0) {
	syslog(LOG_ERR, "bdump_send: ReadKerberosData: %s",
	       error_message(retval));
	cleanup(server);
	return;
    }

    syslog(LOG_DEBUG, "bdump_send: got %d bytes of authenticator for protocol %d", len, proto);

    if (get_tgt()) {
	syslog(LOG_ERR, "bdump_send: get_tgt failed");
	cleanup(server);
	return;
    }

    switch(proto) {
#ifdef HAVE_KRB5
    case 5:
	/* "server" side */
	retval = krb5_build_principal(Z_krb5_ctx, &principal,
				      strlen(ZGetRealm()),
				      ZGetRealm(),
				      SERVER_KRB5_SERVICE, SERVER_INSTANCE,
				      NULL);
	if (retval) {
	    syslog(LOG_ERR, "bdump_send: krb5_build_principal: %s",
		   error_message(retval));
	    cleanup(server);
	    return;
	}


	retval = krb5_auth_con_init(Z_krb5_ctx, &bdump_ac);
	if (retval) {
	    syslog(LOG_ERR, "bdump_send: krb5_auth_con_init: %s",
		   error_message(retval));
	    cleanup(server);
	    return;
	}

	retval = krb5_auth_con_setflags(Z_krb5_ctx, bdump_ac,
					KRB5_AUTH_CONTEXT_DO_SEQUENCE);
	if (retval) {
	    syslog(LOG_ERR, "bdump_send: krb5_auth_con_setflags: %s",
		   error_message(retval));
	    cleanup(server);
	    return;
	}

	retval = krb5_auth_con_genaddrs(Z_krb5_ctx, bdump_ac, live_socket,
                                       KRB5_AUTH_CONTEXT_GENERATE_LOCAL_FULL_ADDR|KRB5_AUTH_CONTEXT_GENERATE_REMOTE_FULL_ADDR);
	if (retval) {
	    syslog(LOG_ERR, "bdump_send: krb5_auth_con_genaddrs: %s", error_message(retval));
	    cleanup(server);
	    return;
	}

	/* Get the "client" krb_ap_req */

	memset((char *)&k5data, 0, sizeof(krb5_data));
	k5data.length = len;
	k5data.data = data;

	/* resolve keytab */
	retval = krb5_kt_resolve(Z_krb5_ctx, keytab_file, &kt);
	if (retval) {
	    syslog(LOG_ERR, "bdump_send: cannot resolve keytab: %s",
		   error_message(retval));
	    krb5_kt_close(Z_krb5_ctx, kt);
	    cleanup(server);
	    return;
	}

	retval = krb5_rd_req(Z_krb5_ctx, &bdump_ac, &k5data, principal, kt, NULL, NULL);
	krb5_free_principal(Z_krb5_ctx, principal);
	krb5_kt_close(Z_krb5_ctx, kt);
	free(k5data.data);
	memset((char *)&k5data, 0, sizeof(krb5_data));
	if (retval) {
	     syslog(LOG_ERR, "bdump_send: mutual authentication failed: %s",
	            error_message(retval));
	     cleanup(server);
	     return;
	}

	/* Now send back our auth packet */

	retval = krb5_mk_rep(Z_krb5_ctx, bdump_ac, &k5data);
	if (retval) {
	    syslog(LOG_ERR, "bdump_send: krb5_mk_rep: %s", error_message(retval));
	    cleanup(server);
	    return;
	}
	retval = SendKrb5Data(live_socket, &k5data);
	if (retval) {
	     syslog(LOG_ERR, "bdump_send: cannot send authenticator: %s",
	            error_message(retval));
	     krb5_free_data_contents(Z_krb5_ctx, &k5data);
	     cleanup(server);
	     return;
	}
	krb5_free_data_contents(Z_krb5_ctx, &k5data);
	break;
#endif  /* HAVE_KRB5 */
    }
#else /* HAVE_KRB5 */
    if (fromport > IPPORT_RESERVED || fromport < IPPORT_RESERVED / 2) {
	syslog(LOG_ERR, "bdump_send: bad port from peer: %d", fromport);
	cleanup(server);
	return;
    }
#endif /* HAVE_KRB5 */
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

    zdbug((LOG_DEBUG, "bdump_send: finished"));

    if (server != limbo_server) {
	/* set this guy to be up, and schedule a hello */
	server->state = SERV_UP;
	timer_reset(server->timer);
	server->timer = timer_set_rel(0L, server_timo, server);
    }

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
bdump_get_v12 (ZNotice_t *notice,
	       int auth,
	       struct sockaddr_in *who,
	       Server *server)
{
    struct sockaddr_in from;
    Code_t retval;
    int on = 1;
#ifdef _POSIX_VERSION
    struct sigaction action;
#endif
#ifdef HAVE_KRB5
#ifdef HAVE_KRB5
    krb5_creds creds;
    krb5_creds *credsp;
    krb5_principal principal;
    krb5_data data;
    krb5_ap_rep_enc_part *rep;
#endif
#else  /* !HAVE_KRB5 */
    int reserved_port = IPPORT_RESERVED - 1;
#endif /* !HAVE_KRB5 */

    bdumping = 1;
    server->dumping = 1;
    bdump_auth_proc = ZNOAUTH;

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
#ifndef HAVE_KRB5
    if (ntohs(from.sin_port) > IPPORT_RESERVED ||
	ntohs(from.sin_port) < IPPORT_RESERVED / 2) {
	syslog(LOG_ERR, "bdump_get: port not reserved: %d",
	       ntohs(from.sin_port));
	cleanup(server);
	return;
    }
    live_socket = rresvport(&reserved_port);
#else  /* !HAVE_KRB5 */
    live_socket = socket(AF_INET, SOCK_STREAM, 0);
#endif /* !HAVE_KRB5 */
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

    zdbug((LOG_DEBUG, "bdump_get: connected"));

    /* Now begin the brain dump. */
#ifdef HAVE_KRB5
    if (get_tgt()) {
	syslog(LOG_ERR, "bdump_get: get_tgt failed");
	cleanup(server);
	return;
    }
    switch(bdump_auth_proto) {
#ifdef HAVE_KRB5
    case 5: /* "client" side */
 	memset((char *)&creds, 0, sizeof(creds));

	retval = krb5_build_principal(Z_krb5_ctx, &principal,
				      strlen(ZGetRealm()),
				      ZGetRealm(),
				      SERVER_KRB5_SERVICE, SERVER_INSTANCE,
				      NULL);
	if (retval) {
	    syslog(LOG_ERR, "bdump_get: krb5_build_principal: %s",
		   error_message(retval));
	    cleanup(server);
	    return;
	}

	retval = krb5_copy_principal(Z_krb5_ctx, principal, &creds.server);
	if (retval) {
	    syslog(LOG_ERR, "bdump_get: krb5_copy_principal (server): %s",
		   error_message(retval));
	    krb5_free_principal(Z_krb5_ctx, principal);
	    cleanup(server);
	    return;
	}

	retval = krb5_copy_principal(Z_krb5_ctx, principal, &creds.client);
	krb5_free_principal(Z_krb5_ctx, principal);
	if (retval) {
	    syslog(LOG_ERR, "bdump_get: krb5_copy_principal (client): %s",
		   error_message(retval));
	    krb5_free_cred_contents(Z_krb5_ctx, &creds);
	    cleanup(server);
	    return;
	}

	retval = krb5_get_credentials(Z_krb5_ctx, 0, Z_krb5_ccache,
				      &creds, &credsp);
	krb5_free_cred_contents(Z_krb5_ctx, &creds);
	if (retval) {
	    syslog(LOG_ERR, "bdump_get: krb5_get_credentials: %s", error_message(retval));
	    cleanup(server);
	    return;
	}

	retval = krb5_auth_con_init(Z_krb5_ctx, &bdump_ac);
	if (retval) {
	    syslog(LOG_ERR, "bdump_get: krb5_auth_con_init: %s", error_message(retval));
	    krb5_free_creds(Z_krb5_ctx, credsp);
	    cleanup(server);
	    return;
	}

	retval = krb5_auth_con_setflags(Z_krb5_ctx, bdump_ac, KRB5_AUTH_CONTEXT_DO_SEQUENCE);
	if (retval) {
	    syslog(LOG_ERR, "bdump_get: krb5_auth_con_setflags: %s", error_message(retval));
	    krb5_free_creds(Z_krb5_ctx, credsp);
	    cleanup(server);
	    return;
	}

	retval = krb5_auth_con_genaddrs(Z_krb5_ctx, bdump_ac, live_socket,
		KRB5_AUTH_CONTEXT_GENERATE_LOCAL_FULL_ADDR|KRB5_AUTH_CONTEXT_GENERATE_REMOTE_FULL_ADDR);
	if (retval) {
	    syslog(LOG_ERR, "bdump_get: krb5_auth_con_genaddrs: %s", error_message(retval));
	    krb5_free_creds(Z_krb5_ctx, credsp);
	    cleanup(server);
	    return;
	}

	memset((char *)&data, 0, sizeof(krb5_data));
	retval = krb5_mk_req_extended(Z_krb5_ctx, &bdump_ac, AP_OPTS_MUTUAL_REQUIRED|AP_OPTS_USE_SUBKEY,
				 NULL, credsp, &data);
	if (retval) {
	    syslog(LOG_ERR, "bdump_get: krb5_mk_req_ext: %s", error_message(retval));
	    krb5_free_creds(Z_krb5_ctx, credsp);
	    cleanup(server);
	    return;
	}
        retval = SendKrb5Data(live_socket, &data);
        krb5_free_creds(Z_krb5_ctx, credsp);
        if (retval) {
             syslog(LOG_ERR, "bdump_get: cannot send authenticator: %s",
                    error_message(retval));
             krb5_free_data_contents(Z_krb5_ctx, &data);
             cleanup(server);
             return;
        }
        krb5_free_data_contents(Z_krb5_ctx, &data);
	memset((char *)&data, 0, sizeof(krb5_data));
        retval = GetKrb5Data(live_socket, &data);
        if (retval) {
             syslog(LOG_ERR, "bdump_get: cannot get auth response: %s",
                    error_message(retval));
             cleanup(server);
             return;
        }
        retval = krb5_rd_rep(Z_krb5_ctx, bdump_ac, &data, &rep);
        free(data.data);
        memset((char *)&data, 0, sizeof(krb5_data));
        if (retval) {
             syslog(LOG_ERR, "bdump_get: mutual authentication failed: %s",
                    error_message(retval));
             cleanup(server);
             return;
        }
	break;
#endif
    }
#endif /* defined(HAVE_KRB5) */
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
    zdbug((LOG_DEBUG,"bdump_get: gbdl ok"));
    retval = bdump_send_loop(server);
    if (retval != ZERR_NONE) {
	syslog(LOG_WARNING, "bdump_send_loop failed: %s",
	       error_message(retval));
	cleanup(server);
	return;
    }

    zdbug((LOG_DEBUG, "bdump_get: gbd finished"));

    /* set this guy to be up, and schedule a hello */
    server->state = SERV_UP;
    timer_reset(server->timer);
    server->timer = timer_set_rel(0L, server_timo, server);


    zdbug((LOG_DEBUG,"cleanup gbd"));

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
bdump_get(ZNotice_t *notice,
	  int auth,
	  struct sockaddr_in *who,
	  Server *server)
{
    void (*proc)(ZNotice_t *, int, struct sockaddr_in *, Server *);

    proc = NULL;

    if (zdebug) {
	syslog(LOG_DEBUG, "bdump_get: bdump v%s avail %s",
	       notice->z_class_inst, inet_ntoa(who->sin_addr));
    }

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
 * Send off a packet via tcp
 */
static Code_t
transmit_tcp(char *pack, int packlen)
{
    Code_t retval = ZERR_NONE;
    u_short length;
    int count;
#ifdef HAVE_KRB5
    krb5_data indata, outmsg;
#endif
    /* output and bdump_ac are globals */

    if (packlen > Z_MAXPKTLEN) {
	syslog(LOG_ERR, "transmit_tcp: packet is too large (%d bytes)", packlen);
	return ZERR_PKTLEN;
    }

#ifdef HAVE_KRB5
    if (bdump_ac) {
        indata.length = packlen;
        indata.data = pack;
        memset(&outmsg, 0, sizeof(krb5_data));

        retval = krb5_mk_priv(Z_krb5_ctx, bdump_ac, &indata, &outmsg, NULL);

        if (retval != ZERR_NONE)
	    goto cleanup;

        packlen = outmsg.length;
        pack = outmsg.data;
    }
#endif
    length = htons((unsigned short) packlen);

    count = net_write(output, (char *) &length, sizeof(length));
    if (count != sizeof(length)) {
	if (count < 0) {
	    syslog(LOG_WARNING, "transmit_tcp: writing length: %m");
	    retval = errno;
	} else {
	    syslog(LOG_WARNING, "transmit_tcp: writing length: %lu vs %d",
		   (unsigned long)sizeof(length), count);
	    retval = ZSRV_LEN;
	}
	goto cleanup;
    }
    count = net_write(output, pack, packlen);
    if (count != packlen) {
	if (count < 0) {
	    syslog(LOG_WARNING, "transmit_tcp: writing data: %m");
	    retval = errno;
	} else {
	    syslog(LOG_WARNING, "transmit_tcp: writing data: %d vs %d", packlen, count);
	    retval = ZSRV_LEN;
	}
	goto cleanup;
    }

 cleanup:
#ifdef HAVE_KRB5
    if (bdump_ac)
	krb5_free_data_contents(Z_krb5_ctx, &outmsg);
#endif

    return retval;
}

/*
 * Send a list off as the specified notice
 */

Code_t
bdump_send_list_tcp(ZNotice_Kind_t kind,
		    struct sockaddr_in *addr,
		    char *class_name,
		    char *inst,
		    char *opcode,
		    char *sender,
		    char *recip,
		    char **lyst,
		    int num)
{
    ZNotice_t notice;
    char *pack;
    int packlen;
    Code_t retval;

    memset (&notice, 0, sizeof(notice));

    notice.z_kind = kind;

    notice.z_port = addr->sin_port;
    notice.z_class = class_name;
    notice.z_class_inst = inst;
    notice.z_opcode = opcode;
    notice.z_sender = sender;
    notice.z_recipient = recip;
    notice.z_default_format = "";
    notice.z_num_other_fields = 0;
    if (addr)
	notice.z_sender_sockaddr.ip4 = *addr; /*XXX*/

    retval = ZFormatNoticeList(&notice, lyst, num, &pack, &packlen,
			       bdump_auth_proc);
    if (retval != ZERR_NONE) {
	syslog(LOG_ERR, "bdump_send_list_tcp: ZFormatNotice: %s", error_message(retval));
	return retval;
    }

    retval = transmit_tcp(pack, packlen);
    free(pack);
    if (retval != ZERR_NONE)
	syslog(LOG_ERR, "bdump_send_list_tcp: transmit_tcp: %s", error_message(retval));

    return retval;
}

static void
shutdown_file_pointers(void)
{
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
#ifdef HAVE_KRB5
	if (bdump_ac)
		krb5_auth_con_free(Z_krb5_ctx, bdump_ac);
	bdump_ac = NULL;
#endif
    }
}

static void
cleanup(Server *server)
{
#ifdef _POSIX_VERSION
    struct sigaction action;
#endif

    zdbug((LOG_DEBUG, "bdump cleanup"));

    if (server != limbo_server) {
	if (server->state != SERV_STARTING)
	    server->state = SERV_DEAD;
	timer_reset(server->timer);
	server->timer = timer_set_rel(server->timeout, server_timo, server);
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

#ifdef HAVE_KRB5

int got_des = 0;

unsigned int enctypes[] = {ENCTYPE_DES_CBC_CRC,
			   ENCTYPE_DES_CBC_MD4,
			   ENCTYPE_DES_CBC_MD5,
#ifdef ENCTYPE_DES_CBC_RAW
			   ENCTYPE_DES_CBC_RAW,
#endif
			   0};


int
get_tgt(void)
{
    int retval = 0;
    int i;
    krb5_keytab_entry kt_ent;
#ifdef HAVE_KRB5
    /* XXX */
    if (ticket5_time < NOW - tkt5_lifetime(TKT5LIFETIME) + (15L * 60L)) {
	krb5_keytab kt;
	krb5_get_init_creds_opt opt;
	krb5_creds cred;
	krb5_principal principal;

	memset(&cred, 0, sizeof(cred));

	retval = krb5_build_principal(Z_krb5_ctx, &principal,
				      strlen(ZGetRealm()),
				      ZGetRealm(),
				      SERVER_KRB5_SERVICE, SERVER_INSTANCE,
				      NULL);
	if (retval) {
	    syslog(LOG_ERR, "get_tgt: krb5_build_principal: %s",
		   error_message(retval));
	    return 1;
	}

	krb5_get_init_creds_opt_init (&opt);
	krb5_get_init_creds_opt_set_tkt_life (&opt, TKT5LIFETIME);

	retval = krb5_kt_resolve(Z_krb5_ctx, keytab_file, &kt);
	if (retval) {
	    syslog(LOG_ERR, "get_tgt: krb5_kt_resolve: %s",
		   error_message(retval));
	    krb5_free_principal(Z_krb5_ctx, principal);
	    return 1;
	}

	retval = krb5_get_init_creds_keytab (Z_krb5_ctx,
					     &cred,
					     principal,
					     kt,
					     0,
					     NULL,
					     &opt);
	if (retval) {
	    syslog(LOG_ERR, "get_tgt: krb5_get_init_creds_keytab: %s",
		   error_message(retval));
	    krb5_free_principal(Z_krb5_ctx, principal);
	    krb5_kt_close(Z_krb5_ctx, kt);
	    return 1;
	}

	for (i = 0; enctypes[i]; i++) {
	    retval = krb5_kt_get_entry(Z_krb5_ctx, kt, principal,
				       0, enctypes[i], &kt_ent);
	    if (!retval)
		break;
	}
	if (!retval) {
#ifdef HAVE_KRB5_CRYPTO_INIT
	    retval = krb5_copy_keyblock(Z_krb5_ctx, &kt_ent.keyblock,
					&server_key);
#else
	    retval = krb5_copy_keyblock(Z_krb5_ctx, &kt_ent.key, &server_key);
#endif
	    if (retval) {
		syslog(LOG_ERR, "get_tgt: krb5_copy_keyblock: %s",
		       error_message(retval));
		krb5_free_principal(Z_krb5_ctx, principal);
		krb5_kt_close(Z_krb5_ctx, kt);
		return 1;
	    }

	    got_des = 1;
	}
	krb5_free_principal(Z_krb5_ctx, principal);
	krb5_kt_close(Z_krb5_ctx, kt);

	retval = krb5_cc_initialize (Z_krb5_ctx, Z_krb5_ccache, cred.client);
	if (retval) {
	    syslog(LOG_ERR, "get_tgt: krb5_cc_initialize: %s",
		   error_message(retval));
	    return 1;
	}

	retval = krb5_cc_store_cred (Z_krb5_ctx, Z_krb5_ccache, &cred);
	if (retval) {
	    syslog(LOG_ERR, "get_tgt: krb5_cc_store_cred: %s",
		   error_message(retval));
	    return 1;
	}

	ticket5_time = NOW;

	krb5_free_cred_contents (Z_krb5_ctx, &cred);
    }
#endif
    return 0;
}
#endif /* HAVE_KRB5 */

/*
 * The braindump offer wasn't taken, so we retract it.
 */

/*ARGSUSED*/
static void
close_bdump(void *arg)
{
    if (bdump_socket >= 0) {
	FD_CLR(bdump_socket, &interesting);
	close(bdump_socket);
	nfds = srv_socket + 1;
	bdump_socket = -1;

	zdbug((LOG_DEBUG, "bdump not used"));
    } else {
	zdbug((LOG_DEBUG, "bdump not open"));
    }
    return;
}

/*
 * Start receiving instruction notices from the brain dump socket
 */

static Code_t
bdump_recv_loop(Server *server)
{
    ZNotice_t notice;
    char *packet = NULL;
    int len;
    int pblen = Z_MAXPKTLEN;
    Code_t retval;
    Client *client = NULL;
    struct sockaddr_in who;
#ifdef HAVE_KRB5
    uint32_t client_enctype;
    uint32_t client_keysize;
    unsigned char buf[512];
    int blen;
#endif
#ifdef HAVE_KRB5
    char *cp;
    unsigned char cblock[8];
#endif
    ZRealm *realm = NULL;

    zdbug((LOG_DEBUG, "bdump_recv_loop"));

    packet = malloc(Z_MAXPKTLEN);

    if (packet == NULL)
	return ENOMEM;

    /* do the inverse of bdump_send_loop, registering stuff on the fly */
    while (1) {
	if (packets_waiting()) {
	    /* A non-braindump packet is waiting; handle it. */
	    bdumping = 0;
	    bdump_concurrent = 1;
	    handle_packet();
	    bdump_concurrent = 0;
	    bdumping = 1;
	}
	len = sizeof(packet);
	retval = get_packet(&packet, &pblen, &len);
	if (retval != ZERR_NONE) {
	    syslog(LOG_ERR, "bdump_recv_loop: get_packet failed: %s", error_message(retval));
	    free(packet);
	    return retval;
	}

#if HAVE_KRB5
	if (bdump_ac) {
	    krb5_data in, out;
	    in.length = len;
	    in.data = packet;
	    memset(&out, 0, sizeof(krb5_data));
	    retval = krb5_rd_priv(Z_krb5_ctx, bdump_ac, &in, &out, NULL);
	    if (retval != ZERR_NONE) {
	        syslog(LOG_ERR, "bdump_recv_loop: krb5_rd_priv failed: %s", error_message(retval));
		free(packet);
	        return retval;
	    }
	    memcpy(packet, out.data, out.length);
	    len = out.length;
	    krb5_free_data_contents(Z_krb5_ctx, &out);
	}
#endif

	retval = ZParseNotice(packet, len, &notice);
	if (retval != ZERR_NONE) {
	    syslog(LOG_ERR, "bdump_recv_loop: ZParseNotice failed: %s", error_message(retval));
	    free(packet);
	    return retval;
	}
#if defined (DEBUG)
	if (zdebug) {
	    syslog(LOG_DEBUG, "bdump_recv_loop: %s '%s' '%s' '%s' '%s' '%s'",
		   ZNoticeKinds[(int) notice.z_kind], notice.z_class,
		   notice.z_class_inst, notice.z_opcode, notice.z_sender,
		   notice.z_recipient);
	}
#endif /* DEBUG */
	who.sin_family = AF_INET; /*XXX*/
	who.sin_addr.s_addr = notice.z_sender_sockaddr.ip4.sin_addr.s_addr;
	who.sin_port = notice.z_port;

	if (strcmp(notice.z_opcode, ADMIN_DONE) == 0) {
	    /* end of brain dump */
	    free(packet);
	    return ZERR_NONE;
	} else if (strcmp(notice.z_opcode, ADMIN_NEWREALM) == 0) {
	    /* get a realm from the message */
	    realm = realm_get_realm_by_name(notice.z_message);
	    if (!realm) {
		syslog(LOG_ERR, "bdump_recv_loop: realm_get_realm_by_name failed: no realm %s",
		       notice.z_message);
	    }
	} else if (strcmp(notice.z_class, LOGIN_CLASS) == 0) {
	    /* 1 = tell it we are authentic */
	    retval = ulogin_dispatch(&notice, 1, &who, server);
	    if (retval != ZERR_NONE) {
		syslog(LOG_ERR, "bdump_recv_loop: ulogin_dispatch failed: %s",
		       error_message(retval));
		free(packet);
		return retval;
	    }
	} else if (strcmp(notice.z_opcode, ADMIN_NEWCLT) == 0) {
	    /* a new client */
	    notice.z_port = htons((u_short) atoi(notice.z_message));
	    retval = client_register(&notice, &who.sin_addr, &client, 0);
	    if (retval != ZERR_NONE) {
		syslog(LOG_ERR,"bdump_recv_loop: client_register failed: %s", error_message(retval));
		free(packet);
		return retval;
	    }
#ifdef HAVE_KRB5
	    client->session_keyblock = NULL;
	    if (*notice.z_class_inst) {
		/* check out this session key I found */
		cp = notice.z_message + strlen(notice.z_message) + 1;
		if (*cp == '0' && got_des) {
		    /* ****ing netascii; this is an encrypted DES keyblock
		       XXX this code should be conditionalized for server
		       transitions   */
		    retval = Z_krb5_init_keyblock(Z_krb5_ctx, ENCTYPE_DES_CBC_CRC,
						  sizeof(cblock),
						  &client->session_keyblock);
		    if (retval) {
			syslog(LOG_ERR, "bdump_recv_loop: failed to allocate DES keyblock: %s",
			       error_message(retval));
			free(packet);
			return retval;
		    }
		    retval = ZReadAscii(cp, strlen(cp), cblock, sizeof(cblock));
		    if (retval != ZERR_NONE) {
			syslog(LOG_ERR,"bdump_recv_loop: bad cblock read: %s (%s)",
			       error_message(retval), cp);
		    } else {
			retval = des_service_decrypt(cblock, Z_keydata(client->session_keyblock));
			if (retval) {
			    syslog(LOG_ERR, "bdump_recv_loop: failed to decyrpt DES session key: %s",
				   error_message(retval));
			    free(packet);
			    return retval;
			}
		    }
		} else if (*cp == 'Z') {
		    /* Zcode! Long live the new flesh! */
		    retval = ZReadZcode((unsigned char *)cp, buf, sizeof(buf), &blen);
		    if (retval != ZERR_NONE) {
			syslog(LOG_ERR,"bdump_recv_loop: bad keyblock read: %s (%s)",
			       error_message(retval), cp);
		    } else {
			memcpy(&client_enctype, &buf[0], sizeof(uint32_t));
			memcpy(&client_keysize, &buf[4], sizeof(uint32_t));
			retval = Z_krb5_init_keyblock(Z_krb5_ctx,
						    ntohl(client_enctype),
						    ntohl(client_keysize),
						    &client->session_keyblock);
			if (retval) {
			    syslog(LOG_ERR, "bdump_recv_loop: failed to allocate keyblock: %s",
				   error_message(retval));
			    free(packet);
			    return retval;
			}
			memcpy(Z_keydata(client->session_keyblock), &buf[8],
			       Z_keylen(client->session_keyblock));
		    }
		}
	    }
#endif
	} else if (strcmp(notice.z_opcode, CLIENT_SUBSCRIBE) == 0) {
	    /* a subscription packet */
	    if (!client) {
		syslog(LOG_ERR, "bdump_recv_loop: no client");
		free(packet);
		return ZSRV_NOCLT;
	    }
	    retval = subscr_subscribe(client, &notice, server);
	    if (retval != ZERR_NONE) {
		syslog(LOG_WARNING, "bdump_recv_loop: subscr_subscribe failed: %s",
		       error_message(retval));
		free(packet);
		return retval;
	    }
	} else if (strcmp(notice.z_opcode, REALM_SUBSCRIBE) == 0) {
	    /* add a subscription for a realm */
	    if (realm) {
		retval = subscr_realm(realm, &notice);
		if (retval != ZERR_NONE) {
		    syslog(LOG_WARNING, "bdump_recv_loop: subscr_realm failed: %s",
			   error_message(retval));
		    free(packet);
		    return retval;
		}
	    } /* else */
		 /* Other side tried to send us subs for a realm we didn't
		    know about, and so we drop them silently */

	} else {
	    syslog(LOG_ERR, "bdump_recv_loop: bad opcode %s",notice.z_opcode);
	    free(packet);
	    return ZSRV_UNKNOWNOPCODE;
	}
    }
}

/*
 * Send all the state to the peer.
 */

static Code_t
bdump_send_loop(Server *server)
{
    Code_t retval;

    zdbug((LOG_DEBUG, "bdump send loop"));

    retval = uloc_send_locations();
    if (retval != ZERR_NONE)
	return retval;
    retval = client_send_clients();
    if (retval != ZERR_NONE)
	return retval;
    retval = realm_send_realms();
    if (retval != ZERR_NONE)
	return retval;
    return send_done();
}

/*
 * Send a sync indicating end of this host
 */

static Code_t
send_done(void)
{
    Code_t retval;

    zdbug((LOG_DEBUG, "send_done"));

    retval = send_normal_tcp(SERVACK, bdump_sin.sin_port, ZEPHYR_ADMIN_CLASS,
			     "", ADMIN_DONE, myname, "", NULL, 0);
    return retval;
}


/*
 * Send a list off as the specified notice
 */

static Code_t
send_list(ZNotice_Kind_t kind,
	  int port,
	  char *class_name,
	  char *inst,
	  char *opcode,
	  char *sender,
	  char *recip,
	  char **lyst,
	  int num)
{
    ZNotice_t notice;
    char *pack;
    int packlen;
    Code_t retval;

    memset (&notice, 0, sizeof(notice));

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
send_normal_tcp(ZNotice_Kind_t kind,
		int port,
		char *class_name,
		char *inst,
		char *opcode,
		char *sender,
		char *recip,
		char *message,
		int len)
{
    ZNotice_t notice;
    char *pack;
    int packlen;
    Code_t retval;

    memset (&notice, 0, sizeof(notice));

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

    retval = ZFormatNotice(&notice, &pack, &packlen, bdump_auth_proc);
    if (retval != ZERR_NONE) {
	syslog(LOG_WARNING, "send_normal_tcp: ZFormatNotice: %s", error_message(retval));
	return retval;
    }

    retval = transmit_tcp(pack, packlen);
    free(pack);
    if (retval != ZERR_NONE)
	syslog(LOG_ERR, "send_normal_tcp: transmit_tcp: %s", error_message(retval));

    return retval;
}

/*
 * get a packet from the TCP socket
 * return 0 if successful, error code else
 */

static Code_t
get_packet(char **packet, int *buflen, int *retlen)
{
    unsigned short length;
    int result;
    char *p;

    result = net_read(input, (char *) &length, sizeof(unsigned short));
    if (result < (int)sizeof(short)) {
	if (result < 0) {
	    return errno;
	} else {
	    syslog(LOG_ERR, "get_packet: received length: %d vs %lu (%m)",
		   result, (unsigned long)sizeof(short));
	    return ZSRV_LEN;
	}
    }

    length = ntohs(length);
    if (*buflen < length) {
	p = realloc(*packet, length);
	if (p == NULL) {
	    syslog(LOG_ERR, "get_packet: failed to expand buffer to %d bytes from %d",
		   *buflen, length);
	    return ZSRV_BUFSHORT;
	}
	syslog(LOG_DEBUG, "get_packet: expanded buffer from %d bytes to %d",
	       *buflen, length);
	*buflen = length;
	*packet = p;
    }
    result = net_read(input, *packet, (int) length);
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
extract_sin(ZNotice_t *notice, struct sockaddr_in *target)
{
    char *cp = notice->z_message;
    char *buf;

    buf = cp;
    if (!notice->z_message_len || *buf == '\0') {
	return ZSRV_PKSHORT;
    }
    target->sin_addr.s_addr = inet_addr(cp);

    cp += (strlen(cp) + 1);	/* past the null */
    if ((cp >= notice->z_message + notice->z_message_len) || (*cp == '\0')) {
	return(ZSRV_PKSHORT);
    }
    target->sin_port = htons((unsigned short)atoi(cp));
    target->sin_family = AF_INET;
    return ZERR_NONE;
}

static int
net_read(FILE *f, char *buf, int len)
{
    int cc, len2 = 0;

    fflush (output);
    do {
	errno = 0;
	cc = fread(buf, 1, len, f);
	if (cc == 0)
	  {
	    if (feof(f))
	      return len2;
	    if (errno == 0)
	      errno = EIO;
	    return -1;
	  }
	buf += cc;
	len2 += cc;
	len -= cc;
    } while (len > 0);
    return len2;
}

static int
net_write(FILE *f, char *buf, int len)
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
setup_file_pointers (void)
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

#ifdef HAVE_KRB5
static int des_service_decrypt(unsigned char *in, unsigned char *out) {
    krb5_data dout;
#ifdef HAVE_KRB5_C_DECRYPT
    krb5_enc_data din;

    dout.length = 8;
    dout.data = (char *)out; /*What*/

    din.ciphertext.length = 8;
    din.ciphertext.data = (char *)in;
    din.enctype = Z_enctype(server_key);

#ifdef HAVE_KRB5_CRYPTO_INIT
    return krb5_c_decrypt(Z_krb5_ctx, *server_key, 0, 0, &din, &dout);
#else
    return krb5_c_decrypt(Z_krb5_ctx, server_key, 0, 0, &din, &dout);
#endif
#elif defined(HAVE_KRB5_CRYPTO_INIT)
    int ret;
    krb5_crypto crypto;

    dout.length = 8;
    dout.data = out;

    ret = krb5_crypto_init(Z_krb5_ctx, server_key, Z_enctype(server_key), &crypto);
    if (ret)
	return ret;

    ret = krb5_decrypt_ivec(Z_krb5_ctx, crypto, 0, in, 8, &dout, NULL);

    krb5_crypto_destroy(Z_krb5_ctx, crypto);

    return ret;
#endif
}
#endif
