#ifndef __ZSERVER_H__
#define __ZSERVER_H__
/* This file is part of the Project Athena Zephyr Notification System.
 * It contains declarations for use in the server.
 *
 *	Created by:	John T. Kohl
 *
 *	$Source$
 *	$Author$
 *	$Header$
 *
 *	Copyright (c) 1987,1988 by the Massachusetts Institute of Technology.
 *	For copying and distribution information, see the file
 *	"mit-copyright.h". 
 */

#include <zephyr/mit-copyright.h>

#include <zephyr/zephyr.h>		/* which includes <errno.h>,
					   <sys/types.h>,
					   <netinet/in.h>,
					   <sys/time.h>, 
					   <stdio.h>,
					   <krb.h> */
extern "C" {
#include <arpa/inet.h>
#include <zephyr/acl.h>
#include <sys/file.h>

#include <zephyr/zsyslog.h>

#include <strings.h>
#include <signal.h>
#ifdef lint
#include <sys/uio.h>			/* so it shuts up about struct iovec */
#endif /* lint */
#include "zsrv_err.h"
}

#include "timer.h"
#include "zsrv_conf.h"			/* configuration params */

#include "ZString.h"
#include "access.h"
#include "unix.h"

/* definitions for the Zephyr server */

/* structures */

/*
 * ZDestination: Where is this notice going to?  This includes class,
 * instance, and recipient at the moment.
 */

struct ZDestination {
    unsigned long hash_value;
public:
    ZString classname;
    ZString inst;
    ZString recip;
    void set_hash () {
	hash_value = classname.hash() ^ inst.hash() ^ recip.hash();
    }
    unsigned long hash () {
	return hash_value;
    }
    friend int operator== (const ZDestination&, const ZDestination&);
    ZDestination (const char*, const char* =0, const char* =0);
    ZDestination (const ZString& = null_string,
		  const ZString& = null_string,
		  const ZString& = null_string);
    ZDestination (const ZDestination&);
    ~ZDestination ();
    void print (char *buf);
    static int order_strings (const ZDestination&, const ZDestination&);
#if !defined(__GNUG__) || defined(FIXED_GXX)
    void *operator new (unsigned int sz) { return zalloc (sz); }
    void operator delete (void *ptr) { zfree (ptr, sizeof (ZDestination)); }
#endif
};

const static ZDestination null_destination = 0;

extern int operator== (const ZDestination&, const ZDestination&);

inline int operator != (const ZDestination& z1, const ZDestination& z2) {
    return !(z1 == z2);
}

inline operator< (const ZDestination& z1, const ZDestination& z2) {
    return (z1.hash_value != z2.hash_value
	    ? z1.hash_value < z2.hash_value
	    : ZDestination::order_strings (z1, z2) < 0);
}

inline operator> (const ZDestination& z1, const ZDestination& z2) {
    return (z1 == z2) ? 0 : !(z1 < z2);
}

inline operator >= (const ZDestination& z1, const ZDestination& z2) {
    return !(z1 < z2);
}

struct Notice {
    ZNotice_t *notice;
    ZDestination dest;
    ZString sender;
    int msg_no;
    static int current_msg;
    Notice (ZNotice_t *n) : notice(n), dest(n->z_class, n->z_class_inst, n->z_recipient), sender (n->z_sender) {
	msg_no = current_msg;
    }
};

struct ZSubscr_t {
	ZSubscr_t *q_forw;	/* links in client's subscr. queue */
	ZSubscr_t *q_back;
	ZDestination zst_dest;	/* destination of messages */

	ZSubscr_t (const ZString& = null_string,
		   const ZString& = null_string,
		   const ZString& = null_string);
	ZSubscr_t (const ZSubscr_t&);
#if !defined (__GNUG__) || defined (FIXED_GXX)
	void *operator new (unsigned int sz) { return zalloc (sz); }
	void operator delete (void *ptr) { zfree (ptr, sizeof (ZSubscr_t)); }
#endif
};

inline ZSubscr_t::ZSubscr_t (const ZString& cls, const ZString& inst, const ZString& recip) : zst_dest (cls, inst, recip) {
    q_forw = q_back = this;
}

inline ZSubscr_t::ZSubscr_t (const ZSubscr_t& z) : zst_dest (z.zst_dest) {
    q_forw = q_back = this;
}

inline int operator== (const ZSubscr_t& s1, const ZSubscr_t& s2) {
    return s1.zst_dest == s2.zst_dest;
}

inline int operator >= (const ZSubscr_t& s1, const ZSubscr_t& s2) {
    return s1.zst_dest >= s2.zst_dest;
}

struct ZClient_t {
	struct sockaddr_in zct_sin;	/* ipaddr/port of client */
	struct ZSubscr_t *zct_subs;	/* subscriptions */
#ifdef KERBEROS
	C_Block zct_cblock;		/* session key for this client */
#endif /* KERBEROS */
	ZString	zct_principal;		/* krb principal of user */
	long	last_msg;		/* last message sent to this client */
	long	last_check;		/* actually, last time the other
					   server was asked to check... */
	ZClient_t () {
	    last_msg = last_check = 0;
	}
#if !defined (__GNUG__) || defined (FIXED_GXX)
	void *operator new (unsigned int sz) { return zalloc (sz); }
	void operator delete (void *ptr) { zfree (ptr, sizeof (ZClient_t)); }
#endif
};

struct ZClientList_t {
	ZClientList_t	*q_forw;
	ZClientList_t	*q_back;
	ZClient_t	*zclt_client;
#if !defined (__GNUG__) || defined (FIXED_GXX)
	void *operator new (unsigned int sz) { return zalloc (sz); }
	void operator delete (void *ptr) { zfree (ptr, sizeof (ZClientList_t)); }
#endif
};

struct ZClass_t {
	ZClass_t *q_forw;
	ZClass_t *q_back;
	ZDestination zct_dest;
	ZAcl_t	*zct_acl;
	ZClientList_t	*zct_clientlist;

	ZClass_t (const ZDestination& dest = null_destination) : zct_dest (dest) {
	    q_forw = q_back = this;
	    zct_clientlist = 0;
	    zct_acl = 0;
	}
	~ZClass_t () {
	    if (zct_clientlist)
		xfree (zct_clientlist);
	}
#if !defined (__GNUG__) || defined (FIXED_GXX)
	void *operator new (unsigned int sz) { return zalloc (sz); }
	void operator delete (void *ptr) { zfree (ptr, sizeof (ZClass_t)); }
#endif
};

struct ZHostList_t {
	struct ZHostList_t *q_forw;
	struct ZHostList_t *q_back;
	ZClientList_t	*zh_clients;
	sockaddr_in	zh_addr;	/* IP addr/port of hostmanager */
	unsigned int zh_locked : 1;	/* 1 if this host is locked for
					   a braindump */
#if !defined (__GNUG__) || defined (FIXED_GXX)
	void *operator new (unsigned int sz) { return zalloc (sz); }
	void operator delete (void *ptr) { zfree (ptr, sizeof (ZHostList_t)); }
#endif
};

enum server_state {
	SERV_UP,			/* Server is up */
	SERV_TARDY,			/* Server due for a hello */
	SERV_DEAD,			/* Server is considered dead */
	SERV_STARTING			/* Server is between dead and up */
};

struct ZNotAcked_t {
	struct ZNotAcked_t *q_forw;	/* link to next */
	struct ZNotAcked_t *q_back;	/* link to prev */
	timer na_timer;			/* timer for retransmit */
	long na_abstimo;		/* absolute timeout to drop after */
	short na_rexmits;		/* number of retransmits */
	short na_packsz;		/* size of packet */
	caddr_t na_packet;		/* ptr to packet */
	ZUnique_Id_t na_uid;		/* uid of packet */
	union {				/* address to send to */
		struct sockaddr_in na_sin; /* client address */
		int srv_idx;		/* index of server */
	} dest;
#define na_addr	dest.na_sin
#define na_srv_idx	dest.srv_idx
#if !defined (__GNUG__) || defined (FIXED_GXX)
	void *operator new (unsigned int sz) { return zalloc (sz); }
	void operator delete (void *ptr) { zfree (ptr, sizeof (ZNotAcked_t)); }
#endif
#ifndef __GNUG__ /* cfront 2.0 breakage... */
	ZNotAcked_t () { }
#endif
};

struct ZSrvPending_t {
	struct ZSrvPending_t *q_forw;	/* link to next */
	struct ZSrvPending_t *q_back;	/* link to prev */
	caddr_t pend_packet;		/* the notice (in pkt form) */
	short pend_len;			/* len of pkt */
	unsigned int pend_auth : 1;	/* whether it is authentic */
	struct sockaddr_in pend_who;	/* the addr of the sender */
#if !defined (__GNUG__) || defined (FIXED_GXX)
	void *operator new (unsigned int sz) { return zalloc (sz); }
	void operator delete (void *ptr) { zfree (ptr, sizeof (ZSrvPending_t)); }
#endif
};

class ZServerDesc_t {
	struct sockaddr_in zs_addr;	/* server's address */
	friend void server_reset (void);
	friend void server_recover (ZClient_t *);
	friend void server_hello (ZServerDesc_t *, int);
	friend void setup_server (ZServerDesc_t *, in_addr *);
	friend void server_shutdown (void);
	friend void server_forw_reliable (ZServerDesc_t*, caddr_t, int,
					  ZNotice_t *);
	friend void srv_rexmit (void*);
	friend ZServerDesc_t*server_which_server(sockaddr_in*);
    public:
	long zs_timeout;		/* Length of timeout in sec */
	timer zs_timer;			/* timer struct for this server */
	ZHostList_t *zs_hosts;		/* pointer to list of info from this
					   server */
	ZSrvPending_t *zs_update_queue;	/* queue of packets to send
					   to this server when done dumping */
	short zs_numsent;		/* number of hello's sent */
	unsigned int zs_dumping : 1;	/* 1 if dumping, so we should queue */
	char addr[16];			/* text version of address */
    private:
	server_state zs_state;		/* server's state */
    public:
	server_state state () {
	    return zs_state;
	}
	void set_state (server_state s) {
	    zs_state = s;
	}
};

enum ZSentType {
	NOT_SENT,			/* message was not xmitted */
	SENT,				/* message was xmitted */
	AUTH_FAILED,			/* authentication failed */
	NOT_FOUND			/* user not found for uloc */
};

class SignalBlock {
    int old_mask;
public:
    SignalBlock (int mask) {
	old_mask = sigblock (mask);
    }
    ~SignalBlock () {
	(void) sigsetmask (old_mask);
    }
};
const int dump_masks = sigmask (SIGFPE) | sigmask (SIGEMT);

/* useful... */
extern "C" char * inet_ntoa (struct in_addr);
inline char * inet_ntoa (struct sockaddr_in &s) {
    return inet_ntoa (s.sin_addr);
}

/* Function declarations */
	
/* found in bdump.c */
extern void bdump_get(ZNotice_t *notice, int auth, struct sockaddr_in *who,
		      ZServerDesc_t *server);
extern void bdump_send(void),
    bdump_offer(struct sockaddr_in *who);
extern Code_t bdump_send_list_tcp(ZNotice_Kind_t kind, u_short port,
				  char *z_class, char *inst, char *opcode,
				  char *sender, char *recip,
				  const char **lyst, int num);

/* found in class.c */
extern Code_t class_register(ZClient_t *client, ZSubscr_t *subs),
    class_deregister(ZClient_t *client, ZSubscr_t *subs),
    class_restrict(char *z_class, ZAcl_t *acl),
    class_setup_restricted(char *z_class, ZAcl_t *acl);
extern ZClientList_t *class_lookup(ZSubscr_t *subs);
extern ZAcl_t *class_get_acl(ZString z_class);
extern void class_free(ZClientList_t *lyst);
extern const ZString class_control, class_admin, class_hm;
extern const ZString class_ulogin, class_ulocate;

inline int class_is_control (const Notice& notice) {
    return notice.dest.classname == class_control;
}
inline int class_is_admin (const Notice& notice) {
    return notice.dest.classname == class_admin;
}
inline int class_is_hm (const Notice& notice) {
    return notice.dest.classname == class_hm;
}
inline int class_is_ulogin (const Notice& notice) {
    return notice.dest.classname == class_ulogin;
}
inline int class_is_ulocate (const Notice& notice) {
    return notice.dest.classname == class_ulocate;
}

/* found in client.c */
extern Code_t client_register(ZNotice_t *notice, struct sockaddr_in *who,
			      register ZClient_t **client,
			      ZServerDesc_t *server, int wantdefaults);
extern void client_deregister(ZClient_t *client, ZHostList_t *host, int flush);
extern void client_dump_clients(FILE *fp, ZClientList_t *clist);
extern ZClient_t *client_which_client(struct sockaddr_in *who,
				      ZNotice_t *notice);

/* found in common.c */
extern char *strsave(const char *str);
extern unsigned long hash (const char *);

/* found in dispatch.c */
extern void handle_packet(void);
extern void clt_ack(ZNotice_t *notice, struct sockaddr_in *who,
		    ZSentType sent);
extern void nack_release(ZClient_t *client);
extern void sendit(register ZNotice_t *notice, int auth,
		   struct sockaddr_in *who);
extern void xmit(register ZNotice_t *notice, struct sockaddr_in *dest,
		 int auth, ZClient_t *client);
extern Code_t control_dispatch(ZNotice_t *notice, int auth,
			       struct sockaddr_in *who, ZServerDesc_t *server);
extern Code_t xmit_frag(ZNotice_t *notice, char *buf, int len, int waitforack);
extern int current_msg;

/* found in hostm.c */
extern void hostm_flush(ZHostList_t *host, ZServerDesc_t *server);
extern void hostm_shutdown(void);
extern void hostm_losing(ZClient_t *client, ZHostList_t *host);
extern ZHostList_t *hostm_find_host(struct in_addr *addr);
extern ZServerDesc_t *hostm_find_server(struct in_addr *addr);
extern void hostm_transfer(ZHostList_t *host, ZServerDesc_t *server);
extern void hostm_deathgram(struct sockaddr_in *sin, ZServerDesc_t *server);
extern void hostm_dump_hosts(FILE *fp);
extern Code_t hostm_dispatch(ZNotice_t *notice, int auth,
			     struct sockaddr_in *who, ZServerDesc_t *server);
extern void hostm_lose_ignore(ZClient_t *client);
extern void hostm_renumber_servers (int *);

/* found in kstuff.c */
extern int GetKerberosData (int, struct in_addr, AUTH_DAT*, char*, char*);
extern Code_t SendKerberosData (int, KTEXT, char*, char*);

/* found in server.c */
extern void server_timo(void *which);
extern void server_recover(ZClient_t *client),
    server_dump_servers(FILE *fp);
extern void server_init(void),
    server_shutdown(void);
extern void server_forward(ZNotice_t *notice, int auth,
			   struct sockaddr_in *who);
extern void server_kill_clt(ZClient_t *client);
extern void server_pending_free(register ZSrvPending_t *pending);
extern void server_self_queue(ZNotice_t*, int, struct sockaddr_in *),
    server_send_queue(ZServerDesc_t *),
    server_reset(void);
extern int is_server();
extern ZServerDesc_t *server_which_server(struct sockaddr_in *who);
extern ZSrvPending_t *server_dequeue(register ZServerDesc_t *server);
extern Code_t server_dispatch(ZNotice_t *notice, int auth,
			      struct sockaddr_in *who);
extern Code_t server_adispatch(ZNotice_t *notice, int auth,
			       struct sockaddr_in *who, ZServerDesc_t *server);


/* found in subscr.c */
extern Code_t subscr_cancel(struct sockaddr_in *sin, ZNotice_t *notice),
    subscr_subscribe(ZClient_t *who, ZNotice_t *notice),
    subscr_send_subs(ZClient_t *client, char *vers);;
extern ZClientList_t *subscr_match_list(ZNotice_t *notice);
extern void subscr_free_list(ZClientList_t *list),
    subscr_cancel_client(register ZClient_t *client),
    subscr_sendlist(ZNotice_t *notice, int auth, struct sockaddr_in *who);
extern void subscr_dump_subs(FILE *fp, ZSubscr_t *subs),
    subscr_reset(void);
extern Code_t subscr_def_subs(ZClient_t *who);

/* found in uloc.c */
extern void uloc_hflush(struct in_addr *addr),
    uloc_flush_client(struct sockaddr_in *sin),
    uloc_dump_locs(register FILE *fp);
extern Code_t ulogin_dispatch(ZNotice_t *notice, int auth,
			      struct sockaddr_in *who, ZServerDesc_t *server),
    ulocate_dispatch(ZNotice_t *notice, int auth, struct sockaddr_in *who,
		     ZServerDesc_t *server),
    uloc_send_locations(ZHostList_t *host, char *vers);

/* global identifiers */

/* found in main.c */
extern struct sockaddr_in sock_sin;	/* socket descriptors */
extern u_short hm_port;			/* port # of hostmanagers */
extern int srv_socket;			/* dgram sockets for clients
					   and other servers */
extern int bdump_socket;		/* brain dump socket
					   (closed most of the time) */

extern fd_set interesting;		/* the file descrips we are listening
					 to right now */
extern int nfildes;			/* number to look at in select() */
extern int zdebug;
extern char myname[];			/* domain name of this host */
extern ZNotAcked_t *nacklist;		/* list of not ack'ed packets */
extern char version[];
extern u_long npackets;			/* num of packets processed */
extern long uptime;			/* time we started */

/* found in bdump.c */
extern int bdumping;			/* are we dumping right now? */

/* found in server.c */
extern ZServerDesc_t *otherservers;	/* array of servers */
extern int me_server_idx;		/* me (in the array of servers) */
extern int nservers;			/* number of other servers*/

#ifdef DEBUG
/* found in dispatch.c */
extern const char *pktypes[];		/* names of the packet types */
#endif /* DEBUG */

extern "C" struct in_addr my_addr;	/* my inet address */

#define	ADMIN_HELLO	"HELLO"		/* Opcode: hello, are you there */
#define	ADMIN_IMHERE	"IHEARDYOU"	/* Opcode: yes, I am here */
#define	ADMIN_SHUTDOWN	"GOODBYE"	/* Opcode: I am shutting down */
#define ADMIN_BDUMP	"DUMP_AVAIL"	/* Opcode: I will give you a dump */
#define	ADMIN_DONE	"DUMP_DONE"	/* Opcode: brain dump for this server
					   is complete */
#define	ADMIN_NEWCLT	"NEXT_CLIENT"	/* Opcode: this is a new client */
#define	ADMIN_LOST_CLT	"LOST_CLIENT"	/* Opcode: client not ack'ing */
#define	ADMIN_KILL_CLT	"KILL_CLIENT"	/* Opcode: client is dead, remove */
#define	ADMIN_STATUS	"STATUS"	/* Opcode: please send status */

#define	ADMIN_LIMBO	"LIMBO"		/* Class inst: please send limbo info*/
#define	ADMIN_YOU	"YOUR_STATE"	/* Class inst: please send your state*/
#define	ADMIN_ME	"MY_STATE"	/* Class inst: please send my info */

ZClass_t * const	NULLZCT	= 0;
ZClient_t * const	NULLZCNT = 0;
ZClientList_t * const	NULLZCLT = 0;
ZSubscr_t * const	NULLZST = 0;
ZHostList_t * const	NULLZHLT = 0;
ZNotAcked_t * const	NULLZNAT = 0;
ZAcl_t * const		NULLZACLT = 0;
ZPacket_t * const	NULLZPT = 0;
ZServerDesc_t * const	NULLZSDT = 0;
ZSrvPending_t * const	NULLZSPT = 0;

/* me_server_idx is the index into otherservers of this server descriptor. */
/* the 'limbo' server is always the first server */

#define	me_server	(&otherservers[me_server_idx])
inline int limbo_server_idx () {
    return 0;
}
#define	limbo_server	(&otherservers[limbo_server_idx()])

inline int msgs_queued () {
    return ZQLength () || otherservers[me_server_idx].zs_update_queue;
}

#define	ack(a,b)	clt_ack(a,b,SENT)
#define	nack(a,b)	clt_ack(a,b,NOT_SENT)

#define	max(a,b)	((a) > (b) ? (a) : (b))

/* the magic class to match all packets */
#define	MATCHALL_CLASS	"zmatch_all"
extern const ZString wildcard_class;
/* the instance that matches all instances */
#define	WILDCARD_INSTANCE	"*"
extern const ZString wildcard_instance;

/* SERVER_SRVTAB is defined in zephyr.h */
#define	ZEPHYR_SRVTAB	SERVER_SRVTAB

/* debugging macros */
#ifdef DEBUG
#define zdbug(s1)	if (zdebug) syslog s1;
#else /* !DEBUG */
#define zdbug(s1)
#endif /* DEBUG */

/* statistics gathering */
class statistic {
    int val;
    const char *str;
public:
    statistic (const char *label) { val = 0; str = label; }
    int value () { return val; }
    void reset () { val = 0; }
    void operator++ () { val++; }
    void log (int do_reset = 0) {
	if (do_reset) {
	    syslog (LOG_INFO, "stats: %s: %d since last report", str, val);
	    reset ();
	}
	else
	    syslog (LOG_INFO, "stats: %s: %d", str, val);
    }
};

#endif /* !__ZSERVER_H__ */
