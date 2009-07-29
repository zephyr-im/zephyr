#ifndef __ZSERVER_H__
#define __ZSERVER_H__
/* This file is part of the Project Athena Zephyr Notification System.
 * It contains declarations for use in the server.
 *
 *	Created by:	John T. Kohl
 *
 *	$Id$
 *
 *	Copyright (c) 1987,1988,1991 by the Massachusetts Institute of Technology.
 *	For copying and distribution information, see the file
 *	"mit-copyright.h".
 */

#include <zephyr/mit-copyright.h>

#include <internal.h>

#include <arpa/inet.h>

#include "zsrv_err.h"

#include "timer.h"
#include "zsrv_conf.h"			/* configuration params */

#include "zstring.h"
#include "access.h"
#include "acl.h"
#include "utf8proc.h"


/* Kerberos-specific library interfaces used only by the server. */
#ifdef HAVE_KRB5
extern krb5_keyblock *__Zephyr_keyblock;
#define ZGetSession() (__Zephyr_keyblock)
void ZSetSession(krb5_keyblock *keyblock);
krb5_error_code Z_krb5_init_keyblock(krb5_context, krb5_enctype, size_t,
        krb5_keyblock **);
#endif

#ifdef HAVE_KRB4
void ZSetSessionDES(C_Block *key);

Code_t ZFormatAuthenticNotice(ZNotice_t*, char*, int, int*, C_Block);

#ifndef HAVE_KRB5
extern C_Block __Zephyr_session;
#define ZGetSession() (__Zephyr_session)
#endif
#endif

/* For krb_rd_req prototype and definition. */
#ifndef KRB_INT32
#define KRB_INT32 ZEPHYR_INT32
#endif

/* Current time as cached by main(); use instead of time(). */
#define NOW t_local.tv_sec

#ifdef HAVE_KRB4
/* Kerberos shouldn't stick us with array types... */
typedef struct {
    des_key_schedule s;
} Sched;
#endif

typedef struct _Destination Destination;
typedef struct _Destlist Destlist;
typedef struct _ZRealm ZRealm;
typedef struct _ZRealmname ZRealmname;
typedef enum _ZRealm_state ZRealm_state;
typedef struct _Client Client;
typedef struct _Triplet Triplet;
typedef enum _Server_state Server_state;
typedef struct _Unacked Unacked;
typedef struct _Pending Pending;
typedef struct _Server Server;
typedef enum _Sent_type Sent_type;
typedef struct _Statistic Statistic;

struct _Destination {
    String		*classname;
    String		*inst;
    String		*recip;
};

struct _Destlist {
    Destination	dest;
    struct _Destlist	*next, **prev_p;
};

enum _ZRealm_state {
    REALM_UP,				/* ZRealm is up */
    REALM_TARDY,			/* ZRealm due for a hello XXX */
    REALM_DEAD,				/* ZRealm is considered dead */
    REALM_STARTING			/* ZRealm is between dead and up */
};

struct _ZRealm {
    char name[REALM_SZ];
    int count;
    struct sockaddr_in *addrs;
    int idx;				/* which server we are connected to */
    Destlist *subs;                     /* what their clients sub to */
    Destlist *remsubs;                  /* our subs on their end */
    Client *client;
    int child_pid;
    int have_tkt;
    ZRealm_state state;
};

struct _ZRealmname {
    char name[REALM_SZ];
    char **servers;
    int nused;
    int nservers;
};

struct _Client {
    struct sockaddr_in	addr;		/* ipaddr/port of client */
    Destlist		*subs	;	/* subscriptions */
#ifdef HAVE_KRB5
    krb5_keyblock       *session_keyblock;
#else
#ifdef HAVE_KRB4
    C_Block		session_key;	/* session key for this client */
#endif /* HAVE_KRB4 */
#endif
    String		*principal;	/* krb principal of user */
    int			last_send;	/* Counter for last sent packet. */
    time_t		last_ack;	/* Time of last received ack */
    ZRealm		*realm;
    struct _Client	*next, **prev_p;
};

struct _Triplet {
    Destination		dest;
    Acl			*acl;
    Client		**clients;
    int			clients_size;
    struct _Triplet	*next, **prev_p;
};

enum _Server_state {
    SERV_UP,				/* Server is up */
    SERV_TARDY,				/* Server due for a hello */
    SERV_DEAD,				/* Server is considered dead */
    SERV_STARTING			/* Server is between dead and up */
};

struct _Unacked {
    Timer		*timer;		/* timer for retransmit */
    Client		*client;	/* responsible client, or NULL */
    short		rexmits;	/* number of retransmits */
    short		packsz;		/* size of packet */
    char		*packet;	/* ptr to packet */
    ZUnique_Id_t	uid;		/* uid of packet */
    struct sockaddr_in	ack_addr;
    union {				/* address to send to */
	struct sockaddr_in addr;	/* client address */
	int	srv_idx;		/* index of server */
	struct {
	    int rlm_idx;		/* index of realm */
	    int rlm_srv_idx;		/* index of server in realm */
	} rlm;
    } dest;
    struct _Unacked *next, **prev_p;
};

struct _Pending {
    char		*packet;	/* the notice (in pkt form) */
    short		len;		/* len of pkt */
    unsigned int	auth;		/* whether it is authentic */
    struct sockaddr_in who;		/* the addr of the sender */
    struct _Pending *next;
};

struct _Server {
    Server_state	state;		/* server's state */
    struct sockaddr_in	addr;		/* server's address */
    long		timeout;	/* Length of timeout in sec */
    Timer		*timer;		/* timer for this server */
    Pending		*queue;		/* queue of packets to send
					   to this server when done dumping */
    Pending		*queue_last;	/* last packet on queue */
    short		num_hello_sent;	/* number of hello's sent */
    unsigned int	dumping;	/* 1 if dumping, so we should queue */
    char		addr_str[16];	/* text version of address */
};

enum _Sent_type {
    NOT_SENT,				/* message was not xmitted */
    SENT,				/* message was xmitted */
    AUTH_FAILED,			/* authentication failed */
    NOT_FOUND				/* user not found for uloc */
};

/* statistics gathering */
struct _Statistic {
    int			val;
    char		*str;
};

/* Function declarations */

/* These macros instantiate inline functions that do the work of the formder
   LIST_INSERT and LIST_DELETE functions, which unfortunately triggered gcc's
   pedanticism.  The comment before the *former* macros was: */
/* These macros are for insertion into and deletion from a singly-linked list
 * with back pointers to the previous element's next pointer.  In order to
 * make these macros act like expressions, they use the comma operator for
 * sequenced evaluations of assignment, and "a && b" for "evaluate assignment
 * b if expression a is true". */

#define MAKE_LIST_INSERT(type) inline static void type##_insert(type **head, type *elem) \
    {\
	(elem)->next = *(head);					\
	if(*head) (*(head))->prev_p = &(elem)->next;		\
	(*head) = (elem);					\
	(elem)->prev_p = (head);				\
    }

#define MAKE_LIST_DELETE(type) inline static void type##_delete(type *elem) \
    {\
	*(elem)->prev_p = (elem)->next;				\
	if((elem)->next) (elem)->next->prev_p = (elem)->prev_p;	\
    }

MAKE_LIST_INSERT(Destlist);
MAKE_LIST_DELETE(Destlist);
MAKE_LIST_INSERT(Client);
MAKE_LIST_DELETE(Client);
MAKE_LIST_INSERT(Triplet);
MAKE_LIST_DELETE(Triplet);
MAKE_LIST_INSERT(Unacked);
MAKE_LIST_DELETE(Unacked);

/* found in bdump.c */
void bdump_get(ZNotice_t *notice, int auth, struct sockaddr_in *who,
		    Server *server);
void bdump_send(void);
void bdump_offer(struct sockaddr_in *who);
Code_t bdump_send_list_tcp(ZNotice_Kind_t kind, struct sockaddr_in *addr,
				char *class_name, char *inst, char *opcode,
				char *sender, char *recip, char **lyst,
				int num);
int get_tgt(void);

/* found in class.c */
extern String *class_control, *class_admin, *class_hm;
extern String *class_ulogin, *class_ulocate;
int ZDest_eq(Destination *d1, Destination *d2);
Code_t triplet_register(Client *client, Destination *dest, ZRealm *realm);
Code_t triplet_deregister(Client *client, Destination *dest,
			       ZRealm *realm);
Code_t class_restrict(char *class, Acl *acl);
Code_t class_setup_restricted(char *class, Acl *acl);
Client **triplet_lookup(Destination *dest);
Acl *class_get_acl(String *class);
int dest_eq(Destination *d1, Destination *d2);
int order_dest_strings(Destination *d1, Destination *d2);
void triplet_dump_subs(FILE *fp);

/* found in client.c */
Code_t client_register(ZNotice_t *notice, struct in_addr *host,
			    Client **client_p, int wantdefaults);
void client_deregister(Client *client, int flush);
void client_flush_host(struct in_addr *host);
void client_dump_clients(FILE *fp);
Client *client_find(struct in_addr *host, unsigned int port);
Code_t client_send_clients(void);

/* found in common.c */
char *strsave(const char *str);
unsigned long hash (const char *);
void dump_quote(char *p, FILE *fp);
void notice_extract_address(ZNotice_t *notice, struct sockaddr_in *addr);

/* found in dispatch.c */
void handle_packet(void);
void clt_ack(ZNotice_t *notice, struct sockaddr_in *who, Sent_type sent);
void nack_release(Client *client);
void sendit(ZNotice_t *notice, int auth, struct sockaddr_in *who,
		 int external);
void rexmit(void *);
void xmit(ZNotice_t *notice, struct sockaddr_in *dest, int auth,
	       Client *client);
Code_t hostm_dispatch(ZNotice_t *notice, int auth,
			   struct sockaddr_in *who, Server *server);
Code_t control_dispatch(ZNotice_t *notice, int auth,
			     struct sockaddr_in *who, Server *server);
Code_t xmit_frag(ZNotice_t *notice, char *buf, int len, int waitforack);
void hostm_shutdown(void);

/* found in kstuff.c */
Code_t ZCheckSrvAuthentication(ZNotice_t *notice, struct sockaddr_in *from, char *realm);
#if defined(HAVE_KRB4) || defined(HAVE_KRB5)
Code_t ReadKerberosData(int, int *, char **, int *);
void sweep_ticket_hash_table(void *);
#endif
#ifdef HAVE_KRB4
int GetKerberosData (int, struct in_addr, AUTH_DAT *, char *, char *);
Code_t SendKerberosData (int, KTEXT, char *, char *);
#endif
#ifdef HAVE_KRB5
Code_t SendKrb5Data(int, krb5_data *);
Code_t GetKrb5Data(int, krb5_data *);
#endif

/* found in server.c */
void server_timo(void *which);
void server_dump_servers(FILE *fp);
void server_init(void);
void server_shutdown(void);
void server_forward(ZNotice_t *notice, int auth,
			 struct sockaddr_in *who);
void server_kill_clt(Client *client);
void server_pending_free(Pending *pending);
void server_self_queue(ZNotice_t *, int, struct sockaddr_in *);
void server_send_queue(Server *);
void server_reset(void);
Server *server_which_server(struct sockaddr_in *who);
Pending *server_dequeue(Server *server);
Code_t server_dispatch(ZNotice_t *notice, int auth,
			    struct sockaddr_in *who);
Code_t server_adispatch(ZNotice_t *notice, int auth,
			     struct sockaddr_in *who, Server *server);

/* found in subscr.c */
Code_t subscr_foreign_user(ZNotice_t *, struct sockaddr_in *, Server *, ZRealm *);
Code_t subscr_cancel(struct sockaddr_in *sin, ZNotice_t *notice);
Code_t subscr_subscribe(Client *who, ZNotice_t *notice, Server *server);
Code_t subscr_send_subs(Client *client);
void subscr_cancel_client(Client *client);
void subscr_sendlist(ZNotice_t *notice, int auth,
			  struct sockaddr_in *who);
void subscr_dump_subs(FILE *fp, Destlist *subs);
void subscr_reset(void);
Code_t subscr_def_subs(Client *who);
Code_t subscr_realm(ZRealm *, ZNotice_t *);
Code_t subscr_send_realm_subs(ZRealm *);
Code_t subscr_realm_cancel(struct sockaddr_in *, ZNotice_t *, ZRealm *);

/* found in uloc.c */
void uloc_hflush(struct in_addr *addr);
void uloc_flush_client(struct sockaddr_in *sin);
void uloc_dump_locs(FILE *fp);
Code_t ulogin_dispatch(ZNotice_t *notice, int auth,
			    struct sockaddr_in *who, Server *server);
Code_t ulocate_dispatch(ZNotice_t *notice, int auth,
			     struct sockaddr_in *who, Server *server);
Code_t uloc_send_locations(void);
void ulogin_relay_locate(ZNotice_t *, struct sockaddr_in *);
void ulogin_realm_locate(ZNotice_t *, struct sockaddr_in *, ZRealm *);

/* found in realm.c */
int realm_sender_in_realm(const char *realm, char *sender);
int realm_bound_for_realm(const char *realm, char *recip);
ZRealm *realm_which_realm(struct sockaddr_in *who);
ZRealm *realm_get_realm_by_name(char *name);
ZRealm *realm_get_realm_by_pid(int);
void realm_handoff(ZNotice_t *, int, struct sockaddr_in *, ZRealm *, int);
const char *realm_expand_realm(char *);
void realm_init(void);
Code_t ZCheckZRealmAuthentication(ZNotice_t *, struct sockaddr_in *,
				      char *);
Code_t realm_control_dispatch(ZNotice_t *, int, struct sockaddr_in *,
				   Server *, ZRealm *);
void realm_shutdown(void);
void realm_deathgram(Server *);
Code_t realm_send_realms(void);
Code_t realm_dispatch(ZNotice_t *, int, struct sockaddr_in *, Server *);
void realm_wakeup(void);
void kill_realm_pids(void);
void realm_dump_realms(FILE *);

/* found in version.c */
char *get_version(void);

/* found in access.c */
int access_check(char *, Acl *, Access);

/* global identifiers */

/* found in main.c */
int packets_waiting(void);
extern struct sockaddr_in srv_addr;	/* server socket address */
extern unsigned short hm_port;		/* host manager receiver port */
extern unsigned short hm_srv_port;	/* host manager server sending port */
extern int srv_socket;			/* dgram sockets for clients
					   and other servers */
extern int bdump_socket;		/* brain dump socket
					   (closed most of the time) */

extern fd_set interesting;		/* the file descrips we are listening
					 to right now */
extern int nfds;			/* number to look at in select() */
extern int zdebug;
extern char myname[];			/* domain name of this host */
extern char list_file[];
#ifdef HAVE_KRB5
extern char keytab_file[];
extern krb5_ccache Z_krb5_ccache;
#endif
#ifdef HAVE_KRB4
extern char srvtab_file[];
extern char my_realm[];
#endif
extern char acl_dir[];
extern char subs_file[];
extern const char version[];
extern u_long npackets;			/* num of packets processed */
extern time_t uptime;			/* time we started */
extern struct in_addr my_addr;
extern struct timeval t_local;		/* current time */

/* found in bdump.c */
extern int bdumping;			/* are we processing a bdump packet? */
extern int bdump_concurrent;		/* set while processing a packet
					 * concurrently during a braindump. */

/* found in dispatch.c */
extern Statistic i_s_ctls, i_s_logins, i_s_admins, i_s_locates;
extern int rexmit_times[];

/* found in server.c */
extern Server *otherservers;		/* array of servers */
extern int me_server_idx;		/* me (in the array of servers) */
extern int nservers;			/* number of other servers*/

/* found in subscr.c */
extern String *empty;
extern String *wildcard_instance;

extern ZRealm *otherrealms;
extern int nrealms;

extern struct in_addr my_addr;	/* my inet address */

#define class_is_control(classname) (classname == class_control)
#define class_is_admin(classname) (classname == class_admin)
#define class_is_hm(classname) (classname == class_hm)
#define class_is_ulogin(classname) (classname == class_ulogin)
#define class_is_ulocate(classname) (classname == class_ulocate)

#define	ADMIN_HELLO	"HELLO"		/* Opcode: hello, are you there */
#define	ADMIN_IMHERE	"IHEARDYOU"	/* Opcode: yes, I am here */
#define	ADMIN_SHUTDOWN	"GOODBYE"	/* Opcode: I am shutting down */
#define ADMIN_BDUMP	"DUMP_AVAIL"	/* Opcode: I will give you a dump */
#define	ADMIN_DONE	"DUMP_DONE"	/* Opcode: brain dump for this server
					   is complete */
#define	ADMIN_NEWCLT	"NEXT_CLIENT"	/* Opcode: this is a new client */
#define	ADMIN_KILL_CLT	"KILL_CLIENT"	/* Opcode: client is dead, remove */
#define	ADMIN_STATUS	"STATUS"	/* Opcode: please send status */

#define ADMIN_NEWREALM	"NEXT_REALM"	/* Opcode: this is a new realm */
#define REALM_REQ_LOCATE "REQ_LOCATE"	/* Opcode: request a location */
#define REALM_ANS_LOCATE "ANS_LOCATE"	/* Opcode: answer to location */
#define REALM_BOOT      "SENDSUBS"	/* Opcode: first server in realm */

/* me_server_idx is the index into otherservers of this server descriptor. */
/* the 'limbo' server is always the first server */

#define	me_server	(&otherservers[me_server_idx])
#define limbo_server_idx()	(0)
#define	limbo_server	(&otherservers[limbo_server_idx()])

#define msgs_queued()	(ZQLength() || otherservers[me_server_idx].queue)

#define	ack(a,b)	clt_ack(a,b,SENT)
#define	nack(a,b)	clt_ack(a,b,NOT_SENT)

#define	min(a,b)	((a) < (b) ? (a) : (b))
#define	max(a,b)	((a) > (b) ? (a) : (b))

#define START_CRITICAL_CODE
#define END_CRITICAL_CODE

/* the instance that matches all instances */
#define	WILDCARD_INSTANCE	"*"

/* debugging macros */
#ifdef DEBUG
#define zdbug(s1)	if (zdebug) syslog s1;
#else /* !DEBUG */
#define zdbug(s1)
#endif /* DEBUG */

#endif /* !__ZSERVER_H__ */
