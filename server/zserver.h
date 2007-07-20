#ifndef __ZSERVER_H__
#define __ZSERVER_H__
/* This file is part of the Project Athena Zephyr Notification System.
 * It contains declarations for use in the server.
 *
 *	Created by:	John T. Kohl
 *
 *	$Source$
 *	$Author$
 *	$Zephyr: /mit/zephyr/src/server/RCS/zserver.h,v 1.34 91/03/08 12:53:24 raeburn Exp $
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

#ifdef HAVE_KRB4
/* Kerberos-specific library interfaces used only by the server. */
extern C_Block __Zephyr_session;
#define ZGetSession() (__Zephyr_session)
Code_t ZFormatAuthenticNotice __P((ZNotice_t*, char*, int, int*, C_Block));
#endif

/* For krb_rd_req prototype and definition. */
#ifndef KRB_INT32
#define KRB_INT32 ZEPHYR_INT32
#endif

/* These macros are for insertion into and deletion from a singly-linked list
 * with back pointers to the previous element's next pointer.  In order to
 * make these macros act like expressions, they use the comma operator for
 * sequenced evaluations of assignment, and "a && b" for "evaluate assignment
 * b if expression a is true". */
#define LIST_INSERT(head, elem) \
	((elem)->next = *(head), \
	 (*head) && ((*(head))->prev_p = &(elem)->next), \
	 (*head) = (elem), (elem)->prev_p = (head))
#define LIST_DELETE(elem) \
	(*(elem)->prev_p = (elem)->next, \
	 (elem)->next && ((elem)->next->prev_p = (elem)->prev_p))

/* Current time as cached by main(); use instead of time(). */
#define NOW t_local.tv_sec

#ifdef HAVE_KRB4
#ifndef NOENCRYPTION
/* Kerberos shouldn't stick us with array types... */
typedef struct {
    des_key_schedule s;
} Sched;
#endif
#endif

typedef struct _Destination Destination;
typedef struct _Destlist Destlist;
typedef struct _Realm Realm;
typedef struct _Realmname Realmname;
typedef enum _Realm_state Realm_state;
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

enum _Realm_state {
    REALM_UP,				/* Realm is up */
    REALM_TARDY,			/* Realm due for a hello XXX */
    REALM_DEAD,				/* Realm is considered dead */
    REALM_STARTING			/* Realm is between dead and up */
};

struct _Realm {
    char name[REALM_SZ];
    int count;
    struct sockaddr_in *addrs;
    int idx;				/* which server we are connected to */
    Destlist *subs;                     /* what their clients sub to */
    Destlist *remsubs;                  /* our subs on their end */
    Client *client;                     
    int child_pid;
    int have_tkt;
    Realm_state state;
};

struct _Realmname {
    char name[REALM_SZ];
    char **servers;
    int nused;
    int nservers;
};

struct _Client {
    struct sockaddr_in	addr;		/* ipaddr/port of client */
    Destlist		*subs	;	/* subscriptions */
#ifdef HAVE_KRB4
    C_Block		session_key;	/* session key for this client */
#endif /* HAVE_KRB4 */
    String		*principal;	/* krb principal of user */
    int			last_send;	/* Counter for last sent packet. */
    time_t		last_ack;	/* Time of last received ack */
    Realm		*realm;
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
	
/* found in bdump.c */
void bdump_get __P((ZNotice_t *notice, int auth, struct sockaddr_in *who,
		    Server *server));
void bdump_send __P((void));
void bdump_offer __P((struct sockaddr_in *who));
Code_t bdump_send_list_tcp __P((ZNotice_Kind_t kind, struct sockaddr_in *addr,
				char *class_name, char *inst, char *opcode,
				char *sender, char *recip, char **lyst,
				int num));
int get_tgt __P((void));

/* found in class.c */
extern String *class_control, *class_admin, *class_hm;
extern String *class_ulogin, *class_ulocate;
int ZDest_eq __P((Destination *d1, Destination *d2));
Code_t triplet_register __P((Client *client, Destination *dest, Realm *realm));
Code_t triplet_deregister __P((Client *client, Destination *dest,
			       Realm *realm));
Code_t class_restrict __P((char *class, Acl *acl));
Code_t class_setup_restricted __P((char *class, Acl *acl));
Client **triplet_lookup __P((Destination *dest));
Acl *class_get_acl __P((String *class));
int dest_eq __P((Destination *d1, Destination *d2));
int order_dest_strings __P((Destination *d1, Destination *d2));
void triplet_dump_subs __P((FILE *fp));

/* found in client.c */
Code_t client_register __P((ZNotice_t *notice, struct in_addr *host,
			    Client **client_p, int wantdefaults));
void client_deregister __P((Client *client, int flush)); 
void client_flush_host __P((struct in_addr *host));
void client_dump_clients __P((FILE *fp));
Client *client_find __P((struct in_addr *host, unsigned int port));
Code_t client_send_clients __P((void));

/* found in common.c */
char *strsave __P((const char *str));
unsigned long hash  __P((const char *));
void dump_quote __P((char *p, FILE *fp));

/* found in dispatch.c */
void handle_packet __P((void));
void clt_ack __P((ZNotice_t *notice, struct sockaddr_in *who, Sent_type sent));
void nack_release __P((Client *client));
void sendit __P((ZNotice_t *notice, int auth, struct sockaddr_in *who,
		 int external));
void rexmit __P((void *));
void xmit __P((ZNotice_t *notice, struct sockaddr_in *dest, int auth,
	       Client *client));
Code_t hostm_dispatch __P((ZNotice_t *notice, int auth,
			   struct sockaddr_in *who, Server *server));
Code_t control_dispatch __P((ZNotice_t *notice, int auth,
			     struct sockaddr_in *who, Server *server));
Code_t xmit_frag __P((ZNotice_t *notice, char *buf, int len, int waitforack));
void hostm_shutdown __P((void));

/* found in kstuff.c */
#ifdef HAVE_KRB4
int GetKerberosData  __P((int, struct in_addr, AUTH_DAT *, char *, char *));
Code_t SendKerberosData  __P((int, KTEXT, char *, char *));
void sweep_ticket_hash_table __P((void *));
#endif

/* found in kopt.c */
#ifdef HAVE_KRB4
#ifndef NOENCRYPTION
Sched *check_key_sched_cache __P((des_cblock key));
void add_to_key_sched_cache __P((des_cblock key, Sched *sched));
int krb_set_key __P((char *key, int cvt));
int krb_rd_req __P((KTEXT authent, char *service, char *instance,
		    unsigned KRB_INT32 from_addr, AUTH_DAT *ad, char *fn));
int krb_find_ticket __P((KTEXT authent, KTEXT ticket));
int krb_get_lrealm __P((char *r, int n));
#endif
#endif

/* found in server.c */
void server_timo __P((void *which));
void server_dump_servers __P((FILE *fp));
void server_init __P((void));
void server_shutdown __P((void));
void server_forward __P((ZNotice_t *notice, int auth,
			 struct sockaddr_in *who));
void server_kill_clt __P((Client *client));
void server_pending_free __P((Pending *pending));
void server_self_queue __P((ZNotice_t *, int, struct sockaddr_in *));
void server_send_queue __P((Server *));
void server_reset __P((void));
int is_server();
Server *server_which_server __P((struct sockaddr_in *who));
Pending *server_dequeue __P((Server *server));
Code_t server_dispatch __P((ZNotice_t *notice, int auth,
			    struct sockaddr_in *who));
Code_t server_adispatch __P((ZNotice_t *notice, int auth,
			     struct sockaddr_in *who, Server *server));

/* found in subscr.c */
Code_t subscr_foreign_user __P((ZNotice_t *, struct sockaddr_in *, Server *, Realm *));
Code_t subscr_cancel __P((struct sockaddr_in *sin, ZNotice_t *notice));
Code_t subscr_subscribe __P((Client *who, ZNotice_t *notice, Server *server));
Code_t subscr_send_subs __P((Client *client));
void subscr_cancel_client __P((Client *client));
void subscr_sendlist __P((ZNotice_t *notice, int auth,
			  struct sockaddr_in *who));
void subscr_dump_subs __P((FILE *fp, Destlist *subs));
void subscr_reset __P((void));
Code_t subscr_def_subs __P((Client *who));

/* found in uloc.c */
void uloc_hflush __P((struct in_addr *addr));
void uloc_flush_client __P((struct sockaddr_in *sin));
void uloc_dump_locs __P((FILE *fp));
Code_t ulogin_dispatch __P((ZNotice_t *notice, int auth,
			    struct sockaddr_in *who, Server *server));
Code_t ulocate_dispatch __P((ZNotice_t *notice, int auth,
			     struct sockaddr_in *who, Server *server));
Code_t uloc_send_locations __P((void));

/* found in realm.c */
int realm_sender_in_realm __P((char *realm, char *sender));
int realm_bound_for_realm __P((char *realm, char *recip));
Realm *realm_which_realm __P((struct sockaddr_in *who));
Realm *realm_get_realm_by_name __P((char *name));
Realm *realm_get_realm_by_pid __P((int));
void realm_handoff(ZNotice_t *, int, struct sockaddr_in *, Realm *, int);
char *realm_expand_realm(char *);
void realm_init __P((void));
Code_t ZCheckRealmAuthentication __P((ZNotice_t *, struct sockaddr_in *,
				      char *));
Code_t realm_control_dispatch __P((ZNotice_t *, int, struct sockaddr_in *,
				   Server *, Realm *));
void realm_shutdown __P((void));
void realm_deathgram __P((Server *));

/* found in version.c */
char *get_version __P((void));

/* global identifiers */

/* found in main.c */
int packets_waiting __P((void));
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
#ifndef HAVE_HESIOD
extern char list_file[];
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

extern Realm *otherrealms;
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
