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

#include <zephyr/zephyr.h>		/* which includes <errno.h>,
					   <sys/types.h>,
					   <netinet/in.h>,
					   <sys/time.h>, 
					   <stdio.h>,
					   <krb.h> */
#include <arpa/inet.h>
#include <zephyr/acl.h>
#include <sys/file.h>
#include <fcntl.h>

#include <zephyr/zsyslog.h>

#include <strings.h>
#include <signal.h>
#ifdef lint
#include <sys/uio.h>			/* so it shuts up about struct iovec */
#endif /* lint */
#ifdef _IBMR2
#include <sys/select.h>
#endif
#include "zsrv_err.h"

#include "timer.h"
#include "zsrv_conf.h"			/* configuration params */

#include "zstring.h"
#include "access.h"
#include "unix.h"
#include "zalloc.h"

/* definitions for the Zephyr server */

/* structures */

/*
 * ZDestination: Where is this notice going to?  This includes class,
 * instance, and recipient at the moment.
 */

typedef struct _ZDestination {
    unsigned long hash_value;
    ZSTRING *classname;
    ZSTRING *inst;
    ZSTRING *recip;
} ZDestination;

/* typedef struct _Notice {
    ZNotice_t *notice;
    struct _ZDestination dest;
    ZSTRING *sender;
    int msg_no;
} Notice;
*/
typedef struct _ZSubscr_t {
	struct _ZSubscr_t *q_forw;	/* links in client's subscr. queue */
	struct _ZSubscr_t *q_back;
	struct _ZDestination zst_dest;	/* destination of messages */
} ZSubscr_t;

typedef struct _ZClient_t {
	struct sockaddr_in zct_sin;	/* ipaddr/port of client */
	struct _ZSubscr_t *zct_subs;	/* subscriptions */
#ifdef KERBEROS
	C_Block zct_cblock;		/* session key for this client */
#endif /* KERBEROS */
	ZSTRING	*zct_principal;		/* krb principal of user */
	long	last_msg;		/* last message sent to this client */
	long	last_check;		/* actually, last time the other
					   server was asked to check... */
} ZClient_t;

typedef struct _ZClientList_t {
	struct _ZClientList_t	*q_forw;
	struct _ZClientList_t	*q_back;
	struct _ZClient_t	*zclt_client;
} ZClientList_t;

typedef struct _ZClass_t {
	struct _ZClass_t *q_forw;
	struct _ZClass_t *q_back;
	ZDestination zct_dest;
	ZAcl_t	*zct_acl;
	ZClientList_t	*zct_clientlist;
} ZClass_t;

typedef struct _ZHostList_t {
	struct _ZHostList_t *q_forw;
	struct _ZHostList_t *q_back;
	ZClientList_t	*zh_clients;
	struct sockaddr_in zh_addr;	/* IP addr/port of hostmanager */
	unsigned int zh_locked;		/* 1 if this host is locked for
					   a braindump */
} ZHostList_t;

typedef enum _server_state {
	SERV_UP,			/* Server is up */
	SERV_TARDY,			/* Server due for a hello */
	SERV_DEAD,			/* Server is considered dead */
	SERV_STARTING			/* Server is between dead and up */
} server_state;

typedef struct _ZNotAcked_t {
	struct _ZNotAcked_t *q_forw;	/* link to next */
	struct _ZNotAcked_t *q_back;	/* link to prev */
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
} ZNotAcked_t;

typedef struct _ZSrvPending_t {
	struct _ZSrvPending_t *q_forw;	/* link to next */
	struct _ZSrvPending_t *q_back;	/* link to prev */
	caddr_t pend_packet;		/* the notice (in pkt form) */
	short pend_len;			/* len of pkt */
	unsigned int pend_auth;		/* whether it is authentic */
	struct sockaddr_in pend_who;	/* the addr of the sender */
} ZSrvPending_t;

typedef struct _ZServerDesc_t {
	server_state zs_state;		/* server's state */
	struct sockaddr_in zs_addr;	/* server's address */
	long zs_timeout;		/* Length of timeout in sec */
	timer zs_timer;			/* timer struct for this server */
	struct _ZHostList_t *zs_hosts;	/* pointer to list of info from this
					   server */
	struct _ZSrvPending_t *zs_update_queue;	/* queue of packets to send
					   to this server when done dumping */
	short zs_numsent;		/* number of hello's sent */
	unsigned int zs_dumping;	/* 1 if dumping, so we should queue */
	char addr[16];			/* text version of address */
} ZServerDesc_t;

typedef enum ZSentType {
	NOT_SENT,			/* message was not xmitted */
	SENT,				/* message was xmitted */
	AUTH_FAILED,			/* authentication failed */
	NOT_FOUND			/* user not found for uloc */
} ZSentType;

/* statistics gathering */
typedef struct _ZStatistic_t {
  int val;
  char *str;
} ZStatistic;

#ifdef __STDC__
# define        P(s) s
#else
# define P(s) ()
#endif

/* Function declarations */
	
/* found in bdump.c */
extern void bdump_get P((ZNotice_t *notice, int auth, struct sockaddr_in *who,
		      ZServerDesc_t *server));
extern void bdump_send P((void));
extern void bdump_offer P((struct sockaddr_in *who));
extern Code_t bdump_send_list_tcp P((ZNotice_Kind_t kind, int port,
				  char *class_name, char *inst, char *opcode,
				  char *sender, char *recip,
				  char **lyst, int num));

/* found in class.c */
extern Code_t class_register P((ZClient_t *client, ZSubscr_t *subs));
extern Code_t class_deregister P((ZClient_t *client, ZSubscr_t *subs));
extern Code_t class_restrict P((char *z_class, ZAcl_t *acl));
extern Code_t class_setup_restricted P((char *z_class, ZAcl_t *acl));
extern ZClientList_t *class_lookup P((ZSubscr_t *subs));
extern ZAcl_t *class_get_acl P((ZSTRING *z_class));
extern void class_free P((ZClientList_t *lyst));
extern ZSTRING *class_control, *class_admin, *class_hm;
extern ZSTRING *class_ulogin, *class_ulocate;
extern void set_ZDestination_hash P((ZDestination *zd));
extern int ZDest_eq P((ZDestination *zd1, ZDestination *zd2));
extern int order_dest_strings P((ZDestination *zd1, ZDestination *zd2));

/* found in client.c */
extern Code_t client_register P((ZNotice_t *notice, struct sockaddr_in *who,
			      register ZClient_t **client,
			      ZServerDesc_t *server, int wantdefaults));
extern void client_deregister P((ZClient_t *client, ZHostList_t *host,
				 int flush)); 
extern void client_dump_clients P((FILE *fp, ZClientList_t *clist));
extern ZClient_t *client_which_client P((struct sockaddr_in *who,
				      ZNotice_t *notice));

/* found in common.c */
extern char *strsave P((Zconst char *str));
extern unsigned long hash  P((Zconst char *));

/* found in dispatch.c */
extern void handle_packet P((void));
extern void clt_ack P((ZNotice_t *notice, struct sockaddr_in *who,
		    ZSentType sent));
extern void nack_release P((ZClient_t *client));
extern void sendit P((register ZNotice_t *notice, int auth,
		   struct sockaddr_in *who));
extern void rexmit P((void *));
extern void xmit P((register ZNotice_t *notice, struct sockaddr_in *dest,
		 int auth, ZClient_t *client));
extern Code_t control_dispatch P((ZNotice_t *notice, int auth,
			       struct sockaddr_in *who,
				  ZServerDesc_t *server));
extern Code_t xmit_frag P((ZNotice_t *notice, char *buf, int len,
			   int waitforack));

/* found in hostm.c */
extern void hostm_flush P((ZHostList_t *host, ZServerDesc_t *server));
extern void hostm_shutdown P((void));
extern void hostm_losing P((ZClient_t *client, ZHostList_t *host));
extern ZHostList_t *hostm_find_host P((struct in_addr *addr));
extern ZServerDesc_t *hostm_find_server P((struct in_addr *addr));
extern void hostm_transfer P((ZHostList_t *host, ZServerDesc_t *server));
extern void hostm_deathgram P((struct sockaddr_in *sin,
			       ZServerDesc_t *server));
extern void hostm_dump_hosts P((FILE *fp));
extern Code_t hostm_dispatch P((ZNotice_t *notice, int auth,
			     struct sockaddr_in *who, ZServerDesc_t *server));
extern void hostm_lose_ignore P((ZClient_t *client));
extern void hostm_renumber_servers  P((int *));

/* found in kstuff.c */
#ifdef KERBEROS
extern int GetKerberosData  P((int, struct in_addr, AUTH_DAT*, char*, char*));
extern Code_t SendKerberosData  P((int, KTEXT, char*, char*));
#endif

/* found in server.c */
extern void server_timo P((void *which));
extern void server_recover P((ZClient_t *client)),
    server_dump_servers P((FILE *fp));
extern void server_init P((void)),
    server_shutdown P((void));
extern void server_forward P((ZNotice_t *notice, int auth,
			   struct sockaddr_in *who));
extern void server_kill_clt P((ZClient_t *client));
extern void server_pending_free P((register ZSrvPending_t *pending));
extern void server_self_queue P((ZNotice_t*, int, struct sockaddr_in *)),
    server_send_queue P((ZServerDesc_t *)),
    server_reset P((void));
extern int is_server();
extern ZServerDesc_t *server_which_server P((struct sockaddr_in *who));
extern ZSrvPending_t *server_dequeue P((register ZServerDesc_t *server));
extern Code_t server_dispatch P((ZNotice_t *notice, int auth,
			      struct sockaddr_in *who));
extern Code_t server_adispatch P((ZNotice_t *notice, int auth,
				  struct sockaddr_in *who,
				  ZServerDesc_t *server));


/* found in subscr.c */
extern Code_t subscr_cancel P((struct sockaddr_in *sin, ZNotice_t *notice));
extern Code_t subscr_subscribe P((ZClient_t *who, ZNotice_t *notice)),
    subscr_send_subs P((ZClient_t *client, char *vers));;
extern ZClientList_t *subscr_match_list P((ZNotice_t *notice));
extern void subscr_free_list P((ZClientList_t *list)),
    subscr_cancel_client P((register ZClient_t *client)),
    subscr_sendlist P((ZNotice_t *notice, int auth, struct sockaddr_in *who));
extern void subscr_dump_subs P((FILE *fp, ZSubscr_t *subs)),
    subscr_reset P((void));
extern int compare_subs P((ZSubscr_t *s1, ZSubscr_t *s2, int do_wildcard));
extern Code_t subscr_def_subs P((ZClient_t *who));

/* found in uloc.c */
extern void uloc_hflush P((struct in_addr *addr)),
    uloc_flush_client P((struct sockaddr_in *sin)),
    uloc_dump_locs P((register FILE *fp));
extern Code_t ulogin_dispatch P((ZNotice_t *notice, int auth,
			      struct sockaddr_in *who, ZServerDesc_t *server)),
    ulocate_dispatch P((ZNotice_t *notice, int auth, struct sockaddr_in *who,
		     ZServerDesc_t *server)),
    uloc_send_locations P((ZHostList_t *host, char *vers));

/* found in version.c */
extern char *get_version P((void));

#undef P


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
extern Zconst char version[];
extern u_long npackets;			/* num of packets processed */
extern long uptime;			/* time we started */
extern struct in_addr my_addr;

/* found in bdump.c */
extern int bdumping;			/* are we dumping right now? */

/* found in dispatch.c */
extern ZStatistic i_s_ctls, i_s_logins, i_s_admins, i_s_locates;
extern int num_rexmits;
extern long rexmit_secs, abs_timo;

/* found in server.c */
extern ZServerDesc_t *otherservers;	/* array of servers */
extern int me_server_idx;		/* me (in the array of servers) */
extern int nservers;			/* number of other servers*/

/* found in subscr.c */
extern ZSTRING *empty;
extern ZSTRING *wildcard_instance;
extern ZSTRING *wildcard_class;
extern ZSubscr_t matchall_sub;

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
#define	ADMIN_LOST_CLT	"LOST_CLIENT"	/* Opcode: client not ack'ing */
#define	ADMIN_KILL_CLT	"KILL_CLIENT"	/* Opcode: client is dead, remove */
#define	ADMIN_STATUS	"STATUS"	/* Opcode: please send status */

#define	ADMIN_LIMBO	"LIMBO"		/* Class inst: please send limbo info*/
#define	ADMIN_YOU	"YOUR_STATE"	/* Class inst: please send your state*/
#define	ADMIN_ME	"MY_STATE"	/* Class inst: please send my info */

#define	NULLZCT		((ZClass_t *) 0)
#define	NULLZCNT	((ZClient_t *) 0)
#define	NULLZCLT	((ZClientList_t *) 0)
#define	NULLZST		((ZSubscr_t *) 0)
#define	NULLZHLT	((ZHostList_t *) 0)
#define	NULLZNAT	((ZNotAcked_t *) 0)
#define	NULLZACLT	((ZAcl_t *) 0)
#define	NULLZPT		((ZPacket_t *) 0)
#define	NULLZSDT	((ZServerDesc_t *) 0)
#define	NULLZSPT	((ZSrvPending_t *) 0)

/* me_server_idx is the index into otherservers of this server descriptor. */
/* the 'limbo' server is always the first server */

#define	me_server	(&otherservers[me_server_idx])
#define limbo_server_idx()	(0)
#define	limbo_server	(&otherservers[limbo_server_idx()])

#define msgs_queued()	(ZQLength() || otherservers[me_server_idx].zs_update_queue)

#define	ack(a,b)	clt_ack(a,b,SENT)
#define	nack(a,b)	clt_ack(a,b,NOT_SENT)

#define	max(a,b)	((a) > (b) ? (a) : (b))

/* the magic class to match all packets */
#define	MATCHALL_CLASS	"zmatch_all"
/* the instance that matches all instances */
#define	WILDCARD_INSTANCE	"*"

/* SERVER_SRVTAB is defined in zephyr.h */
#define	ZEPHYR_SRVTAB	SERVER_SRVTAB

#ifdef KERBEROS
#ifndef NOENCRYPTION
/* Kerberos shouldn't stick us with array types... */
typedef struct {
    des_key_schedule s;
} Sched;
#endif
#endif

/* debugging macros */
#ifdef DEBUG
#define zdbug(s1)	if (zdebug) syslog s1;
#else /* !DEBUG */
#define zdbug(s1)
#endif /* DEBUG */

#endif /* !__ZSERVER_H__ */
