
#ifndef __INTERNAL_H__
#define __INTERNAL_H__

#include <sysdep.h>
#include <zephyr/zephyr.h>
#include <netdb.h>

#ifdef HAVE_KRB4
#include <krb.h>
#include <krb_err.h>
#endif

#ifdef HAVE_HESIOD
#include <hesiod.h>
#endif

#ifndef HAVE_KRB4
#define REALM_SZ	MAXHOSTNAMELEN
#define INST_SZ		0		/* no instances w/o Kerberos */
#define ANAME_SZ	9		/* size of a username + null */
#define CLOCK_SKEW	300		/* max time to cache packet ids */
#endif

#define SERVER_SVC_FALLBACK	htons((unsigned short) 2103)
#define HM_SVC_FALLBACK		htons((unsigned short) 2104)
#define HM_SRV_SVC_FALLBACK	htons((unsigned short) 2105)

#define ZAUTH_CKSUM_FAILED	(-2) /* Used only by server. */
#define ZAUTH_UNSET		(-3) /* Internal to client library. */
#define Z_MAXFRAGS		500	/* Max number of packet fragments */
#define Z_MAXNOTICESIZE		400000	/* Max size of incoming notice */
#define Z_MAXQUEUESIZE		1500000	/* Max size of input queue notices */
#define Z_FRAGFUDGE		13	/* Room to for multinotice field */
#define Z_NOTICETIMELIMIT	30	/* Time to wait for fragments */
#define Z_INITFILTERSIZE	30	/* Starting size of uid filter */

struct _Z_Hole {
    struct _Z_Hole	*next;
    int			first;
    int			last;
};

struct _Z_InputQ {
    struct _Z_InputQ	*next;
    struct _Z_InputQ	*prev;
    ZNotice_Kind_t	kind;
    unsigned ZEPHYR_INT32 timep;
    int			packet_len;
    char		*packet;
    int			complete;
    struct sockaddr_in	from;
    struct _Z_Hole	*holelist;
    ZUnique_Id_t	uid;
    int			auth;
    int			header_len;
    char		*header;
    int			msg_len;
    char		*msg;
};

typedef struct _Z_SrvNameAddr {
   char *name;
   struct in_addr addr;
   struct in_addr my_addr;
} Z_SrvNameAddr;

typedef struct _Z_GalaxyConfig {
   char *galaxy;
   Z_SrvNameAddr *server_list;
   int nservers;
} Z_GalaxyConfig;

typedef struct _Z_GalaxyList {
   Z_GalaxyConfig galaxy_config;
#ifdef HAVE_KRB4
   char krealm[REALM_SZ];
   long last_authent_time;
   KTEXT_ST last_authent;
#endif
} Z_GalaxyList;

extern struct _Z_InputQ *__Q_Head, *__Q_Tail;

extern int __Zephyr_open;	/* 0 if FD opened, 1 otherwise */
extern int __Zephyr_server;	/* 0 if normal client, 1 if server or zhm */

extern Z_GalaxyList *__galaxy_list;
extern int __ngalaxies;
extern int __default_galaxy;

extern ZLocations_t *__locate_list;
extern int __locate_num;
extern int __locate_next;

extern ZSubscription_t *__subscriptions_list;
extern int __subscriptions_num;
extern int __subscriptions_next;

extern int __Zephyr_port;		/* Port number */
extern struct in_addr __My_addr;

typedef Code_t (*Z_SendProc) __P((ZNotice_t *, char *, int, int));

struct _Z_InputQ *Z_GetFirstComplete __P((void));
struct _Z_InputQ *Z_GetNextComplete __P((struct _Z_InputQ *));
Code_t Z_XmitFragment __P((ZNotice_t*, char *,int,int));
void Z_RemQueue __P((struct _Z_InputQ *));
Code_t Z_AddNoticeToEntry __P((struct _Z_InputQ*, ZNotice_t*, int));
Code_t Z_FormatAuthHeader __P((ZNotice_t *, char *, int, int *, Z_AuthProc));
Code_t Z_FormatHeader __P((ZNotice_t *, char *, int, int *, Z_AuthProc));
Code_t Z_FormatRawHeader __P((ZNotice_t *, char*, int,
			      int*, char **, int*, char **, char **));
void Z_SourceAddr __P((struct in_addr *, struct in_addr *));
Code_t Z_FreeGalaxyConfig(Z_GalaxyConfig *);
Code_t Z_ParseGalaxyConfig(char *, Z_GalaxyConfig *);
Code_t Z_ReadEnqueue __P((void));
Code_t Z_ReadWait __P((void));
Code_t Z_SendLocation __P((char *, char*, char*, Z_AuthProc, char*));
Code_t Z_SendFragmentedNotice __P((ZNotice_t *notice, int len,
				   Z_AuthProc cert_func,
				   Z_SendProc send_func));
Code_t Z_WaitForComplete __P((void));
Code_t Z_WaitForNotice __P((ZNotice_t *notice,
			    int (*pred) __P((ZNotice_t *, void *)), void *arg,
			    int timeout));

void Z_gettimeofday(struct _ZTimeval *ztv, struct timezone *tz);
#endif /* __INTERNAL_H__ */

