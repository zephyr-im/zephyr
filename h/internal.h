
#ifndef __INTERNAL_H__
#define __INTERNAL_H__

#include <sysdep.h>
#include <zephyr/zephyr.h>
#include <netdb.h>

#ifdef HAVE_KRB5
#include <krb5.h>
#endif

#ifdef HAVE_HESIOD
#include <hesiod.h>
#endif

#include <arpa/nameser.h>
#ifdef HAVE_ARPA_NAMESER_COMPAT_H
#include <arpa/nameser_compat.h>
#endif
#ifndef REALM_SZ  /* XXX */
#define REALM_SZ	NS_MAXDNAME
#endif
#define MAX_PRINCIPAL_SIZE	1024

#define SERVER_SVC_FALLBACK	htons((unsigned short) 2103)
#define HM_SVC_FALLBACK		htons((unsigned short) 2104)
#define HM_SRV_SVC_FALLBACK	htons((unsigned short) 2105)

#define ZSUBAUTH (Z_MakeAuthenticationSaveKey)

#define ZAUTH_UNSET		(-3) /* Internal to client library. */
#define Z_MAXFRAGS		500	/* Max number of packet fragments */
#define Z_MAXNOTICESIZE		400000	/* Max size of incoming notice */
#define Z_MAXQUEUESIZE		1500000	/* Max size of input queue notices */
#define Z_FRAGFUDGE		13	/* Room to for multinotice field */
#define Z_NOTICETIMELIMIT	30	/* Time to wait for fragments */
#define Z_INITFILTERSIZE	30	/* Starting size of uid filter */
#define Z_FILTERTIMELIMIT	900	/* Max time to cache packet ids */

#define Z_AUTHMODE_NONE          0      /* no authentication */
#define Z_AUTHMODE_KRB4          1      /* authenticate using Kerberos V4 */
#define Z_AUTHMODE_KRB5          2      /* authenticate using Kerberos V5 */

#define Z_KEYUSAGE_CLT_CKSUM  1027    /* client->server notice checksum */
#define Z_KEYUSAGE_SRV_CKSUM  1029    /* server->client notice checksum */

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

extern struct _Z_InputQ *__Q_Head, *__Q_Tail;

extern int __Zephyr_open;	/* 0 if FD opened, 1 otherwise */
extern int __HM_set;		/* 0 if dest addr set, 1 otherwise */
extern int __Zephyr_server;	/* 0 if normal client, 1 if server or zhm */

#ifdef HAVE_KRB5
extern krb5_context Z_krb5_ctx;
Code_t Z_krb5_lookup_cksumtype(krb5_enctype, krb5_cksumtype *);

struct _Z_SessionKey {
    struct _Z_SessionKey    *next;
    struct _Z_SessionKey    *prev;
    krb5_keyblock	    *keyblock;
    time_t		    send_time;
    time_t		    first_use;
};

extern struct _Z_SessionKey *Z_keys_head, *Z_keys_tail;

/*
 * The maximum time we allow for a notice to get delivered. This is used for
 * two timeouts in key expirey. First, we assume that any subscription notice
 * was reached the server within that time; this allows us to assume old keys
 * sent sufficiently long before a newer, verified key are stale. Second, we
 * assume notices authenticated with an old key reach us in that time; this
 * allows us to prune stale keys after a timeout.
*/
#define KEY_TIMEOUT 60
#endif

extern ZLocations_t *__locate_list;
extern int __locate_num;
extern int __locate_next;

extern ZSubscription_t *__subscriptions_list;
extern int __subscriptions_num;
extern int __subscriptions_next;

extern int __Zephyr_port;		/* Port number */
extern struct in_addr __My_addr;
extern int __Zephyr_fd;
extern int __Q_CompleteLength;
extern struct sockaddr_in __HM_addr;
extern char __Zephyr_realm[];

typedef Code_t (*Z_SendProc) (ZNotice_t *, char *, int, int);

struct _Z_InputQ *Z_GetFirstComplete (void);
struct _Z_InputQ *Z_GetNextComplete (struct _Z_InputQ *);
struct _Z_InputQ *Z_SearchQueue (ZUnique_Id_t *, ZNotice_Kind_t);
Code_t Z_XmitFragment (ZNotice_t*, char *,int,int);
void Z_RemQueue (struct _Z_InputQ *);
Code_t Z_AddNoticeToEntry (struct _Z_InputQ*, ZNotice_t*, int);
Code_t Z_FormatAuthHeader (ZNotice_t *, char *, int, int *, Z_AuthProc);
Code_t Z_FormatAuthHeaderWithASCIIAddress (ZNotice_t *, char *, int, int *);
Code_t Z_FormatHeader (ZNotice_t *, char *, int, int *, Z_AuthProc);
Code_t Z_FormatRawHeader (ZNotice_t *, char*, int,
			      int*, char **, char **);
Code_t Z_ReadEnqueue (void);
Code_t Z_ReadWait (void);
int Z_PacketWaiting (void);
Code_t Z_SendLocation (char*, char*, char*, Z_AuthProc, char*);
Code_t Z_SendFragmentedNotice (ZNotice_t *notice, int len,
				   Z_AuthProc cert_func,
				   Z_SendProc send_func);
Code_t Z_WaitForComplete (void);
Code_t Z_WaitForNotice (ZNotice_t *notice,
			int (*pred)(ZNotice_t *, void *), void *arg,
			int timeout);


Code_t Z_NewFormatHeader (ZNotice_t *, char *, int, int *, Z_AuthProc);
Code_t Z_NewFormatAuthHeader (ZNotice_t *, char *, int, int *, Z_AuthProc);
Code_t Z_NewFormatRawHeader (ZNotice_t *, char *, int, int *, char **,
                                 int *, char **, char **);
Code_t Z_AsciiFormatRawHeader (ZNotice_t *, char *, int, int *, char **,
                                 int *, char **, char **);

void Z_gettimeofday(struct _ZTimeval *ztv, struct timezone *tz);

Code_t Z_MakeAuthenticationSaveKey(ZNotice_t*, char *,int, int*);

#ifdef HAVE_KRB5
int ZGetCreds(krb5_creds **creds_out);
int ZGetCredsRealm(krb5_creds **creds_out, char *realm);
Code_t Z_Checksum(krb5_data *cksumbuf, krb5_keyblock *keyblock,
		  krb5_cksumtype cksumtype, krb5_keyusage cksumusage,
		  char **asn1_data, unsigned int *asn1_len);
Code_t Z_ExtractEncCksum(krb5_keyblock *keyblock, krb5_enctype *enctype,
			 krb5_cksumtype *cksumtype);
int Z_krb5_verify_cksum(krb5_keyblock *keyblock, krb5_data *cksumbuf,
			krb5_cksumtype cksumtype, krb5_keyusage cksumusage,
			unsigned char *asn1_data, int asn1_len);
Code_t Z_MakeZcodeAuthentication(register ZNotice_t *notice,
				 char *buffer, int buffer_len,
				 int *phdr_len,
				 krb5_creds *creds);
Code_t Z_InsertZcodeChecksum(krb5_keyblock *keyblock, ZNotice_t *notice,
                             char *buffer,
                             char *cksum_start, int cksum_len,
                             char *cstart, char *cend, int buffer_len,
                             int *length_ajdust, int from_server);
unsigned long z_quad_cksum(const unsigned char *, uint32_t *, long,
			   int, unsigned char *);
Code_t ZFormatAuthenticNoticeV5(ZNotice_t*, char*, int, int*, krb5_keyblock *);
#endif

#ifdef HAVE_KRB5_CREDS_KEYBLOCK_ENCTYPE
#define Z_keydata(keyblock)	((keyblock)->contents)
#define Z_keylen(keyblock)	((keyblock)->length)
#define Z_credskey(creds)	(&(creds)->keyblock)
#define Z_enctype(keyblock)	((keyblock)->enctype)
#else
#define Z_keydata(keyblock)	((keyblock)->keyvalue.data)
#define Z_keylen(keyblock)	((keyblock)->keyvalue.length)
#define Z_credskey(creds)	(&(creds)->session)
#define Z_enctype(keyblock)	((keyblock)->keytype)
#endif

#ifdef HAVE_KRB5_TICKET_ENC_PART2
#define Z_tktprincp(tkt)	((tkt)->enc_part2 != 0)
#define Z_tktprinc(tkt)		((tkt)->enc_part2->client)
#else
#define	Z_tktprincp(tkt)	((tkt)->client != 0)
#define Z_tktprinc(tkt)		((tkt)->client)
#endif

#endif /* __INTERNAL_H__ */
