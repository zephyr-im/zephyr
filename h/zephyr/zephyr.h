/* This file is part of the Project Athena Zephyr Notification System.
 * It contains global definitions
 *
 *	Created by:	Robert French
 *
 *	$Source$
 *	$Author$
 *
 *	Copyright (c) 1987,1988 by the Massachusetts Institute of Technology.
 *	For copying and distribution information, see the file
 *	"mit-copyright.h".
 */
/* $Header$ */

#ifndef __ZEPHYR_H__
#define __ZEPHYR_H__

#include <zephyr/mit-copyright.h>
#include <zephyr/zephyr_err.h>
#include <zephyr/zephyr_conf.h>

#include <errno.h>
#include <sys/types.h>
#include <sys/time.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef KERBEROS
#include <krb.h>
#endif

#ifndef IPPROTO_MAX	/* Make sure not already included */
#include <netinet/in.h>
#endif

#if defined(__STDC__) || defined(__cplusplus)
#define Zproto(X) X
#else
#define Zproto(X) ()
#endif

#define ZVERSIONHDR	"ZEPH"
#define ZVERSIONMAJOR	0
#define ZVERSIONMINOR	2

    /* Types */

    /* Maximum size packet we can send */
#define Z_MAXPKTLEN		1024

    /* Packet */
    typedef char ZPacket_t[Z_MAXPKTLEN];

    /* Maximum size for a notice header */
#define Z_MAXHEADERLEN		800

    /* Maximum number of unknown fields in ZNotice_t */
#define Z_MAXOTHERFIELDS	10

    /* Authentication levels returned by ZCheckAuthentication */
#define ZAUTH_FAILED    (-1)
#define ZAUTH_YES       1
#define ZAUTH_NO        0

    /* Packet type */
    typedef enum { UNSAFE, UNACKED, ACKED, HMACK, HMCTL, SERVACK, SERVNAK,
		       CLIENTACK, STAT } ZNotice_Kind_t;

    /* Unique ID format */
    typedef struct _ZUnique_Id_t {
	struct	in_addr zuid_addr;
	struct	timeval	tv;
    } ZUnique_Id_t;

    /* Checksum */
    typedef u_long ZChecksum_t;

#define ZNUMFIELDS	17

    /* Notice definition */
    typedef struct _ZNotice_t {
	char		*z_packet;
	char		*z_version;
	ZNotice_Kind_t	z_kind;
	ZUnique_Id_t	z_uid;
#define z_sender_addr	z_uid.zuid_addr
	struct		timeval z_time;
	u_short		z_port;
	int			z_auth;
	int			z_authent_len;
	char		*z_ascii_authent;
	char		*z_class;
	char		*z_class_inst;
	char		*z_opcode;
	char		*z_sender;
	char		*z_recipient;
	char		*z_default_format;
	char		*z_multinotice;
	ZUnique_Id_t	z_multiuid;
	ZChecksum_t		z_checksum;
	int			z_num_other_fields;
	char		*z_other_fields[Z_MAXOTHERFIELDS];
	caddr_t		z_message;
	int			z_message_len;
    } ZNotice_t;

    /* Subscription structure */
    typedef struct _ZSubscriptions_t {
	char	*recipient;
#ifdef __cplusplus
	char	*zsub_class;
#else
	char	*class;		/* compat */
#endif
	char	*classinst;
	/* Please use these preferred names; those above will go away soon. */
#define zsub_recipient	recipient
#ifndef __cplusplus
#define zsub_class	class
#endif
#define zsub_classinst	classinst
    } ZSubscription_t;

    /* Function return code */
    typedef int Code_t;

    /* Locations structure */
    typedef struct _ZLocations_t {
	char	*host;
	char	*time;
	char	*tty;
    } ZLocations_t;

    /* Socket file descriptor */
    extern int __Zephyr_fd;

    /* Port number */
    extern int __Zephyr_port;

    /* Destination (HM) addr */
    extern struct sockaddr_in __HM_addr;

    /* for ZQLength */
    extern int __Q_CompleteLength;

    /* for ZGetRealm */
    extern char __Zephyr_realm[];

    /* Kerberos error table base */
    extern int krb_err_base;

    /* UNIX error codes */
    extern int errno;

#ifdef KERBEROS
    /* Session key for last parsed packet - server only */
    extern C_Block __Zephyr_session;
#endif

    /* ZCompareUIDPred definition */
    extern int ZCompareUIDPred Zproto((ZNotice_t *, ZUnique_Id_t *)),
	       ZCompareMultiUIDPred Zproto((ZNotice_t *, ZUnique_Id_t *));

    /* Defines for ZFormatNotice, et al. */
    typedef Code_t (*Z_AuthProc) Zproto((ZNotice_t*, char *, int, int *));
    extern Code_t ZMakeAuthentication Zproto((ZNotice_t*, char *,int, int*));

    /* Random declarations */
    extern char *ZGetSender Zproto((void)), *ZGetVariable Zproto((char *));
    extern int ZGetWGPort Zproto((void));
    extern Code_t ZSetDestAddr Zproto ((struct sockaddr_in *));
    extern Code_t ZFormatNoticeList Zproto((ZNotice_t*, char**, int,
					    char **, int*, Z_AuthProc));
    extern Code_t ZParseNotice Zproto((char*, int, ZNotice_t *));
    extern Code_t ZReadAscii Zproto((char*, int, unsigned char*, int));
    extern Code_t ZSendPacket Zproto((char*, int, int));
    extern Code_t ZFormatNotice Zproto((ZNotice_t*, char**, int*, Z_AuthProc));
    extern Code_t ZInitialize Zproto ((void));
    extern Code_t ZSetServerState Zproto((int));
    extern Code_t ZSetFD Zproto ((int));
    extern Code_t ZFormatSmallRawNotice Zproto ((ZNotice_t*, ZPacket_t, int*));
    extern int ZCompareUID Zproto ((ZUnique_Id_t*, ZUnique_Id_t*));
    extern Code_t ZSrvSendRawList Zproto ((ZNotice_t*, char*[], int,
					   Code_t (*)(ZNotice_t *, char *,
						      int, int)));
    extern Code_t ZMakeAscii Zproto ((char*, int, unsigned char*, int));
    extern Code_t ZReceivePacket Zproto ((ZPacket_t, int*,
					  struct sockaddr_in*));
    extern Code_t ZCheckAuthentication Zproto ((ZNotice_t*,
						struct sockaddr_in*));
    extern Code_t ZFormatAuthenticNotice Zproto ((ZNotice_t*, char*, int,
						  int*, C_Block));
    extern Code_t ZFormatRawNotice Zproto ((ZNotice_t *, char**, int *));

    /* ZGetSession() macro */
#define ZGetSession() (__Zephyr_session)

#ifndef __cplusplus
    /* ZGetFD() macro */
#define ZGetFD() (__Zephyr_fd)

    /* ZQLength macro */
#define ZQLength() (__Q_CompleteLength)

    /* ZGetDestAddr() macro */
#define ZGetDestAddr() (__HM_addr)

    /* ZGetRealm() macro */
#define ZGetRealm() (__Zephyr_realm)

    /* Maximum queue length */
#define Z_MAXQLEN 		30

    /* Successful function return */
#define ZERR_NONE		0

    /* Hostmanager wait time (in secs) */
#define HM_TIMEOUT		30

#define ZAUTH (ZMakeAuthentication)
#define ZNOAUTH ((Z_AuthProc)0)

#else /* C++ */

    inline int ZGetFD () { return __Zephyr_fd; }

    inline int ZQLength () { return __Q_CompleteLength; }

    inline const sockaddr_in& ZGetDestAddr () { return __HM_addr; }

    inline const char* ZGetRealm () { return __Zephyr_realm; }

    const int Z_MAXQLEN = 30;

    const int ZERR_NONE = 0;

    const int HM_TIMEOUT = 30;

    const Z_AuthProc ZAUTH = &ZMakeAuthentication;
    const Z_AuthProc ZNOAUTH = 0;

#endif


    /* Packet strings */

#define ZSRVACK_SENT		"SENT"	/* SERVACK codes */
#define ZSRVACK_NOTSENT		"LOST"
#define ZSRVACK_FAIL		"FAIL"

    /* Server internal class */
#define ZEPHYR_ADMIN_CLASS	"ZEPHYR_ADMIN"	/* Class */

    /* Control codes sent to a server */
#define ZEPHYR_CTL_CLASS	"ZEPHYR_CTL"	/* Class */

#define ZEPHYR_CTL_CLIENT	"CLIENT"	/* Inst: From client */
#define CLIENT_SUBSCRIBE	"SUBSCRIBE"	/* Opcode: Subscribe */
#define CLIENT_SUBSCRIBE_NODEFS	"SUBSCRIBE_NODEFS"	/* Opcode: Subscribe */
#define CLIENT_UNSUBSCRIBE	"UNSUBSCRIBE"	/* Opcode: Unsubsubscribe */
#define CLIENT_CANCELSUB	"CLEARSUB"	/* Opcode: Clear all subs */
#define CLIENT_GIMMESUBS	"GIMME"		/* Opcode: Give me subs */
#define	CLIENT_GIMMEDEFS	"GIMMEDEFS"	/* Opcode: Give me default
						 * subscriptions */

#define ZEPHYR_CTL_HM		"HM"		/* Inst: From HM */
#define HM_BOOT			"BOOT"		/* Opcode: Boot msg */
#define HM_FLUSH		"FLUSH"		/* Opcode: Flush me */
#define HM_DETACH		"DETACH"	/* Opcode: Detach me */
#define HM_ATTACH		"ATTACH"	/* Opcode: Attach me */

    /* Control codes send to a HostManager */
#define	HM_CTL_CLASS		"HM_CTL"	/* Class */

#define HM_CTL_SERVER		"SERVER"	/* Inst: From server */
#define SERVER_SHUTDOWN		"SHUTDOWN"	/* Opcode: Server shutdown */
#define SERVER_PING		"PING"		/* Opcode: PING */

#define HM_CTL_CLIENT           "CLIENT"        /* Inst: From client */
#define CLIENT_FLUSH            "FLUSH"         /* Opcode: Send flush to srv */
#define CLIENT_NEW_SERVER       "NEWSERV"       /* Opcode: Find new server */

    /* HM Statistics */
#define HM_STAT_CLASS		"HM_STAT"	/* Class */

#define HM_STAT_CLIENT		"HMST_CLIENT"	/* Inst: From client */
#define HM_GIMMESTATS		"GIMMESTATS"	/* Opcode: get stats */

    /* Login class messages */
#define LOGIN_CLASS		"LOGIN"		/* Class */

    /* Class Instance is principal of user who is logging in or logging out */

#define EXPOSE_NONE		"NONE"		/* Opcode: Not visible */
#define EXPOSE_OPSTAFF		"OPSTAFF"	/* Opcode: Opstaff visible */
#define EXPOSE_REALMVIS		"REALM-VISIBLE"	/* Opcode: Realm visible */
#define EXPOSE_REALMANN		"REALM-ANNOUNCED"/* Opcode: Realm announced */
#define EXPOSE_NETVIS		"NET-VISIBLE"	/* Opcode: Net visible */
#define EXPOSE_NETANN		"NET-ANNOUNCED"	/* Opcode: Net announced */
#define	LOGIN_USER_LOGIN	"USER_LOGIN"	/* Opcode: user login
						   (from server) */
#define LOGIN_USER_LOGOUT	"USER_LOGOUT"	/* Opcode: User logout */
#define	LOGIN_USER_FLUSH	"USER_FLUSH"	/* Opcode: flush all locs */

    /* Locate class messages */
#define LOCATE_CLASS		"USER_LOCATE"	/* Class */

#define LOCATE_HIDE		"USER_HIDE"	/* Opcode: Hide me */
#define LOCATE_UNHIDE		"USER_UNHIDE"	/* Opcode: Unhide me */

    /* Class Instance is principal of user to locate */

#define LOCATE_LOCATE		"LOCATE"	/* Opcode: Locate user */

    /* WG_CTL class messages */
#define WG_CTL_CLASS		"WG_CTL"	/* Class */

#define WG_CTL_USER		"USER"		/* Inst: User request */
#define USER_REREAD		"REREAD"	/* Opcode: Reread desc file */
#define USER_SHUTDOWN		"SHUTDOWN"	/* Opcode: Go catatonic */
#define USER_STARTUP		"STARTUP"	/* Opcode: Come out of it */

#ifdef __cplusplus
}
#endif

#endif !__ZEPHYR_H__
