/* This file is part of the Project Athena Zephyr Notification System.
 * It contains global definitions
 *
 *	Created by:	Robert French
 *
 *	$Source$
 *	$Author$
 *
 *	Copyright (c) 1987 by the Massachusetts Institute of Technology.
 *	For copying and distribution information, see the file
 *	"mit-copyright.h". 
 */
/* $Header$ */

#ifndef __ZEPHYR_H__
#define __ZEPHYR_H__

#include <zephyr/mit-copyright.h>
#include <zephyr/zephyr_err.h>

#include <errno.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/time.h>
#include <stdio.h>
#include <krb.h>

#define ZVERSION	0

/* Types */

	/* Packet */
typedef char ZPacket_t[BUFSIZ];

	/* Packet type */
typedef enum { UNSAFE, UNACKED, ACKED, HMACK, HMCTL, SERVACK, SERVNAK,
		       CLIENTACK } ZNotice_Kind_t;

	/* Unique ID format */
typedef struct _ZUnique_Id_t {
	struct	in_addr zuid_addr;
	struct	timeval	tv;
} ZUnique_Id_t;

	/* Checksum */
typedef u_long ZChecksum_t;

	/* Notice definition */
typedef struct _ZNotice_t {
	ZNotice_Kind_t	z_kind;
	ZUnique_Id_t	z_uid;
	u_short		z_port;
	int		z_auth;
	int		z_authent_len;
	char		*z_ascii_authent;
	char		*z_class;
	char		*z_class_inst;
	char		*z_opcode;
	char		*z_sender;
	char		*z_recipient;
	ZChecksum_t	z_checksum;
	caddr_t		z_message;
	int		z_message_len;
} ZNotice_t;

	/* Subscription structure */
typedef struct _ZSubscription_t {
	char		*recipient;
	char		*class;
	char		*classinst;
}  ZSubscription_t;

	/* Function return code */
typedef int Code_t;

	/* Socket file descriptor */
extern int __Zephyr_fd;

	/* Port number */
extern int __Zephyr_port;

	/* Desintation (HM) addr */
extern struct sockaddr_in __HM_addr;

	/* Kerberos error table base */
extern int krb_err_base;

	/* Session key for last parsed packet - server only */
extern C_Block __Zephyr_session;

	/* ZGetSession() macro */
#define ZGetSession() (__Zephyr_session)
	
	/* ZGetFD() macro */
#define ZGetFD() (__Zephyr_fd)

	/* ZGetDestAddr() macro */
#define ZGetDestAddr() (__HM_addr)

	/* Maximum packet length */
#define Z_MAXPKTLEN		576

	/* Maximum queue length */
#define Z_MAXQLEN		30

	/* UNIX error codes */
extern int errno;

	/* Successful function return */
#define ZERR_NONE		0

	/* Kerberos information */
#define SERVER_SERVICE		"zephyr"
#define SERVER_INSTANCE		"zephyr"
#define SERVER_SRVTAB		"/u1/zephyr/src/lib/srvtab"

	/* Packet strings */

#define ZSRVACK_SENT		"SENT"	/* SERVACK codes */
#define ZSRVACK_NOTSENT		"LOST"

#define ZEPHYR_ADMIN_CLASS	"ZEPHYR_ADMIN"

#define ZEPHYR_CTL_CLASS	"ZEPHYR_CTL"
#define ZEPHYR_CTL_CLIENT	"CLIENT"
#define CLIENT_SUBSCRIBE	"SUBSCRIBE"
#define CLIENT_UNSUBSCRIBE	"UNSUBSCRIBE"
#define CLIENT_CANCELSUB	"CLEARSUB"
#define ZEPHYR_CTL_HM		"HM"
#define HM_BOOT			"BOOT"
#define ZEPHYR_CTL_SERVER	"SERVER"
#define SERVER_SHUTDOWN		"SHUTDOWN"
#define SERVER_PING		"PING"

#define LOGIN_CLASS		"LOGIN"
#define LOGIN_USER_LOGIN	"USER_LOGIN"
#define LOGIN_QUIET_LOGIN	"QUIET_LOGIN"
#define LOGIN_USER_LOGOUT	"USER_LOGOUT"

#define LOCATE_CLASS		"USER_LOCATE"
#define LOCATE_HIDE		"USER_HIDE"
#define LOCATE_UNHIDE		"USER_UNHIDE"
#define LOCATE_LOCATE		"LOCATE"

#endif !__ZEPHYR_H__
