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

#define ZVERSION	0

/* Types */

	/* Packet */
typedef char ZPacket_t[BUFSIZ];

	/* Packet type */
typedef enum { UNACK, ACK, HMACK, SERVACK, SERVNAK } ZNotice_Kind_t;

	/* Unique ID format */
typedef struct _ZUnique_Id_t {
	struct	in_addr zuid_addr;
	struct	timeval	tv;
} ZUnique_Id_t;

	/* Checksum */
typedef int ZChecksum_t[2];

	/* Notice definition */
typedef struct _ZNotice_t {
	ZNotice_Kind_t	z_kind;
	ZChecksum_t	z_checksum;
	ZUnique_Id_t	z_uid;
#define z_sender_addr	z_uid.zuid_addr
	short		z_port;
	char		*z_class;
	char		*z_class_inst;
	char		*z_opcode;
	char		*z_sender;
	char		*z_recipient;
	caddr_t		z_message;
	int		z_message_len;
} ZNotice_t;

	/* Function return code */
typedef int Code_t;

	/* Socket file descriptor */
extern int __Zephyr_fd;

	/* Port number */
extern int __Zephyr_port;

	/* ZGetFD() macro */
#define ZGetFD() (__Zephyr_fd)

	/* Maximum packet length */
#define Z_MAXPKTLEN		576

	/* Maximum queue length */
#define Z_MAXQLEN		30

	/* UNIX error codes */
extern int errno;

	/* Successful function return */
#define ZERR_NONE		0

#endif !__ZEPHYR_H__
