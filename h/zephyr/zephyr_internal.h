/* This file is part of the Project Athena Zephyr Notification System.
 * It contains internal definitions for the client library.
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

#ifndef __ZINTERNAL_H__
#define __ZINTERNAL_H__

#include <zephyr/zephyr.h>

struct _Z_InputQ {
	struct		_Z_InputQ *next;
	struct		_Z_InputQ *prev;
	int		packet_len;
	struct		sockaddr_in from;
	ZPacket_t	packet;
};

extern struct _Z_InputQ *__Q_Head, *__Q_Tail;
extern int __Q_Length;

extern int __Zephyr_open;
extern int __HM_set;
extern int __Zephyr_server;

extern char **__locate_list;
extern int __locate_num;
extern int __locate_next;

extern int Z_UIDpred();

#define Z_QLength() (__Q_Length)

#endif !__ZINTERNAL_H__
