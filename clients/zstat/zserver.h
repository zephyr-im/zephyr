#ifndef __ZSERVER_H__
#define __ZSERVER_H__
/* This file is part of the Project Athena Zephyr Notification System.
 * It contains declarations for use in the server.
 *
 *	Created by:	John T. Kohl
 *
 *	$Id$
 *
 *	Copyright (c) 1987,1988 by the Massachusetts Institute of Technology.
 *	For copying and distribution information, see the file
 *	"mit-copyright.h". 
 */

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

#endif /* !__ZSERVER_H__ */
