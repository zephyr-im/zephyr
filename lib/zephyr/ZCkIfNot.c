/* This file is part of the Project Athena Zephyr Notification System.
 * It contains source for the ZCheckIfNotice function.
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

#include <zephyr/mit-copyright.h>

#include <zephyr/zephyr_internal.h>

Code_t ZCheckIfNotice(buffer,buffer_len,notice,auth,predicate,args)
	ZPacket_t	buffer;
	int		buffer_len;
	ZNotice_t	*notice;
	int		*auth;
	int		(*predicate)();
	char		*args;
{
	ZNotice_t tmpnotice;
	int qcount,retval,tmpauth;
	struct _Z_InputQ *qptr;

	if ((retval = Z_ReadEnqueue()) != ZERR_NONE)
		return (retval);
	
	qptr = __Q_Head;
	qcount = __Q_Length;
	
	for (;qcount;qcount--) {
		if ((retval = ZParseNotice(qptr->packet,qptr->packet_len,
					   &tmpnotice,auth?&tmpauth:0,
					   &qptr->from))
		    != ZERR_NONE)
			return (retval);
		if ((predicate)(&tmpnotice,args)) {
			if (qptr->packet_len > buffer_len)
				return (ZERR_PKTLEN);
			bcopy(qptr->packet,buffer,qptr->packet_len);
			if ((retval = ZParseNotice(buffer,qptr->packet_len,
						   notice,auth,
						   &qptr->from))
			    != ZERR_NONE)
				return (retval);
			return (Z_RemQueue(qptr));
		} 
		qptr = qptr->next;
	}

	return (ZERR_NONOTICE);
}
