/* This file is part of the Project Athena Zephyr Notification System.
 * It contains source for ZPeekPacket function.
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

Code_t ZPeekPacket(buffer,buffer_len,ret_len)
	ZPacket_t	buffer;
	int		buffer_len;
	int		*ret_len;
{
	int retval;
	
	if (ZGetFD() < 0)
		return (ZERR_NOPORT);

	if (!Z_QLength())
		if ((retval = Z_ReadWait()) != ZERR_NONE)
			return (retval);

	if (buffer_len < __Q_Head->packet_len) {
		*ret_len = buffer_len;
		retval = ZERR_PKTLEN;
	}
	else {
		*ret_len = __Q_Head->packet_len;
		retval = ZERR_NONE;
	}
	
	bcopy(__Q_Head->packet,buffer,*ret_len);

	return (retval);
}
