/* This file is part of the Project Athena Zephyr Notification System.
 * It contains source for the ZSendPacket function.
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
#include <sys/socket.h>

Code_t ZSendPacket(packet,len)
	ZPacket_t	packet;
	int		len;
{
	Code_t retval;
	struct sockaddr_in dest;
	struct timeval tv;
	int i;
	fd_set t1,t2,t3;
	ZPacket_t ackpack;
	ZNotice_t notice;
	
	if (!packet || len < 0 || len > Z_MAXPKTLEN)
		return (ZERR_ILLVAL);

	if (ZGetFD() < 0)
		if ((retval = ZOpenPort((u_short *)0)) != ZERR_NONE)
			return (retval);

	if ((retval = Z_InternalParseNotice(packet,len,&notice,(int *)0,
				   (struct sockaddr_in *)0),(int (*)())0)
	    != ZERR_NONE)
		return (retval);

	dest = ZGetDestAddr();
	
	if (sendto(ZGetFD(),packet,len,0,&dest,sizeof(dest)) < 0)
		return (errno);

	if (notice.z_kind == UNSAFE || notice.z_kind == HMACK ||
	    notice.z_kind == SERVACK || notice.z_kind == CLIENTACK ||
	    __Zephyr_server || __HM_set)
		return (ZERR_NONE);
	
	tv.tv_sec = 0;
	tv.tv_usec = 500000;
	
	for (i=0;i<HM_TIMEOUT*2;i++) {
		if (select(0,&t1,&t2,&t3,&tv) < 0)
			return (errno);
		retval = Z_NoAuthCheckIfNotice(ackpack,sizeof ackpack,&notice,
					       ZCompareUIDPred,
					       (char *)&notice.z_uid);
		if (retval == ZERR_NONE)
			return (ZERR_NONE);
		if (retval != ZERR_NONOTICE)
			return (retval);
	}
	return (ZERR_HMDEAD);
}
