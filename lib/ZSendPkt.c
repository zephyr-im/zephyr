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
	int findack();
	
	Code_t retval;
	struct sockaddr_in sin;
	struct timeval tv;
	int auth,t1,t2,t3,i;
	ZPacket_t ackpack;
	ZNotice_t notice;
	
	if (!packet || len < 0 || len > Z_MAXPKTLEN)
		return (ZERR_ILLVAL);

	if (ZGetFD() < 0)
		if ((retval = ZOpenPort(0)) != ZERR_NONE)
			return (retval);

	if ((retval = Z_GetHMPortAddr()) != ZERR_NONE)
		return (retval);

	sin.sin_family = AF_INET;
	sin.sin_port = htons(__HM_port);
	bcopy(__HM_addr,&sin.sin_addr,__HM_length);

	if (sendto(ZGetFD(),packet,len,0,&sin,sizeof(sin)) < 0)
		return (errno);

	ZParseNotice(packet,len,&notice,&auth);

	tv.tv_sec = 0;
	tv.tv_usec = 400000;
	
	for (i=0;i<4;i++) {
		select(0,&t1,&t2,&t3,&tv);
		retval = ZCheckIfNotice(ackpack,sizeof ackpack,&notice,
					&auth,findack,&notice.z_uid);
		if (retval == ZERR_NONE)
			return (ZERR_NONE);
		if (retval != ZERR_NONOTICE)
			return (retval);
	}
	return (ZERR_HMDEAD);
}

int findack(notice,uid)
	ZNotice_t *notice;
	ZUnique_Id_t *uid;
{
	printf("FOO\n");
	return (!ZCompareUID(uid,&notice->z_uid));
}
