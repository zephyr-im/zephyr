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

#ifndef lint
static char rcsid_ZSendPacket_c[] = "$Header$";
#endif lint

#include <zephyr/mit-copyright.h>

#include <zephyr/zephyr_internal.h>
#include <sys/socket.h>

Code_t ZSendPacket(packet, len, waitforack)
    char *packet;
    int len;
    int waitforack;
{
    int wait_for_hmack();
    Code_t retval;
    struct sockaddr_in dest;
    struct timeval tv, t0;
    fd_set zfdmask;
    int i, zfd;
    ZNotice_t notice, acknotice;
	
    if (!packet || len < 0)
	return (ZERR_ILLVAL);

    if (len > Z_MAXPKTLEN)
	return (ZERR_PKTLEN);
    
    if (ZGetFD() < 0)
	if ((retval = ZOpenPort((u_short *)0)) != ZERR_NONE)
	    return (retval);

    dest = ZGetDestAddr();
	
    if (sendto(ZGetFD(), packet, len, 0, (struct sockaddr *)&dest,
	       sizeof(dest)) < 0)
	return (errno);

    if (!waitforack)
	return (ZERR_NONE);

    if ((retval = ZParseNotice(packet, len, &notice)) != ZERR_NONE)
	return (retval);
    
    tv.tv_sec = HM_TIMEOUT;
    tv.tv_usec = 0;
    /* It is documented in select(2) that future versions of select
       will adjust the passed timeout to indicate the time remaining.
       When this is done, the variable t0 and all references to it
       can be removed.  */
    gettimeofday(&t0, 0);
    FD_ZERO(&zfdmask);
    zfd = ZGetFD();
    FD_SET(zfd, &zfdmask);
    while(1) {
      i = select(zfd + 1, &zfdmask, (fd_set *) 0, (fd_set *) 0, &tv);
      if(i > 0) {
	retval = ZCheckIfNotice(&acknotice, (struct sockaddr_in *)0,
				wait_for_hmack, (char *)&notice.z_uid);
	if (retval == ZERR_NONE) {
	  ZFreeNotice(&acknotice);
	  return (ZERR_NONE);
	}
	if (retval != ZERR_NONOTICE)
	  return (retval);
      } else if(i == 0) {	/* time out */
	return ZERR_HMDEAD;
      } else if(i < 0 && errno != EINTR) {
	return errno;
      }
      /* Here to end of loop deleted if/when select modifies passed timeout */
      gettimeofday(&tv, 0);
      tv.tv_usec = tv.tv_usec - t0.tv_usec;
      if(tv.tv_usec < 0)
	{
	  tv.tv_usec += 1000000;
	  tv.tv_sec = HM_TIMEOUT - 1 + tv.tv_sec - t0.tv_sec;
	} else {
	  tv.tv_sec = HM_TIMEOUT + tv.tv_sec - t0.tv_sec;
	}
    }
    return (ZERR_HMDEAD);
}

static int wait_for_hmack(notice, uid)
    ZNotice_t *notice;
    ZUnique_Id_t *uid;
{
    return (notice->z_kind == HMACK && ZCompareUID(&notice->z_uid, uid));
}
