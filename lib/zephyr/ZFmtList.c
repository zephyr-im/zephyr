/* This file is part of the Project Athena Zephyr Notification System.
 * It contains source for the ZFormatNoticeList function.
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

Code_t ZFormatNoticeList(notice,list,nitems,buffer,buffer_len,ret_len)
	ZNotice_t	*notice;
	char		*list[];
	int		nitems;
	ZPacket_t	buffer;
	int		buffer_len;
	int		*ret_len;
{
	char *ptr,*end;
	Code_t retval;

	end = buffer+buffer_len;

	if ((retval = Z_FormatHeader(notice,buffer,buffer_len,ret_len)) !=
	    ZERR_NONE)
		return (retval);

	ptr = buffer+*ret_len;

	for (;nitems;nitems--,list++) {
		if (ptr+strlen(*list)+1 > end)
			return (ZERR_PKTLEN);
		bcopy(*list,ptr,strlen(*list)+1);
		*ret_len += strlen(*list)+1;
		ptr += strlen(*list)+1;
	}

	if (*ret_len > Z_MAXPKTLEN)
		return (ZERR_PKTLEN);

	return (ZERR_NONE);
}
