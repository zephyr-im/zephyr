/* This file is part of the Project Athena Zephyr Notification System.
 * It contains source for the ZFormatNotice function.
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

#include <zephyr/zephyr.h>

Code_t ZFormatNotice(notice,buffer,buffer_len,len)
	ZNotice_t	*notice;
	ZPacket_t	buffer;
	int		buffer_len;
	int		*len;
{
	char *ptr;
	int hdrlen;
	Code_t retval;

	if ((retval = Z_FormatHeader(notice,buffer,buffer_len,&hdrlen)) > 0)
		return (retval);

	ptr = buffer+hdrlen;

	if (notice->z_message_len+hdrlen > buffer_len)
		return (ZERR_PKTLEN);

	bcopy(notice->z_message,ptr,notice->z_message_len);

	*len = hdrlen+notice->z_message_len;

	if (*len > Z_MAXPKTLEN)
		return (ZERR_PKTLEN);

	return (ZERR_NONE);
}
