/* This file is part of the Project Athena Zephyr Notification System.
 * It contains source for the ZParseNotice function.
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

Code_t ZParseNotice(buffer,len,notice,auth)
	ZPacket_t	buffer;
	int		len;
	ZNotice_t	*notice;
	int		*auth;
{
	int hdrlen;
	char *ptr;

	hdrlen = *((short *)buffer);

	ptr = buffer+2;

	if (*ptr++ != ZVERSION)
		return (ZERR_VERS);

	notice->z_kind = (ZNotice_Kind_t)*ptr++;
	bcopy(ptr,notice->z_checksum,sizeof(ZChecksum_t));
	ptr += sizeof(ZChecksum_t);
	bcopy(ptr,&notice->z_uid,sizeof(ZUnique_Id_t));
	ptr += sizeof(ZUnique_Id_t);
	notice->z_port = *((short *)ptr);
	ptr += sizeof(short);
	notice->z_class = ptr;
	ptr += strlen(ptr)+1;
	notice->z_class_inst = ptr;
	ptr += strlen(ptr)+1;
	notice->z_opcode = ptr;
	ptr += strlen(ptr)+1;
	notice->z_sender = ptr;
	ptr += strlen(ptr)+1;
	notice->z_recipient = ptr;
	ptr += strlen(ptr)+1;

	if (ptr-buffer != hdrlen)
		return(ZERR_BADPKT);

	notice->z_message = (caddr_t) ptr;
	notice->z_message_len = len-hdrlen;

	*auth = 0;
}
