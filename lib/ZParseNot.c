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
	char *ptr;
	int i;
	unsigned int temp[3];

	ptr = buffer;
	
	if (Z_ReadField(&ptr,temp,1))
		return (ZERR_BADPKT);
	
	if (*temp != ZVERSION)
		return (ZERR_VERS);

	if (Z_ReadField(&ptr,temp,1))
		return (ZERR_BADPKT);
	notice->z_kind = (ZNotice_Kind_t)*temp;

	if (Z_ReadField(&ptr,temp,1))
		return (ZERR_BADPKT);
	notice->z_port = (short)*temp;
	
	if (Z_ReadField(&ptr,temp,2))
		return (ZERR_BADPKT);
	bcopy(temp,notice->z_checksum,sizeof(ZChecksum_t));

	if (Z_ReadField(&ptr,temp,3))
		return (ZERR_BADPKT);
	bcopy(temp,&notice->z_uid,sizeof(ZUnique_Id_t));

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

	notice->z_message = (caddr_t) ptr;
	notice->z_message_len = len-(ptr-buffer);

	*auth = 0;

	return (ZERR_NONE);
}

int Z_ReadField(ptr,temp,num)
	char **ptr;
	int *temp;
	int num;
{
	int i;
	char *space;

	for (i=0;i<num;i++) {
		space = (char *)index(*ptr,' ');
		if ((*ptr)[0] != '0' || (*ptr)[1] != 'x')
			return (1);
		sscanf(*ptr+2,"%x",temp+i);
		if (space)
			*ptr = space+1;
		else
			*ptr += strlen(*ptr);
		if (!*ptr && i != num-1)
			return (1);
	}

	if (**ptr)
		return (1);
	(*ptr)++;
	return (0);
}
