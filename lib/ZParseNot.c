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

#ifndef lint
static char rcsid_ZParseNotice_c[] = "$Header$";
#endif lint

#include <zephyr/mit-copyright.h>

#include <zephyr/zephyr_internal.h>

Code_t ZParseNotice(buffer, len, notice)
    char *buffer;
    int len;
    ZNotice_t *notice;
{
    char *ptr, *end;
    int maj, numfields, i;
    unsigned int temp[3];

    bzero(notice, sizeof(ZNotice_t));
	
    ptr = buffer;
    end = buffer+len;

    notice->z_packet = buffer;
    
    notice->z_version = ptr;
    if (strncmp(ptr, ZVERSIONHDR, strlen(ZVERSIONHDR)))
	return (ZERR_VERS);
    ptr += strlen(ZVERSIONHDR);
    maj = atoi(ptr);
    if (maj != ZVERSIONMAJOR)
	return (ZERR_VERS);
    ptr += strlen(ptr)+1;

    if (ZReadAscii(ptr, end-ptr, (unsigned char *)temp,
		   sizeof(int)) == ZERR_BADFIELD)
	return (ZERR_BADPKT);
    numfields = ntohl(*temp);
    ptr += strlen(ptr)+1;

    /*XXX 3 */
    numfields -= 2; /* numfields, version, and checksum */
    if (numfields < 0)
	return (ZERR_BADPKT);

    if (numfields) {
	if (ZReadAscii(ptr, end-ptr, (unsigned char *)temp, 
		       sizeof(int)) == ZERR_BADFIELD)
	    return (ZERR_BADPKT);
	notice->z_kind = (ZNotice_Kind_t)ntohl(*temp);
	numfields--;
	ptr += strlen(ptr)+1;
    }
    else
	return (ZERR_BADPKT);
	
    if (numfields) {
	if (ZReadAscii(ptr, end-ptr, (unsigned char *)temp, 
		       sizeof(ZUnique_Id_t)) == ZERR_BADFIELD)
	    return (ZERR_BADPKT);
	bcopy((char *)temp, (char *)&notice->z_uid, sizeof(ZUnique_Id_t));
	notice->z_time.tv_sec = ntohl(notice->z_uid.tv.tv_sec);
	notice->z_time.tv_usec = ntohl(notice->z_uid.tv.tv_usec);
	numfields--;
	ptr += strlen(ptr)+1;
    }
    else
	return (ZERR_BADPKT);
	
    if (numfields) {
	if (ZReadAscii(ptr, end-ptr, (unsigned char *)temp, 
		       sizeof(u_short)) ==
	    ZERR_BADFIELD)
	    return (ZERR_BADPKT);
	notice->z_port = *((u_short *)temp);
	numfields--;
	ptr += strlen(ptr)+1;
    }
    else
	return (ZERR_BADPKT);

    if (numfields) {
	if (ZReadAscii(ptr, end-ptr, (unsigned char *)temp, 
		       sizeof(int)) == ZERR_BADFIELD)
	    return (ZERR_BADPKT);
	notice->z_auth = *temp;
	numfields--;
	ptr += strlen(ptr)+1;
    }
    else
	return (ZERR_BADPKT);
	
    if (numfields) {
	if (ZReadAscii(ptr, end-ptr, (unsigned char *)temp, 
		       sizeof(int)) == ZERR_BADFIELD)
	    return (ZERR_BADPKT);
	notice->z_authent_len = ntohl(*temp);
	numfields--;
	ptr += strlen(ptr)+1;
    }
    else
	return (ZERR_BADPKT);

    if (numfields) {
	notice->z_ascii_authent = ptr;
	numfields--;
	ptr += strlen(ptr)+1;
    }
    else
	return (ZERR_BADPKT);

    if (numfields) {
	notice->z_class = ptr;
	numfields--;
	ptr += strlen(ptr)+1;
    }
    else
	notice->z_class = "";
	
    if (numfields) {
	notice->z_class_inst = ptr;
	numfields--;
	ptr += strlen(ptr)+1;
    }
    else
	notice->z_class_inst = "";

    if (numfields) {
	notice->z_opcode = ptr;
	numfields--;
	ptr += strlen(ptr)+1;
    }
    else
	notice->z_opcode = "";

    if (numfields) {
	notice->z_sender = ptr;
	numfields--;
	ptr += strlen(ptr)+1;
    }
    else
	notice->z_sender = "";

    if (numfields) {
	notice->z_recipient = ptr;
	numfields--;
	ptr += strlen(ptr)+1;
    }
    else
	notice->z_recipient = "";

    if (numfields) {
	notice->z_default_format = ptr;
	numfields--;
	ptr += strlen(ptr)+1;
    }
    else
	notice->z_default_format = "";
	
/*XXX*/
    if (ZReadAscii(ptr, end-ptr, (unsigned char *)temp, 
		   sizeof(ZChecksum_t))
	== ZERR_BADFIELD)
	return (ZERR_BADPKT);
    notice->z_checksum = ntohl(*temp);
    numfields--;
    ptr += strlen(ptr)+1;

    if (numfields) {
	notice->z_multinotice = ptr;
	numfields--;
	ptr += strlen(ptr)+1;
    }
    else
	notice->z_multinotice = "";

    if (numfields) {
	if (ZReadAscii(ptr, end-ptr, (unsigned char *)temp, 
		       sizeof(ZUnique_Id_t)) == ZERR_BADFIELD)
	    return (ZERR_BADPKT);
	bcopy((char *)temp, (char *)&notice->z_multiuid, sizeof(ZUnique_Id_t));
	notice->z_time.tv_sec = ntohl(notice->z_multiuid.tv.tv_sec);
	notice->z_time.tv_usec = ntohl(notice->z_multiuid.tv.tv_usec);
	numfields--;
	ptr += strlen(ptr)+1;
    }
    else
	bcopy((char *) &notice->z_uid, (char *) &notice->z_multiuid,
	      sizeof(ZUnique_Id_t));

    for (i=0;i<Z_MAXOTHERFIELDS && numfields;i++,numfields--) {
	notice->z_other_fields[i] = ptr;
	numfields--;
	ptr += strlen(ptr)+1;
    }
    notice->z_num_other_fields = i;
    
    for (i=0;i<numfields;i++)
	ptr += strlen(ptr)+1;
	
#ifdef notdef
    if (ZReadAscii(ptr, end-ptr, (unsigned char *)temp, 
		   sizeof(ZChecksum_t))
	== ZERR_BADFIELD)
	return (ZERR_BADPKT);
    notice->z_checksum = ntohl(*temp);
    numfields--;
    ptr += strlen(ptr)+1;
#endif
    
    notice->z_message = (caddr_t) ptr;
    notice->z_message_len = len-(ptr-buffer);

    return (ZERR_NONE);
}
