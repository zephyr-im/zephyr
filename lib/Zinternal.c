/* This file is part of the Project Athena Zephyr Notification System.
 * It contains source for the internal Zephyr routines.
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
static char rcsid_Zinternal_c[] = "$Header$";
#endif lint

#include <zephyr/mit-copyright.h>

#include <zephyr/zephyr_internal.h>
#include <netdb.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <utmp.h>

int __Zephyr_fd = -1;
int __Zephyr_open = 0;
int __Zephyr_port = -1;
int __My_length;
char *__My_addr;
int __Q_CompleteLength = 0;
struct _Z_InputQ *__Q_Head = 0, *__Q_Tail = 0;
struct sockaddr_in __HM_addr;
int __HM_set = 0;
C_Block __Zephyr_session;
int __Zephyr_server = 0;
char __Zephyr_realm[REALM_SZ];
ZLocations_t *__locate_list = 0;
int __locate_num = 0;
int __locate_next = 0;
ZSubscription_t *__subscriptions_list = 0;
int __subscriptions_num = 0;
int __subscriptions_next = 0;

#define min(a,b) ((a)<(b)?(a):(b))

Code_t Z_GetMyAddr()
{
    struct hostent *myhost;
    char hostname[MAXHOSTNAMELEN];
	
    if (__My_length > 0)
	return (ZERR_NONE);

    if (gethostname(hostname, MAXHOSTNAMELEN) < 0)
	return (errno);

    if (!(myhost = gethostbyname(hostname)))
	return (errno);

    if (!(__My_addr = (char *)malloc((unsigned)myhost->h_length)))
	return (ENOMEM);

    __My_length = myhost->h_length;

    bcopy(myhost->h_addr, __My_addr, myhost->h_length);

    return (ZERR_NONE);
} 
	
Code_t Z_PacketWaiting()
{
    int bytes;

    if (ioctl(ZGetFD(), FIONREAD, (char *)&bytes) < 0)
	return (0);

    return (bytes > 0);
} 

Code_t Z_ReadEnqueue()
{
    int retval;
	
    while (Z_PacketWaiting())
	if ((retval = Z_ReadWait()) != ZERR_NONE)
	    return (retval);

    return (ZERR_NONE);
}

Code_t Z_ReadWait()
{
    struct _Z_InputQ *newqueue;
    ZNotice_t notice;
    struct sockaddr_in olddest;
    int from_len, retval;
	
    if (ZGetFD() < 0)
	return (ZERR_NOPORT);
	
    if (__Q_CompleteLength > Z_MAXQLEN)
	return (ZERR_QLEN);
	
    newqueue = (struct _Z_InputQ *)malloc(sizeof(struct _Z_InputQ));
    if (!newqueue)
	return (ENOMEM);

    from_len = sizeof(struct sockaddr_in);
	
    newqueue->packet_len = recvfrom(ZGetFD(), newqueue->packet, 
				    sizeof newqueue->packet, 0, 
				    &newqueue->from, 
				    &from_len);

    if (newqueue->packet_len < 0) {
	free((char *)newqueue);
	return (errno);
    }

    if (!newqueue->packet_len) {
	free((char *)newqueue);
	return (ZERR_EOF);
    }

    if (!__Zephyr_server &&
	ZParseNotice(newqueue->packet, newqueue->packet_len, 
		     &notice) == ZERR_NONE) {
	if (notice.z_kind != HMACK && notice.z_kind != SERVACK &&
	    notice.z_kind != SERVNAK) {
	    notice.z_kind = CLIENTACK;
	    notice.z_message_len = 0;
	    olddest = __HM_addr;
	    __HM_addr = newqueue->from;
	    if ((retval = ZSendRawNotice(&notice)) != ZERR_NONE)
		return (retval);
	    __HM_addr = olddest;
	} 
    }
    
    newqueue->next = NULL;
    if (__Q_CompleteLength) {
	newqueue->prev = __Q_Tail;
	__Q_Tail->next = newqueue;
	__Q_Tail = newqueue;
    }
    else {
	newqueue->prev = NULL;
	__Q_Head = __Q_Tail = newqueue;
    }
	
    __Q_CompleteLength++;
	
    return (ZERR_NONE);
}

Code_t Z_FormatHeader(notice, buffer, buffer_len, len, cert_routine)
    ZNotice_t *notice;
    char *buffer;
    int buffer_len;
    int *len;
    int (*cert_routine)();
{
    Code_t retval;
	
    if (!notice->z_sender)
	notice->z_sender = ZGetSender();

    notice->z_multinotice = "";
    
    (void) gettimeofday(&notice->z_uid.tv, (struct timezone *)0);
    notice->z_uid.tv.tv_sec = htonl(notice->z_uid.tv.tv_sec);
    notice->z_uid.tv.tv_usec = htonl(notice->z_uid.tv.tv_usec);
	
    if ((retval = Z_GetMyAddr()) != ZERR_NONE)
	return (retval);

    bcopy(__My_addr, (char *)&notice->z_uid.zuid_addr, __My_length);

    if (!cert_routine) {
	notice->z_auth = 0;
	notice->z_authent_len = 0;
	notice->z_ascii_authent = "";
	return (Z_FormatRawHeader(notice, buffer, buffer_len, len));
    }
	
    return ((cert_routine)(notice, buffer, buffer_len, len));
} 
	
Code_t Z_FormatRawHeader(notice, buffer, buffer_len, len)
    ZNotice_t *notice;
    char *buffer;
    int buffer_len;
    int *len;
{
    unsigned int temp;
    char newrecip[BUFSIZ], version[BUFSIZ];
    char *ptr, *end;
    int i;

    if (!notice->z_class || !notice->z_class_inst || !notice->z_opcode ||
	!notice->z_recipient || !notice->z_default_format)
	return (ZERR_ILLVAL);

    ptr = buffer;
    end = buffer+buffer_len;

    sprintf(version, "%s%d.%d", ZVERSIONHDR, ZVERSIONMAJOR, ZVERSIONMINOR);
    if (buffer_len < strlen(version)+1)
	return (ZERR_HEADERLEN);

    strcpy(ptr, version);
    ptr += strlen(ptr)+1;

    temp = htonl(ZNUMFIELDS+notice->z_num_other_fields);
    if (ZMakeAscii(ptr, end-ptr, (unsigned char *)&temp, 
		   sizeof(int)) == ZERR_FIELDLEN)
	return (ZERR_HEADERLEN);
    ptr += strlen(ptr)+1;
	
    temp = htonl((int)notice->z_kind);
    if (ZMakeAscii(ptr, end-ptr, (unsigned char *)&temp, 
		   sizeof(int)) == ZERR_FIELDLEN)
	return (ZERR_HEADERLEN);
    ptr += strlen(ptr)+1;
	
    if (ZMakeAscii(ptr, end-ptr, (unsigned char *)&notice->z_uid, 
		   sizeof(ZUnique_Id_t)) == ZERR_FIELDLEN)
	return (ZERR_HEADERLEN);
    ptr += strlen(ptr)+1;
	
    if (ZMakeAscii(ptr, end-ptr, (unsigned char *)&notice->z_port, 
		   sizeof(u_short)) == ZERR_FIELDLEN)
	return (ZERR_HEADERLEN);
    ptr += strlen(ptr)+1;

    if (ZMakeAscii(ptr, end-ptr, (unsigned char *)&notice->z_auth, 
		   sizeof(int)) == ZERR_FIELDLEN)
	return (ZERR_HEADERLEN);
    ptr += strlen(ptr)+1;

    temp = htonl(notice->z_authent_len);
    if (ZMakeAscii(ptr, end-ptr, (unsigned char *)&temp, 
		   sizeof(int)) == ZERR_FIELDLEN)
	return (ZERR_HEADERLEN);
    ptr += strlen(ptr)+1;
	
    if (Z_AddField(&ptr, notice->z_ascii_authent, end))
	return (ZERR_HEADERLEN);
    if (Z_AddField(&ptr, notice->z_class, end))
	return (ZERR_HEADERLEN);
    if (Z_AddField(&ptr, notice->z_class_inst, end))
	return (ZERR_HEADERLEN);
    if (Z_AddField(&ptr, notice->z_opcode, end))
	return (ZERR_HEADERLEN);
    if (Z_AddField(&ptr, notice->z_sender, end))
	return (ZERR_HEADERLEN);
    if (index(notice->z_recipient, '@') || !*notice->z_recipient) {
	if (Z_AddField(&ptr, notice->z_recipient, end))
	    return (ZERR_HEADERLEN);
    }
    else {
	(void) sprintf(newrecip, "%s@%s", notice->z_recipient, 
		       __Zephyr_realm);
	if (Z_AddField(&ptr, newrecip, end))
	    return (ZERR_HEADERLEN);
    }		
    if (Z_AddField(&ptr, notice->z_default_format, end))
	return (ZERR_HEADERLEN);

    temp = htonl(notice->z_checksum);
    if (ZMakeAscii(ptr, end-ptr, (unsigned char *)&temp, 
		   sizeof(ZChecksum_t)) == ZERR_FIELDLEN)
	return (ZERR_HEADERLEN);
    ptr += strlen(ptr)+1;

    if (Z_AddField(&ptr, notice->z_multinotice, end))
	return (ZERR_HEADERLEN);

    for (i=0;i<notice->z_num_other_fields;i++)
	if (Z_AddField(&ptr, notice->z_other_fields[i], end))
	    return (ZERR_HEADERLEN);
    
#ifdef notdef
    temp = htonl(notice->z_checksum);
    if (ZMakeAscii(ptr, end-ptr, (unsigned char *)&temp, 
		   sizeof(ZChecksum_t)) == ZERR_FIELDLEN)
	return (ZERR_HEADERLEN);
    ptr += strlen(ptr)+1;
#endif
    
    *len = ptr-buffer;
	
    return (ZERR_NONE);
}

Z_AddField(ptr, field, end)
    char **ptr, *field, *end;
{
    register int len;

    len = strlen(field)+1;

    if (*ptr+len > end)
	return (1);
    (void) strcpy(*ptr, field);
    *ptr += len;

    return (0);
}

struct _Z_InputQ *Z_GetFirstComplete()
{
    return (__Q_Head);
}

struct _Z_InputQ *Z_GetNextComplete(qptr)
    struct _Z_InputQ *qptr;
{
    return (qptr->next);
}

Z_RemQueue(qptr)
    struct _Z_InputQ *qptr;
{
    __Q_CompleteLength--;

    if (!__Q_CompleteLength) {
	free ((char *)qptr);
	return (ZERR_NONE);
    } 
	
    if (qptr == __Q_Head) {
	__Q_Head = __Q_Head->next;
	__Q_Head->prev = NULL;
	free ((char *)qptr);
	return (ZERR_NONE);
    } 
    if (qptr == __Q_Tail) {
	__Q_Tail = __Q_Tail->prev;
	__Q_Tail->next = NULL;
	free ((char *)qptr);
	return (ZERR_NONE);
    }
    qptr->prev->next = qptr->next;
    qptr->next->prev = qptr->prev;
    free ((char *)qptr);
    return (ZERR_NONE);
}

Code_t Z_SendFragmentedNotice(notice, len)
    ZNotice_t *notice;
    int len;
{
    ZNotice_t partnotice;
    ZPacket_t buffer;
    char multi[64];
    int offset, hdrsize, fragsize, ret_len, waitforack;
    Code_t retval;
    
    hdrsize = len-notice->z_message_len;
    fragsize = Z_MAXPKTLEN-hdrsize-10;
    
    offset = 0;

    waitforack = (notice->z_kind == UNACKED || notice->z_kind == ACKED) &&
	!__Zephyr_server;
    
    while (offset < notice->z_message_len || !notice->z_message_len) {
	sprintf(multi, "%d/%d", offset, notice->z_message_len);
	partnotice = *notice;
	partnotice.z_multinotice = multi;
	partnotice.z_message = notice->z_message+offset;
	partnotice.z_message_len = min(notice->z_message_len-offset,
				       fragsize);
	if ((retval = ZFormatSmallRawNotice(&partnotice, buffer,
					    &ret_len)) != ZERR_NONE) {
	    free(buffer);
	    return (retval);
	}
	if ((retval = ZSendPacket(buffer, ret_len, waitforack)) != ZERR_NONE) {
	    free(buffer);
	    return (retval);
	}
	offset += fragsize;
	if (!notice->z_message_len)
	    break;
    }

    return (ZERR_NONE);
}
