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
int __Q_Length = 0;
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

Code_t Z_GetMyAddr()
{
	struct hostent *myhost;
	char hostname[BUFSIZ];
	struct hostent *gethostbyname();
	
	if (__My_length > 0)
		return (ZERR_NONE);

	if (gethostname(hostname,BUFSIZ) < 0)
		return (errno);

	if (!(myhost = gethostbyname(hostname)))
		return (errno);

	if (!(__My_addr = (char *)malloc((unsigned)myhost->h_length)))
		return (ENOMEM);

	__My_length = myhost->h_length;

	bcopy(myhost->h_addr,__My_addr,myhost->h_length);

	return (ZERR_NONE);
} 
	
Z_NoticeWaiting()
{
	int bytes;

	if (ioctl(ZGetFD(),FIONREAD,(char *)&bytes) < 0)
		return (0);

	return (bytes > 0);
} 

Z_ReadEnqueue()
{
	int retval;
	
	while (Z_NoticeWaiting())
		if ((retval = Z_ReadWait()) != ZERR_NONE)
			return (retval);

	return (ZERR_NONE);
}

Z_ReadWait()
{
	struct _Z_InputQ *newqueue;
	ZNotice_t notice;
	struct sockaddr_in olddest;
	int from_len,retval;
	
	if (ZGetFD() < 0)
		return (ZERR_NOPORT);
	
	if (__Q_Length > Z_MAXQLEN)
		return (ZERR_QLEN);
	
	newqueue = (struct _Z_InputQ *)malloc(sizeof(struct _Z_InputQ));
	if (!newqueue)
		return (ENOMEM);

	from_len = sizeof(struct sockaddr_in);
	
	newqueue->packet_len = recvfrom(ZGetFD(),newqueue->packet,
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
	    Z_InternalParseNotice(newqueue->packet, newqueue->packet_len,
				  &notice,(int *)0,(struct sockaddr_in *)0,
				  (int (*)())0) == ZERR_NONE) {
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
	if (__Q_Length) {
		newqueue->prev = __Q_Tail;
		__Q_Tail->next = newqueue;
		__Q_Tail = newqueue;
	}
	else {
		newqueue->prev = NULL;
		__Q_Head = __Q_Tail = newqueue;
	}
	
	__Q_Length++;
	
	return (ZERR_NONE);
}

Z_FormatHeader(notice,buffer,buffer_len,len,cert_routine)
	ZNotice_t	*notice;
	char		*buffer;
	int		buffer_len;
	int		*len;
	int		(*cert_routine)();
{
	int retval;
	
	if (!notice->z_class || !notice->z_class_inst || !notice->z_opcode ||
	    !notice->z_recipient)
		return (ZERR_ILLVAL);

	if (!notice->z_sender)
		notice->z_sender = ZGetSender();

	(void) gettimeofday(&notice->z_uid.tv,(struct timezone *)0);
	notice->z_uid.tv.tv_sec = htonl(notice->z_uid.tv.tv_sec);
	notice->z_uid.tv.tv_usec = htonl(notice->z_uid.tv.tv_usec);
	
	if ((retval = Z_GetMyAddr()) != ZERR_NONE)
		return (retval);

	bcopy(__My_addr,(char *)&notice->z_uid.zuid_addr,__My_length);

	if (!cert_routine) {
		notice->z_auth = 0;
		notice->z_authent_len = 0;
		notice->z_ascii_authent = (char *)"";
		return (Z_FormatRawHeader(notice,buffer,buffer_len,len));
	}
	
	return ((cert_routine)(notice,buffer,buffer_len,len));
} 
	
Z_FormatRawHeader(notice,buffer,buffer_len,len)
	ZNotice_t	*notice;
	char		*buffer;
	int		buffer_len;
	int		*len;
{
	unsigned int temp;
	char newrecip[BUFSIZ];
	char *ptr,*end;

	if (!notice->z_class)
		notice->z_class = "";

	if (!notice->z_class_inst)
		notice->z_class_inst = "";

	if (!notice->z_opcode)
		notice->z_opcode = "";
	
	if (!notice->z_recipient)
		notice->z_recipient = "";

	ptr = buffer;
	end = buffer+buffer_len;

	temp = htonl(ZVERSION);
	if (ZMakeAscii(ptr,end-ptr,(unsigned char *)&temp,
		       sizeof(int)) == ZERR_FIELDLEN)
		return (ZERR_PKTLEN);
	ptr += strlen(ptr)+1;

	temp = htonl((int)notice->z_kind);
	if (ZMakeAscii(ptr,end-ptr,(unsigned char *)&temp,
		       sizeof(int)) == ZERR_FIELDLEN)
		return (ZERR_PKTLEN);
	ptr += strlen(ptr)+1;
	
	if (ZMakeAscii(ptr,end-ptr,(unsigned char *)&notice->z_uid,
		       sizeof(ZUnique_Id_t)) == ZERR_FIELDLEN)
		return (ZERR_PKTLEN);
	ptr += strlen(ptr)+1;
	
	if (ZMakeAscii(ptr,end-ptr,(unsigned char *)&notice->z_port,
		       sizeof(u_short)) == ZERR_FIELDLEN)
		return (ZERR_PKTLEN);
	ptr += strlen(ptr)+1;

	if (ZMakeAscii(ptr,end-ptr,(unsigned char *)&notice->z_auth,
		       sizeof(int)) == ZERR_FIELDLEN)
		return (ZERR_PKTLEN);
	ptr += strlen(ptr)+1;

	temp = htonl(notice->z_authent_len);
	if (ZMakeAscii(ptr,end-ptr,(unsigned char *)&temp,
		       sizeof(int)) == ZERR_FIELDLEN)
		return (ZERR_PKTLEN);
	ptr += strlen(ptr)+1;
	
	if (Z_AddField(&ptr,notice->z_ascii_authent,end))
		return (ZERR_PKTLEN);
	if (Z_AddField(&ptr,notice->z_class,end))
		return (ZERR_PKTLEN);
	if (Z_AddField(&ptr,notice->z_class_inst,end))
		return (ZERR_PKTLEN);
	if (Z_AddField(&ptr,notice->z_opcode,end))
		return (ZERR_PKTLEN);
	if (Z_AddField(&ptr,notice->z_sender,end))
		return (ZERR_PKTLEN);
	if (index(notice->z_recipient,'@') || !*notice->z_recipient) {
		if (Z_AddField(&ptr,notice->z_recipient,end))
			return (ZERR_PKTLEN);
	}
	else {
		(void) sprintf(newrecip,"%s@%s",notice->z_recipient,
			__Zephyr_realm);
		if (Z_AddField(&ptr,newrecip,end))
			return (ZERR_PKTLEN);
	}		

	temp = htonl(notice->z_checksum);
	if (ZMakeAscii(ptr,end-ptr,(unsigned char *)&temp,
		       sizeof(ZChecksum_t)) == ZERR_FIELDLEN)
		return (ZERR_PKTLEN);
	ptr += strlen(ptr)+1;

	*len = ptr-buffer;
	
	return (ZERR_NONE);
}

Z_AddField(ptr,field,end)
	char **ptr,*field,*end;
{
	register int len;

	len = strlen(field)+1;

	if (*ptr+len > end)
		return (1);
	(void) strcpy(*ptr,field);
	*ptr += len;

	return (0);
}

Z_RemQueue(qptr)
	struct _Z_InputQ *qptr;
{
	__Q_Length--;

	if (!__Q_Length) {
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

Code_t Z_InternalParseNotice(buffer,len,notice,auth,from,auth_routine)
	ZPacket_t	buffer;
	int		len;
	ZNotice_t	*notice;
	int		*auth;
	struct		sockaddr_in *from;
	int		(*auth_routine)();
{
	char *ptr,*end;
	unsigned int temp[3];
	
	ptr = buffer;
	end = buffer+len;
	
	if (ZReadAscii(ptr,end-ptr,(unsigned char *)temp,sizeof(int)) == ZERR_BADFIELD)
		return (ZERR_BADPKT);
	ptr += strlen(ptr)+1;
	
	if (ntohl(*temp) != ZVERSION)
		return (ZERR_VERS);

	if (ZReadAscii(ptr,end-ptr,(unsigned char *)temp,sizeof(int)) == ZERR_BADFIELD)
		return (ZERR_BADPKT);
	notice->z_kind = (ZNotice_Kind_t)ntohl((ZNotice_Kind_t)*temp);
	ptr += strlen(ptr)+1;
	
	if (ZReadAscii(ptr,end-ptr,(unsigned char *)temp,sizeof(ZUnique_Id_t)) ==
	    ZERR_BADFIELD)
		return (ZERR_BADPKT);
	bcopy((char *)temp,(char *)&notice->z_uid,sizeof(ZUnique_Id_t));
	ptr += strlen(ptr)+1;
	notice->z_time.tv_sec = ntohl(notice->z_uid.tv.tv_sec);
	notice->z_time.tv_usec = ntohl(notice->z_uid.tv.tv_usec);
	
	if (ZReadAscii(ptr,end-ptr,(unsigned char *)temp,sizeof(u_short)) ==
	    ZERR_BADFIELD)
		return (ZERR_BADPKT);
	notice->z_port = *((u_short *)temp);
	ptr += strlen(ptr)+1;
	
	if (ZReadAscii(ptr,end-ptr,(unsigned char *)temp,sizeof(int)) == ZERR_BADFIELD)
		return (ZERR_BADPKT);
	notice->z_auth = *temp;
	ptr += strlen(ptr)+1;

	if (ZReadAscii(ptr,end-ptr,(unsigned char *)temp,sizeof(int)) == ZERR_BADFIELD)
		return (ZERR_BADPKT);
	notice->z_authent_len = ntohl(*temp);
	ptr += strlen(ptr)+1;
	
	notice->z_ascii_authent = ptr;
	ptr += strlen(ptr)+1;
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

	if (ZReadAscii(ptr,end-ptr,(unsigned char *)temp,
		       sizeof(ZChecksum_t))
	    == ZERR_BADFIELD)
		return (ZERR_BADPKT);
	notice->z_checksum = ntohl(*temp);
	ptr += strlen(ptr)+1;

	notice->z_message = (caddr_t) ptr;
	notice->z_message_len = len-(ptr-buffer);

	if (!auth)
		return (ZERR_NONE);
	if (!from || !auth_routine) {
		*auth = 0;
		return (ZERR_NONE);
	} 
		
	*auth = (auth_routine)(notice,buffer,from);
	return (ZERR_NONE);
}

/* XXX The following two routines are a TEMPORARY kludge */

Z_NoAuthIfNotice(buffer,buffer_len,notice,predicate,args)
	ZPacket_t	buffer;
	int		buffer_len;
	ZNotice_t	*notice;
	int		(*predicate)();
	char		*args;
{
	ZNotice_t tmpnotice;
	int qcount,retval;
	struct _Z_InputQ *qptr;

	if (__Q_Length)
		retval = Z_ReadEnqueue();
	else
		retval = Z_ReadWait();
	
	if (retval != ZERR_NONE)
		return (retval);
	
	qptr = __Q_Head;
	qcount = __Q_Length;

	for (;;qcount--) {
		if ((retval = Z_InternalParseNotice(qptr->packet,
						    qptr->packet_len,
						    &tmpnotice,(int *)0,
						    (struct sockaddr_in *)0,
						    (int (*)())0))
		    != ZERR_NONE)
			return (retval);
		if ((predicate)(&tmpnotice,args)) {
			if (qptr->packet_len > buffer_len)
				return (ZERR_PKTLEN);
			bcopy(qptr->packet,buffer,qptr->packet_len);
			if ((retval = Z_InternalParseNotice(buffer,
							    qptr->packet_len,
							    notice,(int *)0,
							    (struct sockaddr_in *)0,
							    (int (*)())0))
			    != ZERR_NONE)
				return (retval);
			return (Z_RemQueue(qptr));
		} 
		/* Grunch! */
		if (qcount == 1) {
			if ((retval = Z_ReadWait()) != ZERR_NONE)
				return (retval);
			qcount++;
			qptr = __Q_Tail;
		} 
		else
			qptr = qptr->next;
	}
}

Code_t Z_NoAuthCheckIfNotice(buffer,buffer_len,notice,predicate,args)
	ZPacket_t	buffer;
	int		buffer_len;
	ZNotice_t	*notice;
	int		(*predicate)();
	char		*args;
{
	ZNotice_t tmpnotice;
	int qcount,retval;
	struct _Z_InputQ *qptr;

	if ((retval = Z_ReadEnqueue()) != ZERR_NONE)
		return (retval);
	
	qptr = __Q_Head;
	qcount = __Q_Length;
	
	for (;qcount;qcount--) {
		if ((retval = Z_InternalParseNotice(qptr->packet,
						    qptr->packet_len,
						    &tmpnotice,(int *)0,
						    (struct sockaddr_in *)0,
						    (int (*)())0))
		    != ZERR_NONE)
			return (retval);
		if ((predicate)(&tmpnotice,args)) {
			if (qptr->packet_len > buffer_len)
				return (ZERR_PKTLEN);
			bcopy(qptr->packet,buffer,qptr->packet_len);
			if ((retval = Z_InternalParseNotice(buffer,
							    qptr->packet_len,
							    notice,(int *)0,
							    (struct sockaddr_in *)0,
							    (int (*)())0))
			    != ZERR_NONE)
				return (retval);
			return (Z_RemQueue(qptr));
		} 
		qptr = qptr->next;
	}

	return (ZERR_NONOTICE);
}
