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
int __Q_Size = 0;
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


/* Get the address of the local host and cache it */

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


/* Return 1 if there is a packet waiting, 0 otherwise */

int Z_PacketWaiting()
{
    int bytes;

    if (ioctl(ZGetFD(), FIONREAD, (char *)&bytes) < 0)
	return (0);

    return (bytes > 0);
} 


/* Wait for a complete notice to become available */

Code_t Z_WaitForComplete()
{
    Code_t retval;

    if (__Q_CompleteLength)
	return (Z_ReadEnqueue());

    while (!__Q_CompleteLength)
	if ((retval = Z_ReadWait()) != ZERR_NONE)
	    return (retval);

    return (ZERR_NONE);
}


/* Read any available packets and enqueue them */

Code_t Z_ReadEnqueue()
{
    Code_t retval;

    if (ZGetFD() < 0)
	return (ZERR_NOPORT);
    
    while (Z_PacketWaiting())
	if ((retval = Z_ReadWait()) != ZERR_NONE)
	    return (retval);

    return (ZERR_NONE);
}


/*
 * Search the queue for a notice with the proper multiuid - remove any
 * notices that haven't been touched in a while
 */

struct _Z_InputQ *Z_SearchQueue(uid, kind)
    ZUnique_Id_t *uid;
    ZNotice_Kind_t kind;
{
    struct _Z_InputQ *qptr, *next;
    struct timeval tv;

    (void) gettimeofday(&tv, (struct timezone *)0);

    qptr = __Q_Head;

    while (qptr) {
	if (ZCompareUID(uid, &qptr->uid) && qptr->kind == kind)
	    return (qptr);
	next = qptr->next;
	if (qptr->timep+Z_NOTICETIMELIMIT > tv.tv_sec)
	    (void) Z_RemQueue(qptr);
	qptr = next;
    }
    return (NULL);
}

/*
 * Now we delve into really convoluted queue handling and
 * fragmentation reassembly algorithms and other stuff you probably
 * don't want to look at...
 */

Code_t Z_ReadWait()
{
    struct _Z_InputQ *qptr;
    ZNotice_t notice;
    ZPacket_t packet;
    struct sockaddr_in olddest, from;
    int from_len, packet_len, part, partof;
    char *slash;
    Code_t retval;
	
    if (ZGetFD() < 0)
	return (ZERR_NOPORT);
	
    from_len = sizeof(struct sockaddr_in);
	
    packet_len = recvfrom(ZGetFD(), packet, sizeof(packet), 0, 
			  &from, &from_len);

    if (packet_len < 0)
	return (errno);

    if (!packet_len)
	return (ZERR_EOF);

    /* Parse the notice */
    if ((retval = ZParseNotice(packet, packet_len, &notice)) != ZERR_NONE)
	return (retval);

    /*
     * If we're not a server and the notice is of an appropriate kind,
     * send back a CLIENTACK to whoever sent it to say we got it.
     */
    if (!__Zephyr_server) {
	if (notice.z_kind != HMACK && notice.z_kind != SERVACK &&
	    notice.z_kind != SERVNAK) {
	    notice.z_kind = CLIENTACK;
	    notice.z_message_len = 0;
	    olddest = __HM_addr;
	    __HM_addr = from;
	    if ((retval = ZSendRawNotice(&notice)) != ZERR_NONE)
		return (retval);
	    __HM_addr = olddest;
	} 
    }

    /*
     * Parse apart the z_multinotice field - if the field is blank for
     * some reason, assume this packet stands by itself.
     */
    slash = index(notice.z_multinotice, '/');
    if (slash) {
	part = atoi(notice.z_multinotice);
	partof = atoi(slash+1);
	if (part > partof || partof == 0) {
	    part = 0;
	    partof = notice.z_message_len;
	}
    }
    else {
	part = 0;
	partof = notice.z_message_len;
    }

    /* Too big a packet...just ignore it! */
    if (partof > Z_MAXNOTICESIZE)
	return (ZERR_NONE);

    /*
     * If we aren't a server and we can find a notice in the queue
     * with the same multiuid field, insert the current fragment as
     * appropriate.
     */
    if (!__Zephyr_server && (qptr = Z_SearchQueue(&notice.z_multiuid,
						  notice.z_kind))) {
	/*
	 * If this is the first fragment, and we haven't already gotten a
	 * first fragment, grab the header from it.
	 */
	if (part == 0 && !qptr->header) {
	    qptr->header_len = packet_len-notice.z_message_len;
	    if (!(qptr->header = malloc(qptr->header_len)))
		return (ENOMEM);
	    bcopy(packet, qptr->header, qptr->header_len);
	}
	return (Z_AddNoticeToEntry(qptr, &notice, part, partof));
    }

    /*
     * We'll have to creata a new entry...make sure the queue isn't
     * going to get too big.
     */
    if (__Q_Size+partof > Z_MAXQUEUESIZE)
	return (ZERR_NONE);

    /*
     * This is a notice we haven't heard of, so create a new queue
     * entry for it and zero it out.
     */
    qptr = (struct _Z_InputQ *)malloc(sizeof(struct _Z_InputQ));
    if (!qptr)
	return (ENOMEM);
    bzero(qptr, sizeof(struct _Z_InputQ));

    /* Insert the entry at the end of the queue */
    qptr->next = NULL;
    qptr->prev = __Q_Tail;
    if (__Q_Tail)
	__Q_Tail->next = qptr;
    __Q_Tail = qptr;

    if (!__Q_Head)
	__Q_Head = qptr;

    
    /* Copy the from field... */
    qptr->from = from;
    /* And the multiuid... */
    qptr->uid = notice.z_multiuid;
    /* And the kind... */
    qptr->kind = notice.z_kind;
    
    /*
     * We know how long the message is going to be (this is better
     * than IP fragmentation...), so go ahead and allocate it all.
     */
    if (!(qptr->msg = malloc(partof)))
	return (ENOMEM);
    qptr->msg_len = partof;
    __Q_Size += partof;

    /*
     * If this is the first part of the notice, we take the header
     * from it.  We only take it if this is the first fragment so that
     * the Unique ID's will be predictable.
     */
    if (part == 0) {
	qptr->header_len = packet_len-notice.z_message_len;
	qptr->header = malloc(packet_len-notice.z_message_len);
	bcopy(packet, qptr->header, qptr->header_len);
    }

    /*
     * If this is not a fragmented notice, then don't bother with a
     * hole list.
     */
    if (part == 0 && notice.z_message_len == partof) {
	__Q_CompleteLength++;
	qptr->holelist = NULL;
	qptr->complete = 1;
	bcopy(notice.z_message, qptr->msg, notice.z_message_len);
	qptr->packet_len = qptr->header_len+qptr->msg_len;
	if (!(qptr->packet = malloc(qptr->packet_len)))
	    return (ENOMEM);
	bcopy(qptr->header, qptr->packet, qptr->header_len);
	bcopy(qptr->msg, qptr->packet+qptr->header_len, qptr->msg_len);
	return (ZERR_NONE);
    }
    /*
     * Well, it's a fragmented notice...allocate a hole list and
     * initialize it to the full packet size.  Then insert the
     * current fragment.
     */
    if (!(qptr->holelist = (struct _Z_Hole *)
	  malloc(sizeof(struct _Z_Hole))))
	return (ENOMEM);
    qptr->holelist->next = NULL;
    qptr->holelist->first = 0;
    qptr->holelist->last = partof-1;
    return (Z_AddNoticeToEntry(qptr, &notice, part, partof));
}


/* Fragment management routines - compliments, more or less, of RFC815 */

Code_t Z_AddNoticeToEntry(qptr, notice, part, partof)
    struct _Z_InputQ *qptr;
    ZNotice_t *notice;
    int part;
    int partof;
{
    int last, oldfirst, oldlast;
    struct _Z_Hole *hole, *lasthole;
    struct timeval tv;

    (void) gettimeofday(&tv, (struct timezone *)0);
    qptr->timep = tv.tv_sec;
    
    last = part+notice->z_message_len-1;

    hole = qptr->holelist;
    lasthole = NULL;

    /* Search for a hole that overlaps with the current fragment */
    while (hole) {
	if (part <= hole->last && last >= hole->first)
	    break;
	lasthole = hole;
	hole = hole->next;
    }

    /* If we found one, delete it and reconstruct a new hole */
    if (hole) {
	oldfirst = hole->first;
	oldlast = hole->last;
	if (lasthole)
	    lasthole->next = hole->next;
	else
	    qptr->holelist = hole->next;
	free(hole);
	/*
	 * Now create a new hole that is the original hole without the
	 * current fragment.
	 */
	if (part > oldfirst) {
	    /* Search for the end of the hole list */
	    hole = qptr->holelist;
	    lasthole = NULL;
	    while (hole) {
		lasthole = hole;
		hole = hole->next;
	    }
	    if (lasthole) {
		if (!(lasthole->next = (struct _Z_Hole *)
		      malloc(sizeof(struct _Z_InputQ))))
		    return (ENOMEM);
		hole = lasthole->next;
	    }
	    else {
		if (!(qptr->holelist = (struct _Z_Hole *)
		      malloc(sizeof(struct _Z_InputQ))))
		    return (ENOMEM);
		hole = qptr->holelist;
	    }
	    hole->next = NULL;
	    hole->first = oldfirst;
	    hole->last = part-1;
	}
	if (last < oldlast) {
	    /* Search for the end of the hole list */
	    hole = qptr->holelist;
	    lasthole = NULL;
	    while (hole) {
		lasthole = hole;
		hole = hole->next;
	    }
	    if (lasthole) {
		if (!(lasthole->next = (struct _Z_Hole *)
		      malloc(sizeof(struct _Z_InputQ))))
		    return (ENOMEM);
		hole = lasthole->next;
	    }
	    else {
		if (!(qptr->holelist = (struct _Z_Hole *)
		      malloc(sizeof(struct _Z_InputQ))))
		    return (ENOMEM);
		hole = qptr->holelist;
	    }
	    hole->next = NULL;
	    hole->first = last+1;
	    hole->last = oldlast;
	}
    }

    if (!qptr->holelist) {
	if (!qptr->complete)
	    __Q_CompleteLength++;
	qptr->complete = 1;
	qptr->packet_len = qptr->header_len+qptr->msg_len;
	if (!(qptr->packet = malloc(qptr->packet_len)))
	    return (ENOMEM);
	bcopy(qptr->header, qptr->packet, qptr->header_len);
	bcopy(qptr->msg, qptr->packet+qptr->header_len, qptr->msg_len);
    }
    
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
    bcopy(&notice->z_uid, &notice->z_multiuid, sizeof(ZUnique_Id_t));
    
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

    if (ZMakeAscii(ptr, end-ptr, (unsigned char *)&notice->z_multiuid, 
		   sizeof(ZUnique_Id_t)) == ZERR_FIELDLEN)
	return (ZERR_HEADERLEN);
    ptr += strlen(ptr)+1;
	
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

#ifdef notdef
struct _Z_InputQ *Z_GetFirstComplete()
{
    struct _Z_InputQ *qptr;

    qptr = __Q_Head;

    while (qptr) {
	if (qptr->complete)
	    return (qptr);
	qptr = qptr->next;
    }

    return (NULL);
}

struct _Z_InputQ *Z_GetNextComplete(qptr)
    struct _Z_InputQ *qptr;
{
    qptr = qptr->next;
    while (qptr) {
	if (qptr->complete)
	    return (qptr);
	qptr = qptr->next;
    }

    return (NULL);
}
#endif

struct _Z_InputQ *Z_GetFirstComplete()
{
    struct _Z_InputQ *qptr;

    qptr = __Q_Tail;

    while (qptr) {
	if (qptr->complete)
	    return (qptr);
	qptr = qptr->prev;
    }

    return (NULL);
}

struct _Z_InputQ *Z_GetNextComplete(qptr)
    struct _Z_InputQ *qptr;
{
    qptr = qptr->prev;
    while (qptr) {
	if (qptr->complete)
	    return (qptr);
	qptr = qptr->prev;
    }

    return (NULL);
}

Z_RemQueue(qptr)
    struct _Z_InputQ *qptr;
{
    struct _Z_Hole *hole, *nexthole;
    
    if (qptr->complete)
	__Q_CompleteLength--;

    __Q_Size -= qptr->msg_len;
    
    if (qptr->header)
	free(qptr->header);
    if (qptr->msg)
	free(qptr->msg);
    if (qptr->packet)
	free(qptr->packet);
    
    hole = qptr->holelist;
    while (hole) {
	nexthole = hole->next;
	free(hole);
	hole = nexthole;
    }
    
    if (qptr == __Q_Head && __Q_Head == __Q_Tail) {
	free ((char *)qptr);
	__Q_Head = NULL;
	__Q_Tail = NULL;
	return (ZERR_NONE);
    }
    
    if (qptr == __Q_Head) {
	__Q_Head = qptr->next;
	__Q_Head->prev = NULL;
	free ((char *)qptr);
	return (ZERR_NONE);
    } 
    if (qptr == __Q_Tail) {
	__Q_Tail = qptr->prev;
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
    fragsize = Z_MAXPKTLEN-hdrsize-Z_FRAGFUDGE;
    
    offset = 0;

    waitforack = (notice->z_kind == UNACKED || notice->z_kind == ACKED) &&
	!__Zephyr_server;
    
    partnotice = *notice;

    while (offset < notice->z_message_len || !notice->z_message_len) {
	sprintf(multi, "%d/%d", offset, notice->z_message_len);
	partnotice.z_multinotice = multi;
	if (offset > 0) {
	    (void) gettimeofday(&partnotice.z_uid.tv,
				(struct timezone *)0);
	    partnotice.z_uid.tv.tv_sec =
		htonl(partnotice.z_uid.tv.tv_sec);
	    partnotice.z_uid.tv.tv_usec =
		htonl(partnotice.z_uid.tv.tv_usec);
	    if ((retval = Z_GetMyAddr()) != ZERR_NONE)
		return (retval);
	    bcopy(__My_addr, (char *)&partnotice.z_uid.zuid_addr,
		  __My_length);
	}
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
