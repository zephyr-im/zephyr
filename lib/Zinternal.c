/* This file is part of the Project Athena Zephyr Notification System.
 * It contains source for the internal Zephyr routines.
 *
 *	Created by:	Robert French
 *
 *	$Source$
 *	$Author$
 *
 *	Copyright (c) 1987,1988,1991 by the Massachusetts Institute of
 *	Technology.
 *	For copying and distribution information, see the file
 *	"mit-copyright.h". 
 */
/* $Header$ */

#ifndef lint
static char rcsid_Zinternal_c[] =
  "$Id$";
static char copyright[] =
  "Copyright (c) 1987,1988,1991 by the Massachusetts Institute of Technology.";
#endif

#include <zephyr/zephyr_internal.h>
#include <netdb.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <utmp.h>

#ifdef __STDC__
typedef void *pointer;
#else
typedef char *pointer;
#endif

extern char *inet_ntoa ();

int __Zephyr_fd = -1;
int __Zephyr_open;
int __Zephyr_port = -1;
int __My_length;
char *__My_addr;
int __Q_CompleteLength;
int __Q_Size;
struct _Z_InputQ *__Q_Head, *__Q_Tail;
struct sockaddr_in __HM_addr;
struct sockaddr_in __HM_addr_real;
int __HM_set;
#ifdef KERBEROS
C_Block __Zephyr_session;
char __Zephyr_realm[REALM_SZ];
#endif
int __Zephyr_server;
ZLocations_t *__locate_list;
int __locate_num;
int __locate_next;
ZSubscription_t *__subscriptions_list;
int __subscriptions_num;
int __subscriptions_next;
void (*__Z_debug_print) Zproto((const char *fmt, va_list args, void *closure));
pointer __Z_debug_print_closure;

#define min(a,b) ((a)<(b)?(a):(b))

/* Get the address of the local host and cache it */

Code_t Z_GetMyAddr()
{
    register struct hostent *myhost;
    char hostname[MAXHOSTNAMELEN];
	
    if (__My_length > 0)
	return (ZERR_NONE);

    if (gethostname(hostname, MAXHOSTNAMELEN) < 0)
	return (errno);

    if (!(myhost = gethostbyname(hostname)))
	return (errno);

    /* If h_length is 0, that is a serious problem and it doesn't
       make it worse for malloc(0) to return NULL, so don't worry
       about that case. */
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
    register struct _Z_InputQ *qptr;
    struct _Z_InputQ *next;
    struct timeval tv;

    (void) gettimeofday(&tv, (struct timezone *)0);

    qptr = __Q_Head;

    while (qptr) {
	if (ZCompareUID(uid, &qptr->uid) && qptr->kind == kind)
	    return (qptr);
	next = qptr->next;
	if (qptr->timep && (qptr->timep+Z_NOTICETIMELIMIT < tv.tv_sec))
	    Z_RemQueue(qptr);
	qptr = next;
    }
    return (NULL);
}

/*
 * Now we delve into really convoluted queue handling and
 * fragmentation reassembly algorithms and other stuff you probably
 * don't want to look at...
 *
 * This routine does NOT guarantee a complete packet will be ready when it
 * returns.
 */

Code_t Z_ReadWait()
{
    register struct _Z_InputQ *qptr;
    ZNotice_t notice;
    ZPacket_t packet;
    struct sockaddr_in olddest, from;
    int from_len, packet_len, part, partof;
    char *slash;
    Code_t retval;
    static struct _filter {
	ZUnique_Id_t	uid;
	ZNotice_Kind_t	kind;
    } old_uids[Z_FILTERDEPTH];
    static int filter_idx = -1;
    register int i;

    if (ZGetFD() < 0)
	return (ZERR_NOPORT);
	
    from_len = sizeof(struct sockaddr_in);

    packet_len = recvfrom(ZGetFD(), packet, sizeof(packet), 0, 
			  (struct sockaddr *)&from, &from_len);

    if (packet_len < 0)
	return (errno);

    if (!packet_len)
	return (ZERR_EOF);

    /* XXX Check for null data (debugging) */
    for (i = packet_len - 1; i >= 0; i--)
      if (packet[i])
	goto not_all_null;
    Z_debug ("got null packet from %s", inet_ntoa (from.sin_addr.s_addr));
    return ZERR_NONE;
  not_all_null:

    /* Parse the notice */
    if ((retval = ZParseNotice(packet, packet_len, &notice)) != ZERR_NONE)
	return (retval);

    /*
     * If we're not a server and the notice is of an appropriate kind,
     * send back a CLIENTACK to whoever sent it to say we got it.
     */
    if (!__Zephyr_server) {
	if (notice.z_kind != HMACK && notice.z_kind != SERVACK &&
	    notice.z_kind != SERVNAK && notice.z_kind != CLIENTACK) {
	    ZNotice_t tmpnotice;
	    ZPacket_t pkt;
	    int len;

	    tmpnotice = notice;
	    tmpnotice.z_kind = CLIENTACK;
	    tmpnotice.z_message_len = 0;
	    olddest = __HM_addr;
	    __HM_addr = from;
	    if ((retval = ZFormatSmallRawNotice(&tmpnotice, pkt, &len))
		!= ZERR_NONE)
		return(retval);
	    if ((retval = ZSendPacket(pkt, len, 0)) != ZERR_NONE)
		return (retval);
	    __HM_addr = olddest;
	}
	if (filter_idx == -1) {
	    bzero((char *) old_uids,
		  Z_FILTERDEPTH*(sizeof(struct _filter)));
	    old_uids[0].uid = notice.z_uid;
	    old_uids[0].kind = notice.z_kind;
	    filter_idx = 1;
	} else {
	    for (i = 0; i < Z_FILTERDEPTH; i++)
		if (old_uids[i].uid.tv.tv_sec != 0)
		    if (ZCompareUID(&notice.z_uid, &old_uids[i].uid) &&
			(notice.z_kind == old_uids[i].kind))
			    return(ZERR_NONE);
	    old_uids[filter_idx].uid = notice.z_uid;
	    old_uids[filter_idx++].kind = notice.z_kind;
	    filter_idx %= Z_FILTERDEPTH;
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
    switch (notice.z_kind) {
    case SERVACK:
    case SERVNAK:
	/* The SERVACK and SERVNAK replies shouldn't be reassembled
	   (they have no parts).  Instead, we should hold on to the reply
	   ONLY if it's the first part of a fragmented message, i.e.
	   multi_uid == uid.  This allows programs to wait for the uid
	   of the first packet, and get a response when that notice
	   arrives.  Acknowledgements of the other fragments are discarded
	   (XXX we assume here that they all carry the same information
	   regarding failure/success)
	 */
	if (!__Zephyr_server &&
	    !ZCompareUID(&notice.z_multiuid, &notice.z_uid))
	    /* they're not the same... throw away this packet. */
	    return(ZERR_NONE);
	/* fall thru & process it */
    default:
	/* for HMACK types, we assume no packet loss (local loopback
	   connections).  The other types can be fragmented and MUST
	   run through this code. */
	if (!__Zephyr_server && (qptr = Z_SearchQueue(&notice.z_multiuid,
						      notice.z_kind))) {
	    /*
	     * If this is the first fragment, and we haven't already
	     * gotten a first fragment, grab the header from it.
	     */
	    if (part == 0 && !qptr->header) {
		qptr->header_len = packet_len-notice.z_message_len;
		qptr->header = malloc((unsigned) qptr->header_len);
		if (!qptr->header)
		    return (ENOMEM);
		bcopy(packet, qptr->header, qptr->header_len);
	    }
	    return (Z_AddNoticeToEntry(qptr, &notice, part));
	}
    }

    /*
     * We'll have to create a new entry...make sure the queue isn't
     * going to get too big.
     */
    if (__Q_Size+(__Zephyr_server ? notice.z_message_len : partof) > Z_MAXQUEUESIZE)
	return (ZERR_NONE);

    /*
     * This is a notice we haven't heard of, so create a new queue
     * entry for it and zero it out.
     */
    qptr = (struct _Z_InputQ *)malloc(sizeof(struct _Z_InputQ));
    if (!qptr)
	return (ENOMEM);
    bzero((char *)qptr, sizeof(struct _Z_InputQ));

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
     * If this is the first part of the notice, we take the header
     * from it.  We only take it if this is the first fragment so that
     * the Unique ID's will be predictable.
     *
     * If a Zephyr Server, we always take the header.
     */
    if (__Zephyr_server || part == 0) {
	qptr->header_len = packet_len-notice.z_message_len;
	qptr->header = malloc((unsigned) qptr->header_len);
	if (!qptr->header)
	    return ENOMEM;
	bcopy(packet, qptr->header, qptr->header_len);
    }

    /*
     * If this is not a fragmented notice, then don't bother with a
     * hole list.
     * If we are a Zephyr server, all notices are treated as complete.
     */
    if (__Zephyr_server || (part == 0 && notice.z_message_len == partof)) {
	__Q_CompleteLength++;
	qptr->holelist = (struct _Z_Hole *) 0;
	qptr->complete = 1;
	/* allocate a msg buf for this piece */
	if (notice.z_message_len == 0)
	    qptr->msg = 0;
	else if (!(qptr->msg = malloc((unsigned) notice.z_message_len)))
	    return(ENOMEM);
	else
	    bcopy(notice.z_message, qptr->msg, notice.z_message_len);
	qptr->msg_len = notice.z_message_len;
	__Q_Size += notice.z_message_len;
	qptr->packet_len = qptr->header_len+qptr->msg_len;
	if (!(qptr->packet = malloc((unsigned) qptr->packet_len)))
	    return (ENOMEM);
	bcopy(qptr->header, qptr->packet, qptr->header_len);
	if(qptr->msg)
	    bcopy(qptr->msg, qptr->packet+qptr->header_len, qptr->msg_len);
	return (ZERR_NONE);
    }

    /*
     * We know how long the message is going to be (this is better
     * than IP fragmentation...), so go ahead and allocate it all.
     */
    if (!(qptr->msg = malloc((unsigned) partof)) && partof)
	return (ENOMEM);
    qptr->msg_len = partof;
    __Q_Size += partof;

    /*
     * Well, it's a fragmented notice...allocate a hole list and
     * initialize it to the full packet size.  Then insert the
     * current fragment.
     */
    if (!(qptr->holelist = (struct _Z_Hole *)
	  malloc(sizeof(struct _Z_Hole))))
	return (ENOMEM);
    qptr->holelist->next = (struct _Z_Hole *) 0;
    qptr->holelist->first = 0;
    qptr->holelist->last = partof-1;
    return (Z_AddNoticeToEntry(qptr, &notice, part));
}


/* Fragment management routines - compliments, more or less, of RFC815 */

Code_t Z_AddNoticeToEntry(qptr, notice, part)
    struct _Z_InputQ *qptr;
    ZNotice_t *notice;
    int part;
{
    int last, oldfirst, oldlast;
    struct _Z_Hole *hole, *lasthole;
    struct timeval tv;

    (void) gettimeofday(&tv, (struct timezone *)0);
    qptr->timep = tv.tv_sec;
    
    last = part+notice->z_message_len-1;

    hole = qptr->holelist;
    lasthole = (struct _Z_Hole *) 0;

    /* copy in the message body */
    (void) bcopy(notice->z_message, qptr->msg+part, notice->z_message_len);

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
	free((char *)hole);
	/*
	 * Now create a new hole that is the original hole without the
	 * current fragment.
	 */
	if (part > oldfirst) {
	    /* Search for the end of the hole list */
	    hole = qptr->holelist;
	    lasthole = (struct _Z_Hole *) 0;
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
	    lasthole = (struct _Z_Hole *) 0;
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
	    hole->next = (struct _Z_Hole *) 0;
	    hole->first = last+1;
	    hole->last = oldlast;
	}
    }

    if (!qptr->holelist) {
	if (!qptr->complete)
	    __Q_CompleteLength++;
	qptr->complete = 1;
	qptr->timep = 0;		/* don't time out anymore */
	qptr->packet_len = qptr->header_len+qptr->msg_len;
	if (!(qptr->packet = malloc((unsigned) qptr->packet_len)))
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
    static char version[BUFSIZ]; /* default init should be all \0 */
	
    if (!notice->z_sender)
	notice->z_sender = ZGetSender();

    notice->z_multinotice = "";
    
    (void) gettimeofday(&notice->z_uid.tv, (struct timezone *)0);
    notice->z_uid.tv.tv_sec = htonl((u_long) notice->z_uid.tv.tv_sec);
    notice->z_uid.tv.tv_usec = htonl((u_long) notice->z_uid.tv.tv_usec);
    
    if ((retval = Z_GetMyAddr()) != ZERR_NONE)
	return (retval);

    bcopy(__My_addr, (char *)&notice->z_uid.zuid_addr, __My_length);

    notice->z_multiuid = notice->z_uid;

    if (!version[0])
	    (void) sprintf(version, "%s%d.%d", ZVERSIONHDR, ZVERSIONMAJOR,
			   ZVERSIONMINOR);
    notice->z_version = version;

    if (!cert_routine) {
	notice->z_auth = 0;
	notice->z_authent_len = 0;
	notice->z_ascii_authent = "";
	notice->z_checksum = 0;
	return (Z_FormatRawHeader(notice, buffer, buffer_len,
				  len, (char **) 0));
    }
    
    return ((*cert_routine)(notice, buffer, buffer_len, len));
} 
	
Code_t Z_FormatRawHeader(notice, buffer, buffer_len, len, sumend_ptr)
    ZNotice_t *notice;
    char *buffer;
    int buffer_len;
    int *len;
    char **sumend_ptr;
{
    union {
	int i;
	ZChecksum_t sum;
    } temp;
    char newrecip[BUFSIZ];
    char *ptr, *end;
    int i;

    if (!notice->z_class)
	    notice->z_class = "";

    if (!notice->z_class_inst)
	    notice->z_class_inst = "";

    if (!notice->z_opcode)
	    notice->z_opcode = "";

    if (!notice->z_recipient)
	    notice->z_recipient = "";

    if (!notice->z_default_format)
	    notice->z_default_format = "";

    ptr = buffer;
    end = buffer+buffer_len;

    if (buffer_len < strlen(notice->z_version)+1)
	return (ZERR_HEADERLEN);

    (void) strcpy(ptr, notice->z_version);
    ptr += strlen(ptr)+1;

    temp.i = htonl((u_long) (ZNUMFIELDS+notice->z_num_other_fields));
    if (ZMakeAscii(ptr, end-ptr, (unsigned char *)&temp.i,
		   sizeof(temp.i)) == ZERR_FIELDLEN)
	return (ZERR_HEADERLEN);
    ptr += strlen(ptr)+1;
	
    temp.i = htonl((u_long) notice->z_kind);
    if (ZMakeAscii(ptr, end-ptr, (unsigned char *)&temp.i,
		   sizeof(temp.i)) == ZERR_FIELDLEN)
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

    temp.i = htonl((u_long) notice->z_authent_len);
    if (ZMakeAscii(ptr, end-ptr, (unsigned char *)&temp.i,
		   sizeof(temp.i)) == ZERR_FIELDLEN)
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

    /* copy back the end pointer location for crypto checksum */
    if (sumend_ptr)
	*sumend_ptr = ptr;

    temp.sum = htonl(notice->z_checksum);
    if (ZMakeAscii(ptr, end-ptr, (unsigned char *)&temp.sum,
		   sizeof(temp.sum)) == ZERR_FIELDLEN)
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

    len = field ? strlen (field) + 1 : 1;

    if (*ptr+len > end)
	return 1;
    if (field)
	(void) strcpy(*ptr, field);
    else
	**ptr = '\0';
    *ptr += len;

    return 0;
}

struct _Z_InputQ *Z_GetFirstComplete()
{
    struct _Z_InputQ *qptr;

    qptr = __Q_Head;

    while (qptr) {
	if (qptr->complete)
	    return (qptr);
	qptr = qptr->next;
    }

    return ((struct _Z_InputQ *)0);
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

    return ((struct _Z_InputQ *)0);
}

void Z_RemQueue(qptr)
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
	free((char *)hole);
	hole = nexthole;
    }
    
    if (qptr == __Q_Head && __Q_Head == __Q_Tail) {
	free ((char *)qptr);
	__Q_Head = (struct _Z_InputQ *)0;
	__Q_Tail = (struct _Z_InputQ *)0;
	return;
    }
    
    if (qptr == __Q_Head) {
	__Q_Head = qptr->next;
	__Q_Head->prev = (struct _Z_InputQ *)0;
	free ((char *)qptr);
	return;
    } 
    if (qptr == __Q_Tail) {
	__Q_Tail = qptr->prev;
	__Q_Tail->next = (struct _Z_InputQ *)0;
	free ((char *)qptr);
	return;
    }
    qptr->prev->next = qptr->next;
    qptr->next->prev = qptr->prev;
    free ((char *)qptr);
    return;
}

Code_t Z_SendFragmentedNotice(notice, len, send_func)
    ZNotice_t *notice;
    int len;
    Code_t (*send_func)();
{
    ZNotice_t partnotice;
    ZPacket_t buffer;
    char multi[64];
    int offset, hdrsize, fragsize, ret_len, waitforack;
    Code_t retval;
    
    hdrsize = len-notice->z_message_len;
    fragsize = Z_MAXPKTLEN-hdrsize-Z_FRAGFUDGE;
    
    offset = 0;

    waitforack = ((notice->z_kind == UNACKED || notice->z_kind == ACKED)
		  && !__Zephyr_server);
    
    partnotice = *notice;

    while (offset < notice->z_message_len || !notice->z_message_len) {
	(void) sprintf(multi, "%d/%d", offset, notice->z_message_len);
	partnotice.z_multinotice = multi;
	if (offset > 0) {
	    (void) gettimeofday(&partnotice.z_uid.tv,
				(struct timezone *)0);
	    partnotice.z_uid.tv.tv_sec =
		htonl((u_long) partnotice.z_uid.tv.tv_sec);
	    partnotice.z_uid.tv.tv_usec =
		htonl((u_long) partnotice.z_uid.tv.tv_usec);
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
	    return (retval);
	}
	if ((retval = (*send_func)(&partnotice, buffer, ret_len,
				   waitforack)) != ZERR_NONE) {
	    return (retval);
	}
	offset += fragsize;
	if (!notice->z_message_len)
	    break;
    }

    return (ZERR_NONE);
}

/*ARGSUSED*/
Code_t Z_XmitFragment(notice, buf, len, wait)
ZNotice_t *notice;
char *buf;
int len;
int wait;
{
	return(ZSendPacket(buf, len, wait));
}

/* For debugging printing */
Zconst char *Zconst ZNoticeKinds[] = { "UNSAFE", "UNACKED", "ACKED", "HMACK",
					 "HMCTL", "SERVACK", "SERVNAK",
					 "CLIENTACK", "STAT", };

#undef Z_debug
#ifdef Z_Varargs
void Z_debug (va_alist) va_dcl
{
    va_list pvar;
    char *format;
    if (!__Z_debug_print)
      return;
    va_start (pvar);
    format = va_arg (pvar, char *);
    (*__Z_debug_print) (format, pvar, __Z_debug_print_closure);
    va_end (pvar);
}
#else /* stdarg */
void Z_debug (const char *format, ...)
{
    va_list pvar;
    if (!__Z_debug_print)
      return;
    va_start (pvar, format);
    (*__Z_debug_print) (format, pvar, __Z_debug_print_closure);
    va_end (pvar);
}
#endif

void Z_debug_stderr (format, args, closure)
#ifdef __STDC__
     const
#endif
       char *format;
     va_list args;
#ifdef __STDC__
     void *closure;
#else
     char *closure;
#endif
{
#ifndef NO_VPRINTF
  vfprintf (stderr, format, args);
#else
  _doprnt (format, args, stderr);
#endif
  putc ('\n', stderr);
}

#undef ZGetFD
int ZGetFD () { return __Zephyr_fd; }

#undef ZQLength
int ZQLength () { return __Q_CompleteLength; }

#undef ZGetDestAddr
struct sockaddr_in ZGetDestAddr () { return __HM_addr; }

#undef ZGetRealm
Zconst char * ZGetRealm () { return __Zephyr_realm; }

#ifdef __STDC__
#define ARGS	(void (*proc)(const char *,va_list,void *), void *arg)
#else
#define ARGS	(proc, arg) void (*proc)(); char *arg;
#endif
#undef ZSetDebug
void ZSetDebug ARGS {
    __Z_debug_print = proc;
    __Z_debug_print_closure = arg;
}
