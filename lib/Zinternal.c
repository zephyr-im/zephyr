/* This file is part of the Project Athena Zephyr Notification System.
 * It contains source for the internal Zephyr routines.
 *
 *	Created by:	Robert French
 *
 *	$Id$
 *
 *	Copyright (c) 1987,1988,1991 by the Massachusetts Institute of
 *	Technology.
 *	For copying and distribution information, see the file
 *	"mit-copyright.h". 
 */

#include <internal.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <utmp.h>
#include <unistd.h>
#include <netdb.h>

#ifndef lint
static const char rcsid_Zinternal_c[] =
  "$Id$";
static const char copyright[] =
  "Copyright (c) 1987,1988,1991 by the Massachusetts Institute of Technology.";
#endif

extern char *inet_ntoa ();

int __Zephyr_fd = -1;
int __Zephyr_open;
int __Zephyr_port = -1;
int __Q_CompleteLength;
int __Q_Size;
struct _Z_InputQ *__Q_Head, *__Q_Tail;
struct sockaddr_in __HM_addr;
struct sockaddr_in __HM_addr_real;
int __Zephyr_server;
ZLocations_t *__locate_list;
int __locate_num;
int __locate_next;
ZSubscription_t *__subscriptions_list;
int __subscriptions_num;
int __subscriptions_next;
int Z_discarded_packets = 0;

Z_GalaxyList *__galaxy_list;
int __ngalaxies;
int __default_galaxy;

#ifdef Z_DEBUG
void (*__Z_debug_print) __P((const char *fmt, va_list args, void *closure));
void *__Z_debug_print_closure;
#endif

#define min(a,b) ((a)<(b)?(a):(b))

static int Z_AddField __P((char **ptr, char *field, char *end));
static int find_or_insert_uid __P((ZUnique_Id_t *uid, ZNotice_Kind_t kind));

/* Find or insert uid in the old uids buffer.  The buffer is a sorted
 * circular queue.  We make the assumption that most packets arrive in
 * order, so we can usually search for a uid or insert it into the buffer
 * by looking back just a few entries from the end.  Since this code is
 * only executed by the client, the implementation isn't microoptimized. */
static int find_or_insert_uid(uid, kind)
    ZUnique_Id_t *uid;
    ZNotice_Kind_t kind;
{
    static struct _filter {
	ZUnique_Id_t	uid;
	ZNotice_Kind_t	kind;
	time_t		t;
    } *buffer;
    static long size;
    static long start;
    static long num;

    time_t now;
    struct _filter *new;
    long i, j, new_size;
    int result;

    /* Initialize the uid buffer if it hasn't been done already. */
    if (!buffer) {
	size = Z_INITFILTERSIZE;
	buffer = (struct _filter *) malloc(size * sizeof(*buffer));
	if (!buffer)
	    return 0;
    }

    /* Age the uid buffer, discarding any uids older than the clock skew. */
    time(&now);
    while (num && (now - buffer[start % size].t) > CLOCK_SKEW)
	start++, num--;
    start %= size;

    /* Make room for a new uid, since we'll probably have to insert one. */
    if (num == size) {
	new_size = size * 2 + 2;
	new = (struct _filter *) malloc(new_size * sizeof(*new));
	if (!new)
	    return 0;
	for (i = 0; i < num; i++)
	    new[i] = buffer[(start + i) % size];
	free(buffer);
	buffer = new;
	size = new_size;
	start = 0;
    }

    /* Search for this uid in the buffer, starting from the end. */
    for (i = start + num - 1; i >= start; i--) {
	result = memcmp(uid, &buffer[i % size].uid, sizeof(*uid));
	if (result == 0 && buffer[i % size].kind == kind)
	    return 1;
	if (result > 0)
	    break;
    }

    /* We didn't find it; insert the uid into the buffer after i. */
    i++;
    for (j = start + num; j > i; j--)
	buffer[j % size] = buffer[(j - 1) % size];
    buffer[i % size].uid = *uid;
    buffer[i % size].kind = kind;
    buffer[i % size].t = now;
    num++;

    return 0;
}


/* Return 1 if there is a packet waiting, 0 otherwise */

int Z_PacketWaiting()
{
    struct timeval tv;
    fd_set read;

    tv.tv_sec = tv.tv_usec = 0;
    FD_ZERO(&read);
    FD_SET(ZGetFD(), &read);
    return (select(ZGetFD() + 1, &read, NULL, NULL, &tv));
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
    int i, j, from_len, packet_len, zvlen, part, partof;
    char *slash;
    Code_t retval;
    fd_set fds;
    struct timeval tv;

    if (ZGetFD() < 0)
	return (ZERR_NOPORT);
	
    FD_ZERO(&fds);
    FD_SET(ZGetFD(), &fds);
    tv.tv_sec = 60;
    tv.tv_usec = 0;

    if (select(ZGetFD() + 1, &fds, NULL, NULL, &tv) < 0)
      return (errno);
    if (!FD_ISSET(ZGetFD(), &fds))
      return ETIMEDOUT;

    from_len = sizeof(struct sockaddr_in);

    packet_len = recvfrom(ZGetFD(), packet, sizeof(packet), 0, 
			  (struct sockaddr *)&from, &from_len);

    if (packet_len < 0)
	return (errno);

    if (!packet_len)
	return (ZERR_EOF);

    /* Ignore obviously non-Zephyr packets. */
    zvlen = sizeof(ZVERSIONHDR) - 1;
    if (packet_len < zvlen || memcmp(packet, ZVERSIONHDR, zvlen) != 0) {
	Z_discarded_packets++;
	return (ZERR_NONE);
    }	

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
	if (find_or_insert_uid(&notice.z_uid, notice.z_kind))
	    return(ZERR_NONE);

	notice.z_dest_galaxy = "unknown-galaxy";

	for (i=0; i<__ngalaxies; i++)
	    for (j=0; j<__galaxy_list[i].galaxy_config.nservers; j++)
		if (from.sin_addr.s_addr ==
		    __galaxy_list[i].galaxy_config.server_list[j].addr.s_addr) {
		    notice.z_dest_galaxy = __galaxy_list[i].galaxy_config.galaxy;
		    break;
		}

	if ((notice.z_kind != HMACK) && (notice.z_kind != SERVACK)) {
	   /* Check authentication on the notice. */
	   notice.z_checked_auth = ZCheckAuthentication(&notice, &from);
	}
    }


    /*
     * Parse apart the z_multinotice field - if the field is blank for
     * some reason, assume this packet stands by itself.
     */
    slash = strchr(notice.z_multinotice, '/');
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
		qptr->header = (char *) malloc((unsigned) qptr->header_len);
		if (!qptr->header)
		    return (ENOMEM);
		(void) memcpy(qptr->header, packet, qptr->header_len);
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
    (void) memset((char *)qptr, 0, sizeof(struct _Z_InputQ));

    /* Insert the entry at the end of the queue */
    qptr->next = NULL;
    qptr->prev = __Q_Tail;
    if (__Q_Tail)
	__Q_Tail->next = qptr;
    __Q_Tail = qptr;

    if (!__Q_Head)
	__Q_Head = qptr;

    
    /* Copy the from field, multiuid, kind, and checked authentication. */
    qptr->from = from;
    qptr->uid = notice.z_multiuid;
    qptr->kind = notice.z_kind;
    qptr->auth = notice.z_checked_auth;
    
    /*
     * If this is the first part of the notice, we take the header
     * from it.  We only take it if this is the first fragment so that
     * the Unique ID's will be predictable.
     *
     * If a Zephyr Server, we always take the header.
     */
    if (__Zephyr_server || part == 0) {
	qptr->header_len = packet_len-notice.z_message_len;
	qptr->header = (char *) malloc((unsigned) qptr->header_len);
	if (!qptr->header)
	    return ENOMEM;
	(void) memcpy(qptr->header, packet, qptr->header_len);
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
	else if (!(qptr->msg = (char *) malloc((unsigned) notice.z_message_len)))
	    return(ENOMEM);
	else
	    (void) memcpy(qptr->msg, notice.z_message, notice.z_message_len);
	qptr->msg_len = notice.z_message_len;
	__Q_Size += notice.z_message_len;
	qptr->packet_len = qptr->header_len+qptr->msg_len;
	if (!(qptr->packet = (char *) malloc((unsigned) qptr->packet_len)))
	    return (ENOMEM);
	(void) memcpy(qptr->packet, qptr->header, qptr->header_len);
	if(qptr->msg)
	    (void) memcpy(qptr->packet+qptr->header_len, qptr->msg,
			   qptr->msg_len);
	return (ZERR_NONE);
    }

    /*
     * We know how long the message is going to be (this is better
     * than IP fragmentation...), so go ahead and allocate it all.
     */
    if (!(qptr->msg = (char *) malloc((unsigned) partof)) && partof)
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

    /* Incorporate this notice's checked authentication. */
    if (notice->z_checked_auth == ZAUTH_FAILED)
	qptr->auth = ZAUTH_FAILED;
    else if (notice->z_checked_auth == ZAUTH_NO && qptr->auth != ZAUTH_FAILED)
	qptr->auth = ZAUTH_NO;

    (void) gettimeofday(&tv, (struct timezone *)0);
    qptr->timep = tv.tv_sec;
    
    last = part+notice->z_message_len-1;

    hole = qptr->holelist;
    lasthole = (struct _Z_Hole *) 0;

    /* copy in the message body */
    (void) memcpy(qptr->msg+part, notice->z_message, notice->z_message_len);

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
	if (!(qptr->packet = (char *) malloc((unsigned) qptr->packet_len)))
	    return (ENOMEM);
	(void) memcpy(qptr->packet, qptr->header, qptr->header_len);
	(void) memcpy(qptr->packet+qptr->header_len, qptr->msg,
		       qptr->msg_len);
    }
    
    return (ZERR_NONE);
}

void Z_gettimeofday(struct _ZTimeval *ztv, struct timezone *tz)
{
        struct timeval tv;
        (void) gettimeofday(&tv, tz); /* yeah, yeah, I know */
        ztv->tv_sec=tv.tv_sec;
        ztv->tv_usec=tv.tv_usec;
}

Code_t Z_FormatHeader(notice, buffer, buffer_len, len, cert_routine)
    ZNotice_t *notice;
    char *buffer;
    int buffer_len;
    int *len;
    Z_AuthProc cert_routine;
{
    Code_t retval;
    static char version[BUFSIZ]; /* default init should be all \0 */
    struct sockaddr_in name;
    int namelen = sizeof(name);
    int i, j;

    if (!notice->z_sender)
	notice->z_sender = ZGetSender();

    if (notice->z_port == 0) {
	if (ZGetFD() < 0) {
	    retval = ZOpenPort((u_short *)0);
	    if (retval != ZERR_NONE)
		return (retval);
	}
	retval = getsockname(ZGetFD(), (struct sockaddr *) &name, &namelen);
	if (retval != 0)
	    return (retval);
	notice->z_port = name.sin_port;
    }

    notice->z_multinotice = "";
    
    (void) Z_gettimeofday(&notice->z_uid.tv, (struct timezone *)0);
    notice->z_uid.tv.tv_sec = htonl((u_long) notice->z_uid.tv.tv_sec);
    notice->z_uid.tv.tv_usec = htonl((u_long) notice->z_uid.tv.tv_usec);

    for (i=0; i<__ngalaxies; i++)
	if (notice->z_dest_galaxy == 0 ||
	    strcmp(__galaxy_list[i].galaxy_config.galaxy,
		   notice->z_dest_galaxy) == 0) {
	    memcpy(&notice->z_uid.zuid_addr,
		   &__galaxy_list[i].galaxy_config.server_list[0].my_addr.s_addr,
		   sizeof(struct in_addr));
	    break;
	}

    notice->z_multiuid = notice->z_uid;

    return Z_FormatAuthHeader(notice, buffer, buffer_len, len, cert_routine);
}

Code_t Z_FormatAuthHeader(notice, buffer, buffer_len, len, cert_routine)
    ZNotice_t *notice;
    char *buffer;
    int buffer_len;
    int *len;
    Z_AuthProc cert_routine;
{
    if (!cert_routine) {
	notice->z_auth = 0;
	notice->z_authent_len = 0;
	notice->z_ascii_authent = "";
	notice->z_checksum = 0;
	return (Z_FormatRawHeader(notice, buffer, buffer_len, len,
				  NULL, NULL, NULL, NULL));
    }
    
    return ((*cert_routine)(notice, buffer, buffer_len, len));
} 
	
Code_t Z_FormatRawHeader(notice, buffer, buffer_len, hdr_len,
			 cksum_start, cksum_len, cstart, cend)
    ZNotice_t *notice;
    char *buffer;
    int buffer_len;
    int *hdr_len;
    char **cksum_start;
    int *cksum_len;
    char **cstart, **cend;
{
    static char version_galaxy[BUFSIZ]; /* default init should be all \0 */
    static char version_nogalaxy[BUFSIZ]; /* default init should be all \0 */
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

    if (notice->z_dest_galaxy &&
	*notice->z_dest_galaxy) {
	if (ZGetRhs(notice->z_dest_galaxy) == NULL)
	    return(ZERR_GALAXYUNKNOWN);

	if (!version_galaxy[0])
	    (void) sprintf(version_galaxy, "%s%d.%d", ZVERSIONHDR,
			   ZVERSIONMAJOR, ZVERSIONMINOR_GALAXY);

	if (Z_AddField(&ptr, version_galaxy, end))
	    return (ZERR_HEADERLEN);

	if (Z_AddField(&ptr, notice->z_dest_galaxy, end))
	    return (ZERR_HEADERLEN);
    }

    if (cksum_start)
	*cksum_start = ptr;

    if (!version_nogalaxy[0])
	(void) sprintf(version_nogalaxy, "%s%d.%d", ZVERSIONHDR,
		       ZVERSIONMAJOR, ZVERSIONMINOR_NOGALAXY);

    notice->z_version = version_nogalaxy;

    if (Z_AddField(&ptr, version_nogalaxy, end))
	return (ZERR_HEADERLEN);

    if (ZMakeAscii32(ptr, end-ptr,
		     Z_NUMFIELDS + notice->z_num_other_fields)
	== ZERR_FIELDLEN)
	return (ZERR_HEADERLEN);
    ptr += strlen(ptr)+1;

    if (ZMakeAscii32(ptr, end-ptr, notice->z_kind) == ZERR_FIELDLEN)
	return (ZERR_HEADERLEN);
    ptr += strlen(ptr)+1;

    if (ZMakeAscii(ptr, end-ptr, (unsigned char *)&notice->z_uid, 
		   sizeof(ZUnique_Id_t)) == ZERR_FIELDLEN)
	return (ZERR_HEADERLEN);
    ptr += strlen(ptr)+1;

    if (ZMakeAscii16(ptr, end-ptr, ntohs(notice->z_port)) == ZERR_FIELDLEN)
	return (ZERR_HEADERLEN);
    ptr += strlen(ptr)+1;

    if (ZMakeAscii32(ptr, end-ptr, notice->z_auth) == ZERR_FIELDLEN)
	return (ZERR_HEADERLEN);
    ptr += strlen(ptr)+1;

    if (ZMakeAscii32(ptr, end-ptr, notice->z_authent_len) == ZERR_FIELDLEN)
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
    if (strchr(notice->z_recipient, '@') || !*notice->z_recipient) {
	if (Z_AddField(&ptr, notice->z_recipient, end))
	    return (ZERR_HEADERLEN);
    }
    else {
	(void) sprintf(newrecip, "%s@%s", notice->z_recipient,
		       ZGetRhs(notice->z_dest_galaxy));
	if (Z_AddField(&ptr, newrecip, end))
	    return (ZERR_HEADERLEN);
    }		
    if (Z_AddField(&ptr, notice->z_default_format, end))
	return (ZERR_HEADERLEN);

    /* copy back the end pointer location for crypto checksum */
    if (cstart)
	*cstart = ptr;
    if (ZMakeAscii32(ptr, end-ptr, notice->z_checksum) == ZERR_FIELDLEN)
	return (ZERR_HEADERLEN);
    ptr += strlen(ptr)+1;
    if (cend)
	*cend = ptr;

    if (Z_AddField(&ptr, notice->z_multinotice, end))
	return (ZERR_HEADERLEN);

    if (ZMakeAscii(ptr, end-ptr, (unsigned char *)&notice->z_multiuid, 
		   sizeof(ZUnique_Id_t)) == ZERR_FIELDLEN)
	return (ZERR_HEADERLEN);
    ptr += strlen(ptr)+1;
	
    for (i=0;i<notice->z_num_other_fields;i++)
	if (Z_AddField(&ptr, notice->z_other_fields[i], end))
	    return (ZERR_HEADERLEN);
    
    if (cksum_len)
	*cksum_len = ptr-*cksum_start;

    *hdr_len = ptr-buffer;

    return (ZERR_NONE);
}

static int
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

Code_t Z_SendFragmentedNotice(notice, len, cert_func, send_func)
    ZNotice_t *notice;
    int len;
    Z_AuthProc cert_func;
    Z_SendProc send_func;
{
    ZNotice_t partnotice;
    ZPacket_t buffer;
    char multi[64];
    int i, offset, hdrsize, fragsize, ret_len, message_len, waitforack;
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
	    (void) Z_gettimeofday(&partnotice.z_uid.tv,
				  (struct timezone *)0);
	    partnotice.z_uid.tv.tv_sec =
		htonl((u_long) partnotice.z_uid.tv.tv_sec);
	    partnotice.z_uid.tv.tv_usec =
		htonl((u_long) partnotice.z_uid.tv.tv_usec);

	    for (i=0; i<__ngalaxies; i++)
		if (notice->z_dest_galaxy == 0 ||
		    strcmp(__galaxy_list[i].galaxy_config.galaxy,
			   notice->z_dest_galaxy) == 0) {
		    memcpy((char *)&partnotice.z_uid.zuid_addr,
			   &__galaxy_list[i].galaxy_config.server_list[0].my_addr.s_addr,
			   sizeof(struct in_addr));
		    break;
		}
	}
	message_len = min(notice->z_message_len-offset, fragsize);
	partnotice.z_message = notice->z_message+offset;
	partnotice.z_message_len = message_len;
	if ((retval = Z_FormatAuthHeader(&partnotice, buffer, Z_MAXHEADERLEN,
					 &ret_len, cert_func)) != ZERR_NONE) {
	    return (retval);
	}
	memcpy(buffer + ret_len, partnotice.z_message, message_len);
	if ((retval = (*send_func)(&partnotice, buffer, ret_len+message_len,
				   waitforack)) != ZERR_NONE) {
	    return (retval);
	}
	offset += fragsize;
	if (!notice->z_message_len)
	    break;
    }

    return (ZERR_NONE);
}

void Z_SourceAddr(peer_addr, my_addr)
     struct in_addr *peer_addr, *my_addr;
{
    int s;
    struct sockaddr_in s_in;
    socklen_t sinsize;
    struct hostent *hent;
    char hostname[1024];

    my_addr->s_addr = INADDR_NONE;

    if (peer_addr->s_addr != INADDR_NONE) {
	/* Try to get the local interface address by connecting a UDP
	 * socket to the server address and getting the local address.
	 * Some broken operating systems (e.g. Solaris 2.0-2.5) yield
	 * INADDR_ANY (zero), so we have to check for that. */
	s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s != -1) {
	    memset(&s_in, 0, sizeof(s_in));
	    s_in.sin_family = AF_INET;
	    memcpy(&s_in.sin_addr, peer_addr, sizeof(*peer_addr));
	    s_in.sin_port = HM_SRV_SVC_FALLBACK;
	    sinsize = sizeof(s_in);
	    if (connect(s, (struct sockaddr *) &s_in, sizeof(s_in)) == 0
		&& getsockname(s, (struct sockaddr *) &s_in, &sinsize) == 0
		&& s_in.sin_addr.s_addr != 0)
		memcpy(my_addr, &s_in.sin_addr, sizeof(*my_addr));
	    close(s);
	}
    }

    if (my_addr->s_addr == INADDR_NONE) {
	/* We couldn't figure out the local interface address by the
	 * above method.  Try by resolving the local hostname.  (This
	 * is a pretty broken thing to do) */
	if (gethostname(hostname, sizeof(hostname)) == 0) {
	    hent = gethostbyname(hostname);
	    if (hent && hent->h_addrtype == AF_INET)
		memcpy(my_addr, hent->h_addr, sizeof(*my_addr));
	}
    }

    /* If the above methods failed, zero out my_addr so things will
     * sort of kind of work. */
    if (my_addr->s_addr == INADDR_NONE)
	my_addr->s_addr = 0;
}
    
Code_t Z_ParseGalaxyConfig(str, gc)
     char *str;
     Z_GalaxyConfig *gc;
{
    char *ptra, *ptrb;
    struct hostent *hp;
    enum { CLUSTER, SLOC, HOSTLIST } listtype;
    int hostcount;
    struct in_addr *my_addr, *serv_addr;
#ifdef HAVE_HESIOD
    char **hes_serv_list;
#endif

    gc->galaxy = NULL;

    /* skip whitespace, check for eol or comment */

    ptra = str;
    while (*ptra && isspace(*ptra)) ptra++;

    if (*ptra == '\0' || *ptra == '#') {
       /* no galaxy is ok, it's a blank line */
       return(ZERR_NONE);
    }

    /* scan the galaxy */

    ptrb = ptra;
    while(*ptrb && !isspace(*ptrb) && *ptrb != '#') ptrb++;

    if ((gc->galaxy = (char *) malloc(ptrb - ptra + 1)) == NULL)
	return(ENOMEM);

    strncpy(gc->galaxy, ptra, ptrb - ptra);
    gc->galaxy[ptrb - ptra] = '\0';

    /* skip whitespace, check for eol or comment */

    ptra = ptrb;
    while (*ptra && isspace(*ptra)) ptra++;

    if (*ptra == '\0' || *ptra == '#') {
	free(gc->galaxy);
	return(ZERR_BADCONFGALAXY);
    }

    /* scan the type */

    ptrb = ptra;
    while(*ptrb && !isspace(*ptrb) && *ptrb != '#') ptrb++;

#ifdef HAVE_HESIOD
    if (strncasecmp("hes-cluster", ptra, ptrb - ptra) == 0) {
	listtype = CLUSTER;
    } else if (strncasecmp("hes-sloc", ptra, ptrb - ptra) == 0) {
	listtype = SLOC;
    } else
#endif
	if (strncasecmp("hostlist", ptra, ptrb - ptra) == 0) {
	    listtype = HOSTLIST;
	} else {
	    free(gc->galaxy);
	    return(ZERR_BADCONF);
	}

#ifdef HAVE_HESIOD
    if (listtype == CLUSTER || listtype == SLOC) {
	char *zcluster;

	if (listtype == CLUSTER) {
	    char hostname[1024];

	    if (gethostname(hostname, sizeof(hostname)) != 0) {
		zcluster = 0;
	    } else {
		char **clust_info, **cpp;

		if ((clust_info = hes_resolve(hostname, "CLUSTER")) == NULL) {
		    zcluster = 0;
		} else {
		    for (cpp = clust_info; *cpp; cpp++) {
			if (strncasecmp("ZCLUSTER", *cpp, 9) == 0) {
			    register char *c;
		
			    if ((c = strchr(*cpp, ' ')) == 0) {
				for (cpp = clust_info; *cpp; cpp++)
				    free(*cpp);
				return(ZERR_BADCONFGALAXY);
			    } else {
				if ((zcluster =
				     malloc((unsigned)(strlen(c+1)+1)))
				    != NULL) {
				    strcpy(zcluster, c+1);
				} else {
				    for (cpp = clust_info; *cpp; cpp++)
					free(*cpp);
				    return(ENOMEM);
				}
			    }
			    break;
			}
		    }
		    for (cpp = clust_info; *cpp; cpp++)
			free(*cpp);
		    if (zcluster == NULL) {
			if ((zcluster =
			     malloc((unsigned)(strlen("zephyr")+1))) != NULL)
			    strcpy(zcluster, "zephyr");
			else
			    return(ENOMEM);
		    }
		}
	    }
	} else {
	    /* skip whitespace, check for eol or comment */

	    ptra = ptrb;
	    while (*ptra && isspace(*ptra)) ptra++;

	    if (*ptra == '\0' || *ptra == '#') {
		free(gc->galaxy);
		return(ZERR_BADCONFGALAXY);
	    }

	    /* scan for the service name for the sloc lookup */

	    ptrb = ptra;
	    while(*ptrb && !isspace(*ptrb) && *ptrb != '#') ptrb++;

	    if ((zcluster = (char *) malloc(ptrb - ptra + 1)) == NULL) {
		free(gc->galaxy);
		return(ENOMEM);
	    }

	    strncpy(zcluster, ptra, ptrb - ptra);
	    zcluster[ptrb - ptra] = '\0';

	    /* skip whitespace, check for eol or comment */

	    ptra = ptrb;
	    while (*ptra && isspace(*ptra)) ptra++;

	    if (*ptra != '\0' && *ptra != '#') {
		free(zcluster);
		free(gc->galaxy);
		return(ZERR_BADCONF);
	    }
	}

	/* get the server list from hesiod */
	
	if (((hes_serv_list = hes_resolve(zcluster, "sloc")) == NULL) ||
	    (hes_serv_list[0] == NULL)) {
	    syslog(LOG_ERR, "No hesiod for galaxy %s (%s sloc)",
		   gc->galaxy, zcluster);
	    free(zcluster);
	    free(gc->galaxy);
	    /* treat this as an empty line, since other lines may succeed */
	    gc->galaxy = NULL;
	    return(ZERR_NONE);
	}

	free(zcluster);
    }
#endif

    /* scan hosts */

    gc->server_list = NULL;
    gc->nservers = 0;
    hostcount = 0;

    while (1) {
	if (gc->server_list) {
	    gc->server_list = (Z_SrvNameAddr *)
		realloc(gc->server_list,
			sizeof(Z_SrvNameAddr)*(gc->nservers+1));
	} else {
	    gc->server_list = (Z_SrvNameAddr *)
		malloc(sizeof(Z_SrvNameAddr));
	}

	if (gc->server_list == NULL) {
	    free(gc->galaxy);
	    return(ENOMEM);
	}

#ifdef HAVE_HESIOD
	if (listtype == CLUSTER || listtype == SLOC) {
	    if (*hes_serv_list == NULL)
		break;

	    /* this is clean, but only because hesiod memory management
	       is gross */
	    gc->server_list[gc->nservers].name = *hes_serv_list;
	    hes_serv_list++;
	} else
#endif
	    if (listtype == HOSTLIST) {
		/* skip whitespace, check for eol or comment */

		ptra = ptrb;
		while (*ptra && isspace(*ptra)) ptra++;

		if (*ptra == '\0' || *ptra == '#') {
		    /* end of server list */
		    break;
		}

		/* scan a hostname */

		ptrb = ptra;
		while(*ptrb && !isspace(*ptrb) && *ptrb != '#') ptrb++;

		if ((gc->server_list[gc->nservers].name =
		     (char *) malloc(ptrb - ptra + 1))
		    == NULL) {
		    free(gc->server_list);
		    free(gc->galaxy);
		    return(ENOMEM);
		}

		strncpy(gc->server_list[gc->nservers].name, ptra, ptrb - ptra);
		gc->server_list[gc->nservers].name[ptrb - ptra] = '\0';
	    }

	hostcount++;

	/* now, take the hesiod or hostlist hostname, and resolve it */

	if ((hp = gethostbyname(gc->server_list[gc->nservers].name)) == NULL) {
	    /* if the address lookup fails authoritatively from a
	       hostlist, return an error.  Otherwise, syslog.  This
	       could cause a syslog from a client, but only if a
	       lookup which succeeded from zhm earlier fails now.
	       This isn't perfect, but will do. */

	    if (h_errno != TRY_AGAIN && listtype == HOSTLIST) {
		free(gc->server_list);
		free(gc->galaxy);
		return(ZERR_BADCONFHOST);
	    } else {
		syslog(LOG_ERR, "Lookup for server %s for galaxy %s failed, continuing",
		       gc->server_list[gc->nservers].name, gc->galaxy);

		/* in an ideal world, when we need to find a new
		   server, or when we receive a packet from a server
		   we don't know, we would redo the lookup, but this
		   takes a long time, and blocks.  So for now, we'll
		   only do this when we reread the config info. */

		continue;
	    }
	}

	/* XXX this isn't quite right for multihomed servers. In that
           case, we should add an entry to server_list for each unique
	   address */

	serv_addr = &gc->server_list[gc->nservers].addr;

	if (hp->h_length < sizeof(*serv_addr)) {
	    syslog(LOG_ERR, "Lookup for server %s for galaxy %s failed (h_length < %d), continuing",
		   gc->server_list[gc->nservers].name, gc->galaxy,
		   sizeof(*serv_addr));;
	    continue;
	}

	memcpy((char *) serv_addr, hp->h_addr, sizeof(*serv_addr));

	my_addr = &gc->server_list[gc->nservers].my_addr;

	Z_SourceAddr(serv_addr, my_addr);

	gc->nservers++;
    }

    if (gc->nservers == 0) {
	if (hostcount) {
	    /* this means the net was losing.  skip this galaxy, because
	       another one might be ok. */

	    free(gc->server_list);
	    free(gc->galaxy);
	    gc->galaxy = NULL;
	    return(ZERR_NONE);
	} else {
	    /* this means that a hostlist was empty */

	    return(ZERR_BADCONFGALAXY);
	}
    }

    return(ZERR_NONE);
}

Code_t Z_FreeGalaxyConfig(gc)
     Z_GalaxyConfig *gc;
{
    int i;

    for (i=0; i<gc->nservers; i++)
	free(gc->server_list[i].name);
	
    free(gc->server_list);
    free(gc->galaxy);

    return(ZERR_NONE);
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

#ifdef Z_DEBUG
/* For debugging printing */
const char *const ZNoticeKinds[] = {
    "UNSAFE", "UNACKED", "ACKED", "HMACK", "HMCTL", "SERVACK", "SERVNAK",
    "CLIENTACK", "STAT"
};
#endif

#ifdef Z_DEBUG

#undef Z_debug
#ifdef HAVE_STDARG_H
void Z_debug (const char *format, ...)
{
    va_list pvar;
    if (!__Z_debug_print)
      return;
    va_start (pvar, format);
    (*__Z_debug_print) (format, pvar, __Z_debug_print_closure);
    va_end (pvar);
}
#else /* stdarg */
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
#endif

void Z_debug_stderr (format, args, closure)
     const char *format;
     va_list args;
     void *closure;
{
#ifdef HAVE_VPRINTF
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

#undef ZSetDebug
void ZSetDebug(proc, arg)
    void (*proc) __P((const char *, va_list, void *));
    char *arg;
{
    __Z_debug_print = proc;
    __Z_debug_print_closure = arg;
}
#endif /* Z_DEBUG */

