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

#ifndef lint
static const char rcsid_Zinternal_c[] =
  "$Id$";
static const char copyright[] =
  "Copyright (c) 1987,1988,1991 by the Massachusetts Institute of Technology.";
#endif

int __Zephyr_fd = -1;
int __Zephyr_open;
int __Zephyr_port = -1;
struct in_addr __My_addr;
int __Q_CompleteLength;
int __Q_Size;
struct _Z_InputQ *__Q_Head, *__Q_Tail;
struct sockaddr_in __HM_addr;
struct sockaddr_in __HM_addr_real;
int __HM_set;
int __Zephyr_server;
ZLocations_t *__locate_list;
int __locate_num;
int __locate_next;
ZSubscription_t *__subscriptions_list;
int __subscriptions_num;
int __subscriptions_next;
int Z_discarded_packets = 0;

#ifdef HAVE_KRB5
/* This context is used throughout */
krb5_context Z_krb5_ctx;

static const struct cksum_map_s {
  krb5_enctype e;
  krb5_cksumtype c;
} cksum_map[] = {
  /* per RFC1510 and draft-ietf-krb-wg-crypto-02.txt */
  { ENCTYPE_NULL,                     CKSUMTYPE_RSA_MD5 },
  { ENCTYPE_DES_CBC_CRC,              CKSUMTYPE_RSA_MD5_DES },
  { ENCTYPE_DES_CBC_MD4,              CKSUMTYPE_RSA_MD4_DES },
  { ENCTYPE_DES_CBC_MD5,              CKSUMTYPE_RSA_MD5_DES },

  /*
   * The implementors hate us, and are inconsistent with names for
   * most things defined after RFC1510.  Note that des3-cbc-sha1
   * and des3-cbc-sha1-kd are listed by number to avoid confusion
   * caused by inconsistency between the names used in the specs
   * and those used by implementations.
   * -- jhutz, 30-Nov-2002
   */

  /* source lost in history (an expired internet-draft) */
  { 5 /* des3-cbc-md5 */,             9  /* rsa-md5-des3 */ },
  { 7 /* des3-cbc-sha1 */,            13 /* hmac-sha1-des3 */ },

  /* per draft-ietf-krb-wg-crypto-02.txt */
  { 16 /* des3-cbc-sha1-kd */,        12 /* hmac-sha1-des3-kd */ },

  /* per draft-raeburn-krb-rijndael-krb-02.txt */
  { 17 /* aes128-cts-hmac-sha1-96 */, 15 /* hmac-sha1-96-aes128 */ },
  { 18 /* aes256-cts-hmac-sha1-96 */, 16 /* hmac-sha1-96-aes256 */ },

  /* per draft-brezak-win2k-krb-rc4-hmac-04.txt */
  { 23 /* rc4-hmac */,                -138 /* hmac-md5 */ },
  { 24 /* rc4-hmac-exp */,            -138 /* hmac-md5 */ },
  { 25 /* camellia128-cts-cmac */,    17 /* cmac-camellia128 */ },
  { 26 /* camellia256-cts-cmac */,    18 /* cmac-camellia256 */ },
};
#define N_CKSUM_MAP (sizeof(cksum_map) / sizeof(struct cksum_map_s))

Code_t
Z_krb5_lookup_cksumtype(krb5_enctype e,
			krb5_cksumtype *c)
{
  unsigned int i;

  for (i = 0; i < N_CKSUM_MAP; i++) {
    if (cksum_map[i].e == e) {
      *c = cksum_map[i].c;
      return ZERR_NONE;
    }
  }
  return KRB5_PROG_ETYPE_NOSUPP;
}
#endif /* HAVE_KRB5 */

char __Zephyr_realm[REALM_SZ];

#ifdef Z_DEBUG
void (*__Z_debug_print)(const char *fmt, va_list args, void *closure);
void *__Z_debug_print_closure;
#endif

#define min(a,b) ((a)<(b)?(a):(b))

static int Z_AddField(char **ptr, char *field, char *end);
static int find_or_insert_uid(ZUnique_Id_t *uid, ZNotice_Kind_t kind);
static Code_t Z_ZcodeFormatRawHeader(ZNotice_t *, char *, int, int *, char **,
				     int *, char **, char **, int cksumstyle,
				     int addrstyle);

/* Find or insert uid in the old uids buffer.  The buffer is a sorted
 * circular queue.  We make the assumption that most packets arrive in
 * order, so we can usually search for a uid or just tack it onto the end.
 * The first entry at at buffer[start], the last is at
 * buffer[(start + num - 1) % size] */
static int
find_or_insert_uid(ZUnique_Id_t *uid,
		   ZNotice_Kind_t kind)
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
    long i, new_size;
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
    }

    /* We didn't find it; stick it on the end */
    i = start + num;
    buffer[i % size].uid = *uid;
    buffer[i % size].kind = kind;
    buffer[i % size].t = now;
    num++;

    return 0;
}


/* Return 1 if there is a packet waiting, 0 otherwise */

int
Z_PacketWaiting(void)
{
    struct timeval tv;
    fd_set readfds;

    tv.tv_sec = tv.tv_usec = 0;
    FD_ZERO(&readfds);
    FD_SET(ZGetFD(), &readfds);
    return (select(ZGetFD() + 1, &readfds, NULL, NULL, &tv));
}


/* Wait for a complete notice to become available */

Code_t
Z_WaitForComplete(void)
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

Code_t
Z_ReadEnqueue(void)
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

struct _Z_InputQ *
Z_SearchQueue(ZUnique_Id_t *uid,
	      ZNotice_Kind_t kind)
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
	if (qptr->timep &&
            (qptr->timep+Z_NOTICETIMELIMIT < (unsigned long)tv.tv_sec))
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

Code_t
Z_ReadWait(void)
{
    register struct _Z_InputQ *qptr;
    ZNotice_t notice;
    ZPacket_t packet;
    struct sockaddr_in olddest, from;
    unsigned int from_len;
    int packet_len, zvlen, part, partof;
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
	return (ZERR_BADPKT);
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
	    retval = ZFormatSmallRawNotice(&tmpnotice, pkt, &len);
	    if (retval == ZERR_NONE)
		retval = ZSendPacket(pkt, len, 0);
	    __HM_addr = olddest;
	    if (retval != ZERR_NONE)
		return retval;
	}
	if (find_or_insert_uid(&notice.z_uid, notice.z_kind))
	    return(ZERR_NONE);

	/* Check authentication on the notice. */
	notice.z_checked_auth = ZCheckAuthentication(&notice, &from);
    }


    /*
     * Parse apart the z_multinotice field - if the field is blank for
     * some reason, assume this packet stands by itself.
     */
    slash = strchr(notice.z_multinotice, '/');
    if (slash) {
	part = atoi(notice.z_multinotice);
	partof = atoi(slash+1);
	if (part < 0 || part > partof || partof <= 0) {
	    part = 0;
	    partof = notice.z_message_len;
	}
    } else {
	part = 0;
	partof = notice.z_message_len;
    }

    /* Too big a packet...just ignore it! */
    if (partof > Z_MAXNOTICESIZE)
	return (ZERR_NONE);

    /* Ignore garbage at the end */
    if (notice.z_message_len > partof - part)
	notice.z_message_len = partof - part;

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

Code_t
Z_AddNoticeToEntry(struct _Z_InputQ *qptr,
		   ZNotice_t *notice,
		   int part)
{
    int last, oldfirst, oldlast;
    struct _Z_Hole *hole, *lasthole;
    struct timeval tv;

    /* Make sure this notice is expirable */
    (void) gettimeofday(&tv, (struct timezone *)0);
    qptr->timep = tv.tv_sec;

    /* Bounds check. */
    if (part < 0 || notice->z_message_len < 0 || part > qptr->msg_len
	|| notice->z_message_len > qptr->msg_len - part)
      return (ZERR_NONE);

    /* Incorporate this notice's checked authentication. */
    if (notice->z_checked_auth == ZAUTH_FAILED)
	qptr->auth = ZAUTH_FAILED;
    else if (notice->z_checked_auth == ZAUTH_NO && qptr->auth != ZAUTH_FAILED)
	qptr->auth = ZAUTH_NO;

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
		lasthole->next = (struct _Z_Hole *)malloc(sizeof(struct _Z_Hole));
		if (lasthole->next == NULL)
		    return ENOMEM;
		hole = lasthole->next;
	    } else {
		qptr->holelist = (struct _Z_Hole *)malloc(sizeof(struct _Z_Hole));
		if (qptr->holelist == NULL)
		    return ENOMEM;
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
		lasthole->next = (struct _Z_Hole *)malloc(sizeof(struct _Z_Hole));
		if (lasthole->next == NULL)
		    return ENOMEM;
		hole = lasthole->next;
	    } else {
		qptr->holelist = (struct _Z_Hole *)malloc(sizeof(struct _Z_Hole));
		if (qptr->holelist == NULL)
		    return ENOMEM;
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

void
Z_gettimeofday(struct _ZTimeval *ztv,
	       struct timezone *tz)
{
        struct timeval tv;
        (void) gettimeofday(&tv, tz); /* yeah, yeah, I know */
        ztv->tv_sec=tv.tv_sec;
        ztv->tv_usec=tv.tv_usec;
}

Code_t
Z_FormatHeader(ZNotice_t *notice,
	       char *buffer,
	       int buffer_len,
	       int *len,
	       Z_AuthProc cert_routine)
{
    Code_t retval;
    static char version[BUFSIZ]; /* default init should be all \0 */

    if (!notice->z_sender)
	notice->z_sender = ZGetSender();

    if (notice->z_port == 0) {
	if (ZGetFD() < 0) {
	    retval = ZOpenPort((u_short *)0);
	    if (retval != ZERR_NONE)
		return (retval);
	}
	notice->z_port = __Zephyr_port;
    }

    notice->z_multinotice = "";

    (void) Z_gettimeofday(&notice->z_uid.tv, (struct timezone *)0);
    notice->z_uid.tv.tv_sec = htonl((u_long) notice->z_uid.tv.tv_sec);
    notice->z_uid.tv.tv_usec = htonl((u_long) notice->z_uid.tv.tv_usec);

    (void) memcpy(&notice->z_uid.zuid_addr, &__My_addr, sizeof(__My_addr));

    if (notice->z_sender_sockaddr.ip4.sin_family == 0) {
	(void) memset(&notice->z_sender_sockaddr, 0, sizeof(notice->z_sender_sockaddr));
	notice->z_sender_sockaddr.ip4.sin_family = AF_INET; /*XXX*/
	notice->z_sender_sockaddr.ip4.sin_port = notice->z_port;
	(void) memcpy(&notice->z_sender_sockaddr.ip4.sin_addr, &__My_addr, sizeof(__My_addr));
#ifdef HAVE_SOCKADDR_IN_SIN_LEN
	notice->z_sender_sockaddr.ip4.sin_len = sizeof(notice->z_sender_sockaddr.ip4);
#endif
    }

    notice->z_multiuid = notice->z_uid;

    if (!version[0])
	    (void) sprintf(version, "%s%d.%d", ZVERSIONHDR, ZVERSIONMAJOR,
			   ZVERSIONMINOR);
    notice->z_version = version;

    return Z_FormatAuthHeader(notice, buffer, buffer_len, len, cert_routine);
}

Code_t
Z_NewFormatHeader(ZNotice_t *notice,
		  char *buffer,
		  int buffer_len,
		  int *len,
		  Z_AuthProc cert_routine)
{
    Code_t retval;
    static char version[BUFSIZ]; /* default init should be all \0 */
    struct timeval tv;

    if (!notice->z_sender)
	notice->z_sender = ZGetSender();

    if (notice->z_port == 0) {
	if (ZGetFD() < 0) {
	    retval = ZOpenPort((u_short *)0);
	    if (retval != ZERR_NONE)
		return (retval);
	}
	notice->z_port = __Zephyr_port;
    }

    notice->z_multinotice = "";

    (void) gettimeofday(&tv, (struct timezone *)0);
    notice->z_uid.tv.tv_sec = htonl((u_long) tv.tv_sec);
    notice->z_uid.tv.tv_usec = htonl((u_long) tv.tv_usec);

    (void) memcpy(&notice->z_uid.zuid_addr, &__My_addr, sizeof(__My_addr));

    (void) memset(&notice->z_sender_sockaddr, 0, sizeof(notice->z_sender_sockaddr));
    notice->z_sender_sockaddr.ip4.sin_family = AF_INET; /*XXX*/
    notice->z_sender_sockaddr.ip4.sin_port = notice->z_port;
    (void) memcpy(&notice->z_sender_sockaddr.ip4.sin_addr, &__My_addr, sizeof(__My_addr));
#ifdef HAVE_SOCKADDR_IN_SIN_LEN
    notice->z_sender_sockaddr.ip4.sin_len = sizeof(notice->z_sender_sockaddr.ip4);
#endif

    notice->z_multiuid = notice->z_uid;

    if (!version[0])
	    (void) sprintf(version, "%s%d.%d", ZVERSIONHDR, ZVERSIONMAJOR,
			   ZVERSIONMINOR);
    notice->z_version = version;

    return Z_NewFormatAuthHeader(notice, buffer, buffer_len, len, cert_routine);
}

Code_t
Z_FormatAuthHeaderWithASCIIAddress(ZNotice_t *notice,
				   char *buffer,
				   int buffer_len,
				   int *len)
{
    notice->z_auth = 0;
    notice->z_authent_len = 0;
    notice->z_ascii_authent = "";
    notice->z_checksum = 0;
    if (!(notice->z_sender_sockaddr.sa.sa_family == AF_INET ||
	  notice->z_sender_sockaddr.sa.sa_family == AF_INET6))
	notice->z_sender_sockaddr.sa.sa_family = AF_INET; /* \/\/hatever *//*XXX*/

    return Z_ZcodeFormatRawHeader(notice, buffer, buffer_len, len,
				  NULL, NULL, NULL, NULL, 0, 1);
}

Code_t
Z_FormatAuthHeader(ZNotice_t *notice,
		   char *buffer,
		   int buffer_len,
		   int *len,
		   Z_AuthProc cert_routine)
{
    if (!cert_routine) {
	notice->z_auth = 0;
	notice->z_authent_len = 0;
	notice->z_ascii_authent = "";
	notice->z_checksum = 0;
	return (Z_FormatRawHeader(notice, buffer, buffer_len,
				  len, NULL, NULL));
    }

    return ((*cert_routine)(notice, buffer, buffer_len, len));
}

Code_t
Z_NewFormatAuthHeader(ZNotice_t *notice,
		      char *buffer,
		      int buffer_len,
		      int *len,
		      Z_AuthProc cert_routine)
{
    if (!cert_routine) {
	notice->z_auth = 0;
	notice->z_authent_len = 0;
	notice->z_ascii_authent = "";
	notice->z_checksum = 0;
	return (Z_FormatRawHeader(notice, buffer, buffer_len,
				  len, NULL, NULL));
    }

    return ((*cert_routine)(notice, buffer, buffer_len, len));
}

Code_t
Z_NewFormatRawHeader(ZNotice_t *notice,
		     char *buffer,
		     int buffer_len,
		     int *hdr_len,
		     char **cksum_start,
		     int *cksum_len,
		     char **cstart,
		     char **cend)
{
   return(Z_ZcodeFormatRawHeader(notice, buffer, buffer_len, hdr_len,
				 cksum_start, cksum_len, cstart, cend, 0, 0));
}

Code_t
Z_AsciiFormatRawHeader(ZNotice_t *notice,
		       char *buffer,
		       int buffer_len,
		       int *hdr_len,
		       char **cksum_start,
		       int *cksum_len,
		       char **cstart,
		       char **cend)
{
   return(Z_ZcodeFormatRawHeader(notice, buffer, buffer_len, hdr_len,
				 cksum_start, cksum_len, cstart, cend, 1, 0));
}

static Code_t
Z_ZcodeFormatRawHeader(ZNotice_t *notice,
		       char *buffer,
		       int buffer_len,
		       int *hdr_len,
		       char **cksum_start,
		       int *cksum_len,
		       char **cstart,
		       char **cend,
		       int cksumstyle,
		       int addrstyle)
{
    static char version_nogalaxy[BUFSIZ]; /* default init should be all \0 */
    char newrecip[BUFSIZ];
    char *ptr, *end;
    int i;
    int addrlen = 0;
    unsigned char *addraddr = NULL;

    if (!(notice->z_sender_sockaddr.sa.sa_family == AF_INET ||
	  notice->z_sender_sockaddr.sa.sa_family == AF_INET6))
	return ZERR_ILLVAL;

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

    if (cksum_start)
        *cksum_start = ptr;

    (void) sprintf(version_nogalaxy, "%s%d.%d", ZVERSIONHDR,
		   ZVERSIONMAJOR, ZVERSIONMINOR);

    notice->z_version = version_nogalaxy;

    if (Z_AddField(&ptr, version_nogalaxy, end))
        return (ZERR_HEADERLEN);

    if (ZMakeAscii32(ptr, end-ptr,
                     (notice->z_num_hdr_fields ? (notice->z_num_hdr_fields - notice->z_num_other_fields) : Z_NUMFIELDS) + notice->z_num_other_fields)
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
	if (strlen(notice->z_recipient) + strlen(__Zephyr_realm) + 2 >
            sizeof(newrecip))
            return (ZERR_HEADERLEN);
        (void) sprintf(newrecip, "%s@%s", notice->z_recipient, __Zephyr_realm);
        if (Z_AddField(&ptr, newrecip, end))
            return (ZERR_HEADERLEN);
    }
    if (Z_AddField(&ptr, notice->z_default_format, end))
        return (ZERR_HEADERLEN);

    /* copy back the end pointer location for crypto checksum */
    if (cstart)
        *cstart = ptr;
    if (cksumstyle == 1) {
      if (Z_AddField(&ptr, notice->z_ascii_checksum, end))
	 return (ZERR_HEADERLEN);
    } else {
#ifdef xZCODE_K4SUM
    if (ZMakeZcode32(ptr, end-ptr, notice->z_checksum) == ZERR_FIELDLEN)
        return ZERR_HEADERLEN;
#else
    if (ZMakeAscii32(ptr, end-ptr, notice->z_checksum) == ZERR_FIELDLEN)
        return (ZERR_HEADERLEN);
#endif
    ptr += strlen(ptr)+1;
    }
    if (cend)
        *cend = ptr;

    if (Z_AddField(&ptr, notice->z_multinotice, end))
        return (ZERR_HEADERLEN);

    if (ZMakeAscii(ptr, end-ptr, (unsigned char *)&notice->z_multiuid,
                   sizeof(ZUnique_Id_t)) == ZERR_FIELDLEN)
        return (ZERR_HEADERLEN);
    ptr += strlen(ptr)+1;

    if (!notice->z_num_hdr_fields || notice->z_num_hdr_fields > 17) {
	if (notice->z_sender_sockaddr.sa.sa_family == AF_INET) {
	    addrlen = sizeof(notice->z_sender_sockaddr.ip4.sin_addr);
	    addraddr = (unsigned char *)&notice->z_sender_sockaddr.ip4.sin_addr;
	} else if (notice->z_sender_sockaddr.sa.sa_family == AF_INET6) {
	    addrlen = sizeof(notice->z_sender_sockaddr.ip6.sin6_addr);
	    addraddr = (unsigned char *)&notice->z_sender_sockaddr.ip6.sin6_addr;
	}

	if (notice->z_sender_sockaddr.sa.sa_family == AF_INET && addrstyle) {
	    if (ZMakeAscii(ptr, end-ptr, addraddr, addrlen) == ZERR_FIELDLEN)
		return ZERR_HEADERLEN;
	} else {
	    if (ZMakeZcode(ptr, end-ptr, addraddr, addrlen) == ZERR_FIELDLEN)
		return ZERR_HEADERLEN;
	}
	ptr += strlen(ptr) + 1;
    }

    if (!notice->z_num_hdr_fields || notice->z_num_hdr_fields > 18) {
	if (ZMakeAscii16(ptr, end-ptr, ntohs(notice->z_charset)) == ZERR_FIELDLEN)
	    return ZERR_HEADERLEN;
	ptr += strlen(ptr) + 1;
    }

    for (i=0;i<notice->z_num_other_fields;i++)
        if (Z_AddField(&ptr, notice->z_other_fields[i], end))
            return (ZERR_HEADERLEN);

    if (cksum_len)
        *cksum_len = ptr-*cksum_start;

    *hdr_len = ptr-buffer;

    return (ZERR_NONE);
}

Code_t
Z_FormatRawHeader(ZNotice_t *notice,
		  char *buffer,
		  int buffer_len,
		  int *len,
		  char **cstart,
		  char **cend)
{

    if (!(notice->z_sender_sockaddr.sa.sa_family == AF_INET ||
	  notice->z_sender_sockaddr.sa.sa_family == AF_INET6))
	notice->z_sender_sockaddr.sa.sa_family = AF_INET; /* \/\/hatever *//*XXX*/

    return Z_ZcodeFormatRawHeader(notice, buffer, buffer_len, len,
				  NULL, NULL, cstart, cend, 0, 0);
}

static int
Z_AddField(char **ptr,
	   char *field,
	   char *end)
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

struct _Z_InputQ *
Z_GetFirstComplete(void)
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

struct _Z_InputQ *
Z_GetNextComplete(struct _Z_InputQ *qptr)
{
    qptr = qptr->next;
    while (qptr) {
	if (qptr->complete)
	    return (qptr);
	qptr = qptr->next;
    }

    return ((struct _Z_InputQ *)0);
}

void
Z_RemQueue(struct _Z_InputQ *qptr)
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

Code_t
Z_SendFragmentedNotice(ZNotice_t *notice,
		       int len,
		       Z_AuthProc cert_func,
		       Z_SendProc send_func)
{
    ZNotice_t partnotice;
    ZPacket_t buffer;
    char multi[64];
    int offset, hdrsize, fragsize, ret_len, message_len, waitforack;
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
	    (void) memcpy((char *)&partnotice.z_uid.zuid_addr, &__My_addr,
			  sizeof(__My_addr));
	    (void) memset(&notice->z_sender_sockaddr, 0, sizeof(notice->z_sender_sockaddr));
	    notice->z_sender_sockaddr.ip4.sin_family = AF_INET; /*XXX*/
	    notice->z_sender_sockaddr.ip4.sin_port = notice->z_port;
	    (void) memcpy(&notice->z_sender_sockaddr.ip4.sin_addr, &__My_addr, sizeof(__My_addr));
#ifdef HAVE_SOCKADDR_IN_SIN_LEN
	    notice->z_sender_sockaddr.ip4.sin_len = sizeof(notice->z_sender_sockaddr.ip4);
#endif
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

/*ARGSUSED*/
Code_t Z_XmitFragment(ZNotice_t *notice,
		      char *buf,
		      int len,
		      int waitforack)
{
    return(ZSendPacket(buf, len, waitforack));
}

/* For debugging printing */
const char *const ZNoticeKinds[] = {
    "UNSAFE", "UNACKED", "ACKED", "HMACK", "HMCTL", "SERVACK", "SERVNAK",
    "CLIENTACK", "STAT"
};

#ifdef Z_DEBUG

#undef Z_debug
void
Z_debug(const char *format, ...)
{
    va_list pvar;
    if (!__Z_debug_print)
      return;
    va_start (pvar, format);
    (*__Z_debug_print) (format, pvar, __Z_debug_print_closure);
    va_end (pvar);
}

void
Z_debug_stderr(const char *format,
	       va_list args,
	       void *closure)
{
#ifdef HAVE_VPRINTF
    vfprintf (stderr, format, args);
#else
    _doprnt (format, args, stderr);
#endif
    putc ('\n', stderr);
}

#undef ZSetDebug
void
ZSetDebug(void (*proc)(const char *, va_list, void *),
	  char *arg)
{
    __Z_debug_print = proc;
    __Z_debug_print_closure = arg;
}
#endif /* Z_DEBUG */

#ifdef HAVE_KRB5
Code_t
Z_Checksum(krb5_data *cksumbuf,
	   krb5_keyblock *keyblock,
	   krb5_cksumtype cksumtype,
	   krb5_keyusage cksumusage,
	   char **asn1_data,
	   unsigned int *asn1_len)
{
    krb5_error_code result;
    unsigned char *data;
    int len;
#ifndef HAVE_KRB5_CRYPTO_INIT
    krb5_checksum checksum;
#else
    Checksum checksum;
    krb5_crypto cryptctx;
#endif

#ifndef HAVE_KRB5_CRYPTO_INIT
    /* Create the checksum -- MIT crypto API */
    result = krb5_c_make_checksum(Z_krb5_ctx, cksumtype,
				  keyblock, cksumusage,
				  cksumbuf, &checksum);
    if (result)
	return result;
    /* HOLDING: checksum */

    data = checksum.contents;
    len = checksum.length;
#else
    /* Create the checksum -- heimdal crypto API */
    result = krb5_crypto_init(Z_krb5_ctx, keyblock, keyblock->keytype,
                              &cryptctx);
    if (result)
	return result;

    /* HOLDING: cryptctx */
    result = krb5_create_checksum(Z_krb5_ctx, cryptctx,
				  cksumusage, cksumtype,
				  cksumbuf->data, cksumbuf->length,
				  &checksum);
    krb5_crypto_destroy(Z_krb5_ctx, cryptctx);
    if (result)
	return result;

    len = checksum.checksum.length;
    data = checksum.checksum.data;
    /* HOLDING: checksum */
#endif

    *asn1_data = malloc(len);
    if (*asn1_data == NULL)
	return errno;
    memcpy(*asn1_data, data, len);
    *asn1_len = len;

#ifndef HAVE_KRB5_CRYPTO_INIT
    krb5_free_checksum_contents(Z_krb5_ctx, &checksum);
#else
    free_Checksum(&checksum);
#endif

    return 0;
}

Code_t
Z_InsertZcodeChecksum(krb5_keyblock *keyblock,
		      ZNotice_t *notice,
                      char *buffer,
		      char *cksum_start,
		      int cksum_len,
                      char *cstart,
		      char *cend,
		      int buffer_len,
                      int *length_adjust,
		      int from_server)
{
     int plain_len;   /* length of part not to be checksummed */
     int cksum0_len;  /* length of part before checksum */
     int cksum1_len;  /* length of part after checksum */
     krb5_data cksumbuf;
     krb5_data cksum;
     unsigned char *cksum_data;
     unsigned int cksum_data_len;
     char *cksum_out_data;
     krb5_enctype enctype;
     krb5_cksumtype cksumtype;
     Code_t result;

     result = Z_ExtractEncCksum(keyblock, &enctype, &cksumtype);
     if (result)
          return (ZAUTH_FAILED);

     /* Assemble the things to be checksummed */
     plain_len  = cksum_start - buffer;
     cksum0_len = cstart - cksum_start;
     cksum1_len = (cksum_start + cksum_len) - cend;
     memset(&cksumbuf, 0, sizeof(cksumbuf));
     cksumbuf.length = cksum0_len + cksum1_len + notice->z_message_len;
     cksumbuf.data = malloc(cksumbuf.length);
     if (!cksumbuf.data)
          return ENOMEM;
     cksum_data = (unsigned char *)cksumbuf.data;
     memcpy(cksum_data, cksum_start, cksum0_len);
     memcpy(cksum_data + cksum0_len, cend, cksum1_len);
     memcpy(cksum_data + cksum0_len + cksum1_len,
            notice->z_message, notice->z_message_len);
     /* compute the checksum */
     result = Z_Checksum(&cksumbuf, keyblock, cksumtype,
			 from_server ? Z_KEYUSAGE_SRV_CKSUM
			  : Z_KEYUSAGE_CLT_CKSUM,
			  &cksum_out_data, &cksum_data_len);
     if (result) {
          free(cksumbuf.data);
          return result;
     }
     cksum.data = cksum_out_data;
     cksum.length = cksum_data_len;

     /*
      * OK....  we can zcode to a space starting at 'cstart',
      * with a length of buffer_len - (plain_len + cksum_len).
      * Then we tack on the end part, which is located at
      * cksumbuf.data + cksum0_len and has length cksum1_len
      */

     result = ZMakeZcode(cstart, buffer_len - (plain_len + cksum_len),
                         (unsigned char *)cksum.data, cksum.length);
     free(cksum.data);
     if (!result) {
          int zcode_len = strlen(cstart) + 1;
          memcpy(cstart + zcode_len, cksum_data + cksum0_len, cksum1_len);
          *length_adjust = zcode_len - cksum_len + (cksum0_len + cksum1_len);
     }
     free(cksumbuf.data);
     return result;
}

Code_t
Z_ExtractEncCksum(krb5_keyblock *keyblock,
		  krb5_enctype *enctype,
                  krb5_cksumtype *cksumtype)
{
    *enctype  = Z_enctype(keyblock);
    return Z_krb5_lookup_cksumtype(*enctype, cksumtype);
}
#endif

#ifdef HAVE_KRB5
/* returns 0 if invalid or losing, 1 if valid, *sigh* */
int
Z_krb5_verify_cksum(krb5_keyblock *keyblock,
		    krb5_data *cksumbuf,
                    krb5_cksumtype cksumtype,
		    krb5_keyusage cksumusage,
		    unsigned char *asn1_data,
                    int asn1_len)
{
    krb5_error_code result;
#ifndef HAVE_KRB5_CRYPTO_INIT
    krb5_checksum checksum;
    krb5_boolean valid;
#else
    krb5_crypto cryptctx;
    Checksum checksum;
#endif

    memset(&checksum, 0, sizeof(checksum));
#ifndef HAVE_KRB5_CRYPTO_INIT
    /* Verify the checksum -- MIT crypto API */
    checksum.length = asn1_len;
    checksum.contents = asn1_data;
    checksum.checksum_type = cksumtype;
    result = krb5_c_verify_checksum(Z_krb5_ctx,
				    keyblock, cksumusage,
				    cksumbuf, &checksum, &valid);
    if (!result && valid)
	return 1;
    else
	return 0;
#else
    checksum.checksum.length = asn1_len;
    checksum.checksum.data = asn1_data;
    checksum.cksumtype = cksumtype;

    result = krb5_crypto_init(Z_krb5_ctx, keyblock, keyblock->keytype, &cryptctx);
    if (result)
	return 0;

    /* HOLDING: cryptctx */
    result = krb5_verify_checksum(Z_krb5_ctx, cryptctx, cksumusage,
				  cksumbuf->data, cksumbuf->length,
				  &checksum);
    krb5_crypto_destroy(Z_krb5_ctx, cryptctx);
    if (result)
	return 0;
    else
	return 1;
#endif
}
#endif
