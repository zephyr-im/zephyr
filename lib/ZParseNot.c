/* This file is part of the Project Athena Zephyr Notification System.
 * It contains source for the ZParseNotice function.
 *
 *	Created by:	Robert French
 *
 *	$Id$
 *
 *	Copyright (c) 1987,1991 by the Massachusetts Institute of Technology.
 *	For copying and distribution information, see the file
 *	"mit-copyright.h". 
 */

#ifndef lint
static const char rcsid_ZParseNotice_c[] =
    "$Zephyr: /mit/zephyr/src/lib/RCS/ZParseNotice.c,v 1.22 91/03/29 03:34:46 raeburn Exp $";
#endif

#include <internal.h>

/* Skip to the next NUL-terminated field in the packet. */
static char *
next_field(char *ptr,
	   char *end)
{
    while (ptr < end && *ptr != '\0')
	ptr++;
    if (ptr < end)
	ptr++;
    return (ptr);
}

Code_t
ZParseNotice(char *buffer,
	     int len,
	     ZNotice_t *notice)
{
    char *ptr, *end;
    unsigned long temp;
    int maj, numfields, i;

#ifdef __LINE__
    int lineno;
    /* Note: This definition of BAD eliminates lint and compiler
     * complains about the "while (0)", but require that the macro not
     * be used as the "then" part of an "if" statement that also has
     * an "else" clause.
     */
#define BAD_PACKET	{lineno=__LINE__;goto badpkt;}
    /* This one gets lint/compiler complaints.  */
/*#define BAD	do{lineno=__LINE__;goto badpkt;}while(0)*/
#else
#define BAD_PACKET	goto badpkt
#endif

    (void) memset((char *)notice, 0, sizeof(ZNotice_t));
	
    ptr = buffer;
    end = buffer+len;

    notice->z_packet = buffer;
    
    notice->z_version = ptr;
    if (strncmp(ptr, ZVERSIONHDR, sizeof(ZVERSIONHDR) - 1))
	return (ZERR_VERS);
    ptr += sizeof(ZVERSIONHDR) - 1;
    if (!*ptr) {
#ifdef Z_DEBUG
	Z_debug ("ZParseNotice: null version string");
#endif
	return ZERR_BADPKT;
    }
    maj = atoi(ptr);
    if (maj != ZVERSIONMAJOR)
	return (ZERR_VERS);
    ptr = next_field(ptr, end);

    if (ZReadAscii32(ptr, end-ptr, &temp) == ZERR_BADFIELD)
	BAD_PACKET;
    numfields = temp;
    ptr = next_field(ptr, end);

    /*XXX 3 */
    numfields -= 2; /* numfields, version, and checksum */
    if (numfields < 0) {
#ifdef __LINE__
	lineno = __LINE__;
      badpkt:
#ifdef Z_DEBUG
	Z_debug ("ZParseNotice: bad packet from %s/%d (line %d)",
		 inet_ntoa (notice->z_uid.zuid_addr.s_addr),
		 notice->z_port, lineno);
#endif
#else
    badpkt:
#ifdef Z_DEBUG
	Z_debug ("ZParseNotice: bad packet from %s/%d",
		 inet_ntoa (notice->z_uid.zuid_addr.s_addr),
		 notice->z_port);
#endif
#endif
	return ZERR_BADPKT;
    }

    if (numfields && ptr < end) {
	if (ZReadAscii32(ptr, end-ptr, &temp) == ZERR_BADFIELD)
	    BAD_PACKET;
	notice->z_kind = (ZNotice_Kind_t)temp;
	numfields--;
	ptr = next_field(ptr, end);
    }
    else
	BAD_PACKET;
	
    if (numfields && ptr < end) {
	if (ZReadAscii(ptr, end-ptr, (unsigned char *)&notice->z_uid,
		       sizeof(ZUnique_Id_t)) == ZERR_BADFIELD)
	    BAD_PACKET;
	notice->z_time.tv_sec = ntohl((u_long) notice->z_uid.tv.tv_sec);
	notice->z_time.tv_usec = ntohl((u_long) notice->z_uid.tv.tv_usec);
	numfields--;
	ptr = next_field(ptr, end);
    }
    else
	BAD_PACKET;
	
    if (numfields && ptr < end) {
	if (ZReadAscii16(ptr, end-ptr, &notice->z_port) == ZERR_BADFIELD)
	    BAD_PACKET;
	notice->z_port = htons(notice->z_port);
	numfields--;
	ptr = next_field(ptr, end);
    }
    else
	BAD_PACKET;

    if (numfields && ptr < end) {
	if (ZReadAscii32(ptr, end-ptr, &temp) == ZERR_BADFIELD)
	    BAD_PACKET;
	notice->z_auth = temp;
	numfields--;
	ptr = next_field(ptr, end);
    }
    else
	BAD_PACKET;
    notice->z_checked_auth = ZAUTH_UNSET;
	
    if (numfields && ptr < end) {
	if (ZReadAscii32(ptr, end-ptr, &temp) == ZERR_BADFIELD)
	    BAD_PACKET;
	notice->z_authent_len = temp;
	numfields--;
	ptr = next_field(ptr, end);
    }
    else
	BAD_PACKET;

    if (numfields && ptr < end) {
	notice->z_ascii_authent = ptr;
	numfields--;
	ptr = next_field(ptr, end);
    }
    else
	BAD_PACKET;

    if (numfields && ptr < end) {
	notice->z_class = ptr;
	numfields--;
	ptr = next_field(ptr, end);
    }
    else
	notice->z_class = "";
	
    if (numfields && ptr < end) {
	notice->z_class_inst = ptr;
	numfields--;
	ptr = next_field(ptr, end);
    }
    else
	notice->z_class_inst = "";

    if (numfields && ptr < end) {
	notice->z_opcode = ptr;
	numfields--;
	ptr = next_field(ptr, end);
    }
    else
	notice->z_opcode = "";

    if (numfields && ptr < end) {
	notice->z_sender = ptr;
	numfields--;
	ptr = next_field(ptr, end);
    }
    else
	notice->z_sender = "";

    if (numfields && ptr < end) {
	notice->z_recipient = ptr;
	numfields--;
	ptr = next_field(ptr, end);
    }
    else
	notice->z_recipient = "";

    if (numfields && ptr < end) {
	notice->z_default_format = ptr;
	numfields--;
	ptr = next_field(ptr, end);
    }
    else
	notice->z_default_format = "";
	
    if (numfields && ptr < end) {
      notice->z_ascii_checksum = ptr;

      if (ZReadAscii32(ptr, end-ptr, &temp) == ZERR_BADFIELD)
	notice->z_checksum = 0;
      else
	notice->z_checksum = temp;

      numfields--;
      ptr = next_field (ptr, end);
    }
    else 
      {
	notice->z_ascii_checksum = "";
	notice->z_checksum = 0;
      }

    if (numfields && ptr < end) {
	notice->z_multinotice = ptr;
	numfields--;
	ptr = next_field(ptr, end);
    }
    else
	notice->z_multinotice = "";

    if (numfields && ptr < end) {
	if (ZReadAscii(ptr, end-ptr, (unsigned char *)&notice->z_multiuid,
		       sizeof(ZUnique_Id_t)) == ZERR_BADFIELD)
	    BAD_PACKET;
	notice->z_time.tv_sec = ntohl((u_long) notice->z_multiuid.tv.tv_sec);
	notice->z_time.tv_usec = ntohl((u_long) notice->z_multiuid.tv.tv_usec);
	numfields--;
	ptr = next_field(ptr, end);
    }
    else
	notice->z_multiuid = notice->z_uid;

    if (numfields && ptr < end) {
	/* we will take it on faith that ipv6 addresses are longer than ipv4
	   addresses */
	unsigned char addrbuf[sizeof(notice->z_sender_sockaddr.ip6.sin6_addr)];
	int len;

	/* because we're paranoid about naughtily misformated packets */
	if (memchr(ptr, '\0', end - ptr) == NULL)
	    BAD_PACKET;

	if (ZReadZcode((unsigned char *)ptr, addrbuf, sizeof(addrbuf), &len) == ZERR_BADFIELD)
	    BAD_PACKET;

	if (len == sizeof(notice->z_sender_sockaddr.ip6.sin6_addr))
	    memcpy(&notice->z_sender_sockaddr.ip6.sin6_addr, addrbuf, len);
	else if (len == sizeof(notice->z_sender_sockaddr.ip4.sin_addr))
	    memcpy(&notice->z_sender_sockaddr.ip4.sin_addr, addrbuf, len);
	else
	    BAD_PACKET;

	numfields--;
	ptr = next_field(ptr, end);
    } else {
	memset(&notice->z_sender_sockaddr, 0, sizeof notice->z_sender_sockaddr);
	notice->z_sender_sockaddr.ip4.sin_family = AF_INET;
	notice->z_sender_sockaddr.ip4.sin_addr = notice->z_uid.zuid_addr;
    }

    if (numfields && ptr < end) {
	if (ZReadAscii16(ptr, end-ptr, &notice->z_charset) == ZERR_BADFIELD)
	    BAD_PACKET;
	notice->z_charset = htons(notice->z_charset);

	numfields--;
	ptr = next_field(ptr, end);
    } else
	notice->z_charset = ZCHARSET_UNKNOWN;
    
    for (i=0;ptr < end && i<Z_MAXOTHERFIELDS && numfields;i++,numfields--) {
	notice->z_other_fields[i] = ptr;
	ptr = next_field(ptr, end);
    }
    notice->z_num_other_fields = i;
    
    for (i=0;ptr < end && numfields;numfields--)
	ptr = next_field(ptr, end);

    if (numfields || *(ptr - 1) != '\0')
	BAD_PACKET;

    notice->z_message = (caddr_t) ptr;
    notice->z_message_len = len-(ptr-buffer);

    return (ZERR_NONE);
}
