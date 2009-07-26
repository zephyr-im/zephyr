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
    "$Id$";
#endif

#include <internal.h>
#include <syslog.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

inline static int
_bad_packet(int line, char *where, ZNotice_t *notice, char *what) {
    if (__Zephyr_server) {
	syslog(LOG_ERR, "ZParseNotice: bad packet (%s) from %s.%d at line %d",
	       what, inet_ntoa(notice->z_uid.zuid_addr), notice->z_port, line);
    } else {
#ifdef Z_DEBUG
	Z_debug("ZParseNotice: bad packet (%s) from %s.%d at line %d",
		what, inet_ntoa(notice->z_uid.zuid_addr), notice->z_port, line);
#endif
    }

    return ZERR_BADPKT;
}

/* Skip to the next NUL-terminated field in the packet. */
inline static char *
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

#ifndef __LINE__
#define __LINE__ -1
#endif
#define BAD_PACKET(what)	return _bad_packet(__LINE__, ptr, notice, what)

    (void) memset((char *)notice, 0, sizeof(ZNotice_t));
	
    ptr = buffer;
    end = buffer+len;

    notice->z_packet = buffer;
    
    notice->z_version = ptr;
    if (strncmp(ptr, ZVERSIONHDR, sizeof(ZVERSIONHDR) - 1))
	return (ZERR_VERS);
    ptr += sizeof(ZVERSIONHDR) - 1;
    if (!*ptr)
	BAD_PACKET("null version string");

    maj = atoi(ptr);
    if (maj != ZVERSIONMAJOR)
	return (ZERR_VERS);
    ptr = next_field(ptr, end);

    if (ZReadAscii32(ptr, end-ptr, &temp) == ZERR_BADFIELD)
	BAD_PACKET("parsing num_hdr_fields");
    numfields = temp;
    notice->z_num_hdr_fields = numfields;
    ptr = next_field(ptr, end);

    /*XXX 3 */
    numfields -= 2; /* numfields, version, and checksum */
    if (numfields < 0)
	BAD_PACKET("no header fields");

    if (numfields && ptr < end) {
	if (ZReadAscii32(ptr, end-ptr, &temp) == ZERR_BADFIELD)
	    BAD_PACKET("parsing kind");
	notice->z_kind = (ZNotice_Kind_t)temp;
	numfields--;
	ptr = next_field(ptr, end);
    }
    else
	BAD_PACKET("missing kind");
	
    if (numfields && ptr < end) {
	if (ZReadAscii(ptr, end-ptr, (unsigned char *)&notice->z_uid,
		       sizeof(ZUnique_Id_t)) == ZERR_BADFIELD)
	    BAD_PACKET("parsing uid");
	notice->z_time.tv_sec = ntohl((u_long) notice->z_uid.tv.tv_sec);
	notice->z_time.tv_usec = ntohl((u_long) notice->z_uid.tv.tv_usec);
	numfields--;
	ptr = next_field(ptr, end);
    }
    else
	BAD_PACKET("missing uid");
	
    if (numfields && ptr < end) {
	if (ZReadAscii16(ptr, end-ptr, &notice->z_port) == ZERR_BADFIELD)
	    BAD_PACKET("parsing port");
	notice->z_port = htons(notice->z_port);
	numfields--;
	ptr = next_field(ptr, end);
    }
    else
	BAD_PACKET("missing port");

    if (numfields && ptr < end) {
	if (ZReadAscii32(ptr, end-ptr, &temp) == ZERR_BADFIELD)
	    BAD_PACKET("parsing auth");
	notice->z_auth = temp;
	numfields--;
	ptr = next_field(ptr, end);
    }
    else
	BAD_PACKET("missing auth");
    notice->z_checked_auth = ZAUTH_UNSET;
	
    if (numfields && ptr < end) {
	if (ZReadAscii32(ptr, end-ptr, &temp) == ZERR_BADFIELD)
	    BAD_PACKET("parsing authenticator length");
	notice->z_authent_len = temp;
	numfields--;
	ptr = next_field(ptr, end);
    }
    else
	BAD_PACKET("missing authenticator length");

    if (numfields && ptr < end) {
	notice->z_ascii_authent = ptr;
	numfields--;
	ptr = next_field(ptr, end);
    }
    else
	BAD_PACKET("missing authenticator field");

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
	    BAD_PACKET("parsing multiuid");
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

	/* because we're paranoid about naughtily misformatted packets */
	if (memchr(ptr, '\0', end - ptr) == NULL)
	    BAD_PACKET("unterminated address field");

	if (*ptr == 'Z') {
	    if (ZReadZcode((unsigned char *)ptr, addrbuf,
			   sizeof(addrbuf), &len) == ZERR_BADFIELD)
		BAD_PACKET("parsing Zcode address");
	} else {
	    len = sizeof(notice->z_sender_sockaddr.ip4.sin_addr);
	    if (ZReadAscii(ptr, end - ptr, (unsigned char *)addrbuf,
			   len) == ZERR_BADFIELD)
		BAD_PACKET("parsing NetASCII address");
	}

	if (len == sizeof(notice->z_sender_sockaddr.ip6.sin6_addr)) {
	    notice->z_sender_sockaddr.ip6.sin6_family = AF_INET6;
	    memcpy(&notice->z_sender_sockaddr.ip6.sin6_addr, addrbuf, len);
	} else if (len == sizeof(notice->z_sender_sockaddr.ip4.sin_addr)) {
	    notice->z_sender_sockaddr.ip4.sin_family = AF_INET;
	    memcpy(&notice->z_sender_sockaddr.ip4.sin_addr, addrbuf, len);
	} else
	    BAD_PACKET("address claims to be neither IPv4 or IPv6");

	numfields--;
	ptr = next_field(ptr, end);
    } else {
	memset(&notice->z_sender_sockaddr, 0,
	       sizeof notice->z_sender_sockaddr);
	notice->z_sender_sockaddr.ip4.sin_family = AF_INET;
	notice->z_sender_sockaddr.ip4.sin_addr = notice->z_uid.zuid_addr;
    }

    if (numfields && ptr < end) {
	if (ZReadAscii16(ptr, end-ptr, &notice->z_charset) == ZERR_BADFIELD)
	    BAD_PACKET("parsing charset");
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
	BAD_PACKET("end of headers");

    notice->z_message = (caddr_t) ptr;
    notice->z_message_len = len-(ptr-buffer);

    return (ZERR_NONE);
}
