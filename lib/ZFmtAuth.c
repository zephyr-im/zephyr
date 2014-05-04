/* This file is part of the Project Athena Zephyr Notification System.
 * It contains source for the ZFormatAuthenticNotice function.
 *
 *	Created by:	Robert French
 *
 *	$Id$
 *
 *	Copyright (c) 1987,1988 by the Massachusetts Institute of Technology.
 *	For copying and distribution information, see the file
 *	"mit-copyright.h".
 */

#ifndef lint
static const char rcsid_ZFormatAuthenticNotice_c[] = "$Id$";
#endif

#include <internal.h>

#ifdef HAVE_KRB5
Code_t
ZFormatAuthenticNoticeV5(ZNotice_t *notice,
			 register char *buffer,
			 register int buffer_len,
			 int *len,
			 krb5_keyblock *keyblock)
{
    ZNotice_t newnotice;
    char *ptr;
    int retval, hdrlen, hdr_adj;
    krb5_enctype enctype;
    krb5_cksumtype cksumtype;
    char *cksum_start, *cstart, *cend;
    int cksum_len;

    retval = Z_ExtractEncCksum(keyblock, &enctype, &cksumtype);
    if (retval)
	return (ZAUTH_FAILED);

    newnotice = *notice;
    newnotice.z_auth = 1;
    newnotice.z_authent_len = 0;
    newnotice.z_ascii_authent = "";

    if ((retval = Z_NewFormatRawHeader(&newnotice, buffer, buffer_len,
                                       &hdrlen,
                                       &cksum_start, &cksum_len, &cstart,
                                       &cend)) != ZERR_NONE)
	return (retval);

    /* we know this is only called by the server */
    retval = Z_InsertZcodeChecksum(keyblock, &newnotice, buffer,
                                   cksum_start, cksum_len, cstart, cend,
                                   buffer_len, &hdr_adj, 1);
    if (retval)
	return retval;

    hdrlen += hdr_adj;

    ptr = buffer+hdrlen;

    if (newnotice.z_message_len+hdrlen > buffer_len)
	 return (ZERR_PKTLEN);

    (void) memcpy(ptr, newnotice.z_message, newnotice.z_message_len);

    *len = hdrlen+newnotice.z_message_len;

    if (*len > Z_MAXPKTLEN)
	return (ZERR_PKTLEN);

    return (ZERR_NONE);
}
#endif
