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
static char rcsid_ZFormatAuthenticNotice_c[] = "$Id$";
#endif

#include <internal.h>

#if defined(HAVE_KRB4) || defined(HAVE_KRB5)
Code_t ZFormatAuthenticNotice(notice, buffer, buffer_len, len, session)
    ZNotice_t *notice;
    register char *buffer;
    register int buffer_len;
    int *len;
    C_Block session;
{
    ZNotice_t newnotice;
    char *ptr;
    int retval, hdrlen;

    newnotice = *notice;
    newnotice.z_auth = 1;
    newnotice.z_authent_len = 0;
    newnotice.z_ascii_authent = "";

    if ((retval = Z_FormatRawHeader(&newnotice, buffer, buffer_len,
				    &hdrlen, &ptr, NULL)) != ZERR_NONE)
	return (retval);

#ifdef NOENCRYPTION
    newnotice.z_checksum = 0;
#else
    newnotice.z_checksum =
	(ZChecksum_t)des_quad_cksum(buffer, NULL, ptr - buffer, 0, session);
#endif
    if ((retval = Z_FormatRawHeader(&newnotice, buffer, buffer_len,
				    &hdrlen, NULL, NULL)) != ZERR_NONE)
	return (retval);

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

#ifdef HAVE_KRB5
Code_t ZFormatAuthenticNoticeV5(notice, buffer, buffer_len, len, keyblock)
    ZNotice_t *notice;
    register char *buffer;
    register int buffer_len;
    int *len;
    krb5_keyblock *keyblock;
{
    ZNotice_t newnotice;
    char *ptr;
    int retval, hdrlen, hdr_adj;
    krb5_enctype enctype;
    krb5_cksumtype cksumtype;
    int valid;
    char *svcinst, *x, *y;
    int key_len;
    char *cksum_start, *cstart, *cend;
    int cksum_len;
    
    key_len = Z_keylen(keyblock);
    retval = Z_ExtractEncCksum(keyblock, &enctype, &cksumtype);
    if (retval)
         return (ZAUTH_FAILED);

    if (key_len == 8 && (enctype == ENCTYPE_DES_CBC_CRC || 
                         enctype == ENCTYPE_DES_CBC_MD4 ||
                         enctype == ENCTYPE_DES_CBC_MD5)) {
         C_Block tmp;
         memcpy(&tmp, Z_keydata(keyblock), key_len);
         return ZFormatAuthenticNotice(notice, buffer, buffer_len, len,
                                       tmp);
    }
         
    newnotice = *notice;
    newnotice.z_auth = 1;
    newnotice.z_authent_len = 0;
    newnotice.z_ascii_authent = "";

    if ((retval = Z_NewFormatRawHeader(&newnotice, buffer, buffer_len,
                                       &hdrlen, 
                                       &cksum_start, &cksum_len, &cstart, 
                                       &cend)) != ZERR_NONE)
	return (retval);
     
    retval = Z_InsertZcodeChecksum(keyblock, &newnotice, buffer, 
                                   cksum_start, cksum_len, cstart, cend, 
                                   buffer_len, &hdr_adj);
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
