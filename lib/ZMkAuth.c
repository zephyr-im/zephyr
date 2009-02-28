/* This file is part of the Project Athena Zephyr Notification System.
 * It contains source for the ZMakeAuthentication function.
 *
 *	Created by:	Robert French
 *
 *	$Id$
 *
 *	Copyright (c) 1987 by the Massachusetts Institute of Technology.
 *	For copying and distribution information, see the file
 *	"mit-copyright.h". 
 */

#include <internal.h>

#ifndef lint
static const char rcsid_ZMakeAuthentication_c[] = "$Id$";
#endif

#ifdef HAVE_KRB4
#include <krb_err.h>
#endif

Code_t ZResetAuthentication () {
    return ZERR_NONE;
}

Code_t ZMakeAuthentication(notice, buffer, buffer_len, len)
    register ZNotice_t *notice;
    char *buffer;
    int buffer_len;
    int *len;
{
#ifdef HAVE_KRB4
    int result;
    time_t now;
    KTEXT_ST authent;
    char *cstart, *cend;
    ZChecksum_t checksum;
    CREDENTIALS cred;
    extern unsigned long des_quad_cksum();

    result = krb_mk_req(&authent, SERVER_SERVICE, 
			SERVER_INSTANCE, __Zephyr_realm, 0);
    if (result != MK_AP_OK)
	return (result+krb_err_base);
    result = krb_get_cred(SERVER_SERVICE, SERVER_INSTANCE,
			  __Zephyr_realm, &cred);
    if (result != KSUCCESS)
	return (result+krb_err_base);

    notice->z_auth = 1;
    notice->z_authent_len = authent.length;
    notice->z_ascii_authent = (char *)malloc((unsigned)authent.length*3);
    /* zero length authent is an error, so malloc(0) is not a problem */
    if (!notice->z_ascii_authent)
	return (ENOMEM);
    if ((result = ZMakeAscii(notice->z_ascii_authent, 
			     authent.length*3, 
			     authent.dat, 
			     authent.length)) != ZERR_NONE) {
	free(notice->z_ascii_authent);
	return (result);
    }
    result = Z_FormatRawHeader(notice, buffer, buffer_len, len, &cstart,
			       &cend);
    free(notice->z_ascii_authent);
    notice->z_authent_len = 0;
    if (result)
	return(result);

    /* Compute a checksum over the header and message. */
    checksum = des_quad_cksum(buffer, NULL, cstart - buffer, 0, cred.session);
    checksum ^= des_quad_cksum(cend, NULL, buffer + *len - cend, 0,
			       cred.session);
    checksum ^= des_quad_cksum(notice->z_message, NULL, notice->z_message_len,
			       0, cred.session);
    notice->z_checksum = checksum;
    ZMakeAscii32(cstart, buffer + buffer_len - cstart, checksum);

    return (ZERR_NONE);
#else
    notice->z_checksum = 0;
    notice->z_auth = 1;
    notice->z_authent_len = 0;
    notice->z_ascii_authent = "";
    return (Z_FormatRawHeader(notice, buffer, buffer_len, len, NULL, NULL));
#endif
}
