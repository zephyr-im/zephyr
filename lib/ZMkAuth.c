/* This file is part of the Project Athena Zephyr Notification System.
 * It contains source for the ZMakeAuthentication function.
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
/* $Id$ */

#ifndef lint
static char rcsid_ZMakeAuthentication_c[] = "$Id$";
#endif

#include <zephyr/zephyr_internal.h>
#ifdef Z_HaveKerberos
#include "krb_err.h"
static long last_authent_time = 0L;
static KTEXT_ST last_authent;
#endif

Code_t ZResetAuthentication () {
#ifdef Z_HaveKerberos
    last_authent_time = 0L;
#endif
    return ZERR_NONE;
}

Code_t ZMakeAuthentication(notice, buffer, buffer_len, len)
    register ZNotice_t *notice;
    char *buffer;
    int buffer_len;
    int *len;
{
#ifdef Z_HaveKerberos
    int result;
    long now,time();
    KTEXT_ST authent;
    char *cstart, *cend;
    long checksum;
    CREDENTIALS cred;

    now = time(0);
    if (last_authent_time == 0 || (now - last_authent_time > 120)) {
	result = krb_mk_req(&authent, SERVER_SERVICE, 
			    SERVER_INSTANCE, __Zephyr_realm, 0);
	if (result != MK_AP_OK) {
	    last_authent_time = 0;
	    return (result+krb_err_base);
        }
	last_authent_time = now;
	last_authent = authent;
    }
    else {
	authent = last_authent;
    }
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
    if (result = krb_get_cred(SERVER_SERVICE, SERVER_INSTANCE, 
			      __Zephyr_realm, &cred))
	return result;
    checksum = des_quad_cksum(buffer, NULL, cstart - buffer, 0, cred.session);
    checksum ^= des_quad_cksum(cend, NULL, buffer + *len - cend, 0,
			       cred.session);
    checksum ^= des_quad_cksum(notice->z_message, NULL, notice->message_len, 0,
			       cred.session);
    notice->z_checksum = (ZChecksum_t) checksum;
    checksum = htonl(checksum);
    ZMakeAscii(cptr, buffer + buffer_len - cptr, (unsigned char *) &checksum,
	       sizeof(checksum));

    return (ZERR_NONE);
#else
    notice->z_checksum = 0;
    notice->z_auth = 1;
    notice->z_authent_len = 0;
    notice->z_ascii_authent = "";
    return (Z_FormatRawHeader(notice, buffer, buffer_len, len, (char **) 0));
#endif
}
