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

#include <internal.h>

#ifndef lint
static const char rcsid_ZMakeAuthentication_c[] = "$Id$";
#endif

Code_t ZResetAuthentication () {
#ifdef ZEPHYR_USES_KERBEROS
    int i;

    for (i=0; i<__nrealms; i++)
	__realm_list[i].last_authent_time = 0;

#endif
    return ZERR_NONE;
}

Code_t ZMakeAuthentication(notice, buffer, buffer_len, phdr_len)
    register ZNotice_t *notice;
    char *buffer;
    int buffer_len;
    int *phdr_len;
{
#ifdef ZEPHYR_USES_KERBEROS
    int i;
    int result;
    time_t now;
    KTEXT_ST authent;
    int cksum_len;
    char *cksum_start, *cstart, *cend;
    ZChecksum_t checksum;
    CREDENTIALS cred;
    extern unsigned long des_quad_cksum();

    if (notice->z_dest_realm) {
	for (i=0; i<__nrealms; i++) {
	    if (strcasecmp(notice->z_dest_realm,
			   __realm_list[i].realm_config.realm) == 0)
		break;
	}
    } else {
	i = 0;
    }

    now = time(0);
    if ((__realm_list[i].last_authent_time == 0) ||
	(now - __realm_list[i].last_authent_time > 120)) {
	result = krb_mk_req(&authent, SERVER_SERVICE, SERVER_INSTANCE,
			    ZGetRhs(notice->z_dest_realm), 0);
	if (result != MK_AP_OK) {
	    __realm_list[i].last_authent_time = 0;
	    return (result+krb_err_base);
        }
	__realm_list[i].last_authent_time = now;
	__realm_list[i].last_authent = authent;
    }
    else {
	authent = __realm_list[i].last_authent;
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
    result = Z_FormatRawHeader(notice, buffer, buffer_len, phdr_len,
			       &cksum_start, &cksum_len, &cstart, &cend);
    free(notice->z_ascii_authent);
    notice->z_authent_len = 0;
    if (result)
	return(result);

    /* Compute a checksum over the header and message. */

    if ((result = krb_get_cred(SERVER_SERVICE, SERVER_INSTANCE, 
			       ZGetRhs(notice->z_dest_realm), &cred)) != 0)
	return result;
    checksum = des_quad_cksum(cksum_start, NULL, cstart - cksum_start, 0,
			      cred.session);
    checksum ^= des_quad_cksum(cend, NULL, (cksum_start + cksum_len) - cend, 0,
			       cred.session);
    checksum ^= des_quad_cksum(notice->z_message, NULL, notice->z_message_len,
			       0, cred.session);
    notice->z_checksum = checksum;
    ZMakeAscii32(cstart, (buffer + buffer_len) - cstart, checksum);

    return (ZERR_NONE);
#else
    notice->z_checksum = 0;
    notice->z_auth = 1;
    notice->z_authent_len = 0;
    notice->z_ascii_authent = "";
    return (Z_FormatRawHeader(notice, buffer, buffer_len, phdr_len, &cksum_len,
			      NULL, NULL));
#endif
}
