/* This file is part of the Project Athena Zephyr Notification System.
 * It contains source for the ZCheckAuthentication function.
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
static char rcsid_ZCheckAuthentication_c[] =
    "$Zephyr: /mit/zephyr/src/lib/RCS/ZCheckAuthentication.c,v 1.14 89/03/24 14:17:38 jtkohl Exp Locker: raeburn $";
#endif

#include <internal.h>

#if defined(HAVE_KRB5) && !HAVE_KRB5_FREE_DATA
#define krb5_free_data(ctx, dat) free((dat)->data)
#endif

/* Check authentication of the notice.
   If it looks authentic but fails the Kerberos check, return -1.
   If it looks authentic and passes the Kerberos check, return 1.
   If it doesn't look authentic, return 0

   When not using Kerberos, return true if the notice claims to be authentic.
   Only used by clients; the server uses its own routine.
 */
Code_t ZCheckAuthentication(notice, from)
    ZNotice_t *notice;
    struct sockaddr_in *from;
{
#if 0
#if defined(HAVE_KRB4) || defined(HAVE_KRB5)
    int result;
    ZChecksum_t our_checksum;
    C_Block *session;
#ifdef HAVE_KRB5
    krb5_creds *creds_out;
#else
    CREDENTIALS cred;
#endif
    /* If the value is already known, return it. */
    if (notice->z_checked_auth != ZAUTH_UNSET)
	return (notice->z_checked_auth);

    if (!notice->z_auth)
	return (ZAUTH_NO);

#ifdef HAVE_KRB5
    result = ZGetCreds(&creds_out);
    if (result)
      return ZAUTH_NO;
    /* HOLDING: creds_out */

    if (creds_out->keyblock.enctype != ENCTYPE_DES_CBC_CRC)
      return (ZAUTH_NO);
    session = (C_Block *)creds_out->keyblock.contents;
    
#else
    if ((result = krb_get_cred(SERVER_SERVICE, SERVER_INSTANCE, 
			       __Zephyr_realm, &cred)) != 0)
	return (ZAUTH_NO);

    session = (C_Block *)cred.session;
#endif

#ifdef NOENCRYPTION
    our_checksum = 0;
#else
    our_checksum = des_quad_cksum(notice->z_packet, NULL, 
				  notice->z_default_format+
				  strlen(notice->z_default_format)+1-
				  notice->z_packet, 0, session);
#endif
    /* if mismatched checksum, then the packet was corrupted */
    return ((our_checksum == notice->z_checksum) ? ZAUTH_YES : ZAUTH_FAILED);

#else
    return (notice->z_auth ? ZAUTH_YES : ZAUTH_NO);
#endif
#else
    ZCheckZcodeAuthentication(notice, from);
#endif
} 
