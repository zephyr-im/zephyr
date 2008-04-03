/* This file is part of the Project Athena Zephyr Notification System.
 * It contains source for the ZCheckAuthentication function.
 *
 *	Created by:	Robert French
 *
 *	$Source$
 *	$Author$
 *
 *	Copyright (c) 1987,1991 by the Massachusetts Institute of Technology.
 *	For copying and distribution information, see the file
 *	"mit-copyright.h". 
 */
/* $Header$ */

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
Code_t ZCheckZcodeAuthentication(notice, from)
    ZNotice_t *notice;
    struct sockaddr_in *from;
{	
    /* If the value is already known, return it. */
    if (notice->z_checked_auth != ZAUTH_UNSET)
        return (notice->z_checked_auth);

    if (!notice->z_auth)
        return (ZAUTH_NO);

    if (!notice->z_ascii_checksum)
        return (ZAUTH_NO);

#ifdef HAVE_KRB5
    {
        krb5_error_code result;
        krb5_creds *creds;
        krb5_keyblock *keyblock;
        krb5_enctype enctype;
        krb5_cksumtype cksumtype;
        krb5_data cksumbuf;
	int valid;
        char *cksum0_base, *cksum1_base, *cksum2_base;
        char *svcinst, *x, *y;
        char *asn1_data, *key_data;
        int asn1_len, key_len, cksum0_len, cksum1_len, cksum2_len;

	result = ZGetCreds(&creds);

        if (result)
            return (ZAUTH_NO);
        /* HOLDING: creds */

        /* Figure out what checksum type to use */
	keyblock = Z_credskey(creds);
	key_data = Z_keydata(keyblock);
	key_len = Z_keylen(keyblock);
	result = Z_ExtractEncCksum(keyblock, &enctype, &cksumtype);
        if (result) {
	    krb5_free_creds(Z_krb5_ctx, creds);
	    return (ZAUTH_FAILED);
        }
        /* HOLDING: creds */

        /* Assemble the things to be checksummed */
        /* first part is from start of packet through z_default_format:
         * - z_version
         * - z_num_other_fields
         * - z_kind
         * - z_uid
         * - z_port
         * - z_auth
         * - z_authent_len
         * - z_ascii_authent
         * - z_class
         * - z_class_inst
         * - z_opcode
         * - z_sender
         * - z_recipient
         * - z_default_format
         */
        cksum0_base = notice->z_packet;
        x           = notice->z_default_format;
        cksum0_len  = x + strlen(x) + 1 - cksum0_base;
        /* second part is from z_multinotice through other fields:
         * - z_multinotice
         * - z_multiuid
         * - z_other_fields[]
         */
        cksum1_base = notice->z_multinotice;
        if (notice->z_num_other_fields)
          x = notice->z_other_fields[notice->z_num_other_fields];
        else
          x = cksum1_base + strlen(cksum1_base) + 1; /* multiuid */
        cksum1_len  = x + strlen(x) + 1 - cksum1_base;

        /* last part is the message body */
        cksum2_base = notice->z_message;
        cksum2_len  = notice->z_message_len;

        if ((!notice->z_ascii_checksum || *notice->z_ascii_checksum != 'Z') &&
            key_len == 8 &&
            (enctype == ENCTYPE_DES_CBC_CRC ||
             enctype == ENCTYPE_DES_CBC_MD4 ||
             enctype == ENCTYPE_DES_CBC_MD5)) {
	  /* try old-format checksum (covers cksum0 only) */

            ZChecksum_t our_checksum;

            our_checksum = des_quad_cksum(cksum0_base, NULL, cksum0_len, 0,
                                          key_data);
            if (our_checksum == notice->z_checksum) {
                krb5_free_creds(Z_krb5_ctx, creds);
                return ZAUTH_YES;
            }
        }
        /* HOLDING: creds */

        cksumbuf.length = cksum0_len + cksum1_len + cksum2_len;
        cksumbuf.data = malloc(cksumbuf.length);
        if (!cksumbuf.data) {
	    krb5_free_creds(Z_krb5_ctx, creds);
	    return ZAUTH_NO;
        }
        /* HOLDING: creds, cksumbuf.data */

        memcpy(cksumbuf.data, cksum0_base, cksum0_len);
        memcpy(cksumbuf.data + cksum0_len, cksum1_base, cksum1_len);
        memcpy(cksumbuf.data + cksum0_len + cksum1_len,
               cksum2_base, cksum2_len);

        /* decode zcoded checksum */
        /* The encoded form is always longer than the original */
        asn1_len = strlen(notice->z_ascii_checksum) + 1;
        asn1_data = malloc(asn1_len);
        if (!asn1_data) {
            krb5_free_creds(Z_krb5_ctx, creds);
            free(cksumbuf.data);
            return ZAUTH_FAILED;
        }
        /* HOLDING: creds, asn1_data, cksumbuf.data */
        result = ZReadZcode(notice->z_ascii_checksum,
                            asn1_data, asn1_len, &asn1_len);
        if (result != ZERR_NONE) {
            krb5_free_creds(Z_krb5_ctx, creds);
            free(asn1_data);
            free(cksumbuf.data);
            return ZAUTH_FAILED;
        }
        /* HOLDING: creds, asn1_data, cksumbuf.data */

	valid = Z_krb5_verify_cksum(keyblock, &cksumbuf, cksumtype,
				    asn1_data, asn1_len);

        free(asn1_data);
        krb5_free_creds(Z_krb5_ctx, creds);
        free(cksumbuf.data);

	if (valid)
	  return ZAUTH_YES;
	else
	  return ZAUTH_FAILED;
    }
#endif /* HAVE_KRB5 */
    return (notice->z_auth ? ZAUTH_YES : ZAUTH_NO);
}
