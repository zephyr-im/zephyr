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

#if defined(HAVE_KRB5) && !HAVE_KRB5_FREE_DATA
#define krb5_free_data(ctx, dat) free((dat)->data)
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

Code_t ZMakeZcodeAuthentication(notice, buffer, buffer_len, phdr_len)
    register ZNotice_t *notice;
    char *buffer;
    int buffer_len;
    int *phdr_len;
{
    return ZMakeZcodeRealmAuthentication(notice, buffer, buffer_len, phdr_len,
					 __Zephyr_realm);
}

Code_t ZMakeZcodeRealmAuthentication(notice, buffer, buffer_len, phdr_len, 
				     realm)
    register ZNotice_t *notice;
    char *buffer;
    int buffer_len;
    int *phdr_len;
    char *realm;
{
#ifdef HAVE_KRB5
    krb5_error_code result;
    krb5_ccache ccache;
    krb5_creds creds_in, *creds;
    krb5_keyblock *keyblock;
    krb5_enctype enctype;
    krb5_cksumtype cksumtype;
    krb5_auth_context authctx;
    krb5_data *authent;
    krb5_data cksumbuf;
#if HAVE_KRB5_C_MAKE_CHECKSUM
    krb5_checksum checksum;
#else
    krb5_crypto cryptctx;
    Checksum checksum;
    size_t xlen;
#endif
    char *svcinst, *x, *y;
    char *cksum_start, *cstart, *cend, *asn1_data;
    int plain_len;   /* length of part not to be checksummed */
    int cksum_len;   /* length of part to be checksummed (incl cksum) */
    int cksum0_len;  /* length of part before checksum */
    int cksum1_len;  /* length of part after checksum */
    int i, zcode_len, asn1_len;
    
    /* Get a pointer to the default ccache.  We don't need to free this. */
    result = krb5_cc_default(Z_krb5_ctx, &ccache);
    if (result)
	return result;
    
    /* GRRR.  There's no allocator or constructor for krb5_creds */
    /* GRRR.  It would be nice if this API were documented at all */
    memset(&creds_in, 0, sizeof(creds_in));

    result = krb5_cc_get_principal(Z_krb5_ctx, ccache, &creds_in.client);
    if (result) {
      krb5_cc_close(Z_krb5_ctx, ccache);
      return(result);
    }

    /* construct the service principal */
    result = krb5_build_principal(Z_krb5_ctx, &creds_in.server,
				  strlen(realm),
				  realm,
				  SERVER_KRB5_SERVICE, SERVER_INSTANCE, NULL);
    if (result) {
        krb5_free_cred_contents(Z_krb5_ctx, &creds_in); /* hope this is OK */
	krb5_cc_close(Z_krb5_ctx, ccache);
	return result;
    }
    /* HOLDING: creds_in.server, ccache */
    
    /* look up or get the credentials we need */
    result = krb5_get_credentials(Z_krb5_ctx, 0 /* flags */, ccache,
				  &creds_in, &creds);
    krb5_cc_close(Z_krb5_ctx, ccache);
    krb5_free_cred_contents(Z_krb5_ctx, &creds_in); /* hope this is OK */
    if (result)
	return result;
    /* HOLDING: creds */
    
    /* Figure out what checksum type to use */
#if HAVE_KRB5_CREDS_KEYBLOCK_ENCTYPE
    keyblock = &creds->keyblock;
    enctype  = keyblock->enctype;

    result = Z_krb5_lookup_cksumtype(enctype, &cksumtype);
    if (result) {
	krb5_free_creds(Z_krb5_ctx, creds);
	return result;
    }
#else
    keyblock = &creds->session;
    {
       unsigned int len;
       ENCTYPE *val;
       int i = 0;

       result  = krb5_keytype_to_enctypes(Z_krb5_ctx, keyblock->keytype,
                                           &len, &val);
       if (result) {
           krb5_free_creds(Z_krb5_ctx, creds); 
           return result;
       }

       do {
           if (i == len) break;
           result = Z_krb5_lookup_cksumtype(val[i], &cksumtype);
           i++;
       } while (result != 0);

       if (result) {
           krb5_free_creds(Z_krb5_ctx, creds); 
           return result;
       }
       enctype = val[i-1];
    }
#endif
    /* HOLDING: creds */
    
    /* Create the authenticator */
    result = krb5_auth_con_init(Z_krb5_ctx, &authctx);
    if (result) {
	krb5_free_creds(Z_krb5_ctx, creds);
	return (result);
    }

    authent = (krb5_data *)malloc(sizeof(krb5_data));

    /* HOLDING: creds, authctx */
    result = krb5_mk_req_extended(Z_krb5_ctx, &authctx, 0 /* options */,
				  0 /* in_data */, creds, authent);
    krb5_auth_con_free(Z_krb5_ctx, authctx);
    if (result) {
	krb5_free_creds(Z_krb5_ctx, creds);
	return (result);
    }
    /* HOLDING: creds, authent */
    
    /* Encode the authenticator */
    notice->z_auth = 1;
    notice->z_authent_len = authent->length;
    zcode_len = authent->length * 2 + 2; /* 2x growth plus Z and null */
    notice->z_ascii_authent = (char *)malloc(zcode_len);
    if (!notice->z_ascii_authent) {
	krb5_free_data(Z_krb5_ctx, authent);
	krb5_free_creds(Z_krb5_ctx, creds);
	return (ENOMEM);
    }
    /* HOLDING: creds, authent, notice->z_ascii_authent */
    result = ZMakeZcode(notice->z_ascii_authent, zcode_len, 
			authent->data, authent->length);
    krb5_free_data(Z_krb5_ctx, authent);
    if (result) {
	free(notice->z_ascii_authent);
	krb5_free_creds(Z_krb5_ctx, creds);
	return (result);
    }
    /* HOLDING: creds, notice->z_ascii_authent */
    
    /* format the notice header, with a zero checksum */
    result = Z_NewFormatRawHeader(notice, buffer, buffer_len, phdr_len,
				  &cksum_start, &cksum_len, &cstart, &cend);
    free(notice->z_ascii_authent);
    notice->z_authent_len = 0;
    if (result) {
	krb5_free_creds(Z_krb5_ctx, creds);
	return (result);
    }
    /* HOLDING: creds */
    
    /* Assemble the things to be checksummed */
    plain_len  = cksum_start - buffer;
    cksum0_len = cstart - cksum_start;
    cksum1_len = (cksum_start + cksum_len) - cend;
    memset(&cksumbuf, 0, sizeof(cksumbuf));
    cksumbuf.length = cksum0_len + cksum1_len + notice->z_message_len;
    cksumbuf.data = malloc(cksumbuf.length);
    if (!cksumbuf.data) {
	krb5_free_creds(Z_krb5_ctx, creds);
	return (ENOMEM);
    }
    /* HOLDING: creds, cksumbuf.data */
    memcpy(cksumbuf.data, cksum_start, cksum0_len);
    memcpy(cksumbuf.data + cksum0_len, cend, cksum1_len);
    memcpy(cksumbuf.data + cksum0_len + cksum1_len,
	   notice->z_message, notice->z_message_len);
    
#if HAVE_KRB5_C_MAKE_CHECKSUM
    /* Create the checksum -- MIT crypto API */
    result = krb5_c_make_checksum(Z_krb5_ctx, cksumtype,
				  keyblock, Z_KEYUSAGE_CLT_CKSUM,
				  &cksumbuf, &checksum);
    krb5_free_creds(Z_krb5_ctx, creds);
    if (result) {
	free(cksumbuf.data);
	return result;
    }
    /* HOLDING: cksumbuf.data, checksum */

    asn1_data = checksum.contents;
    asn1_len = checksum.length;
#else
    /* Create the checksum -- heimdal crypto API */
    result = krb5_crypto_init(Z_krb5_ctx, keyblock, enctype, &cryptctx);
    krb5_free_creds(Z_krb5_ctx, creds);
    if (result) {
	free(cksumbuf.data);
	return result;
    }
    /* HOLDING: cksumbuf.data, cryptctx */
    result = krb5_create_checksum(Z_krb5_ctx, cryptctx,
				  Z_KEYUSAGE_CLT_CKSUM, cksumtype,
				  cksumbuf.data, cksumbuf.length,
				  &checksum);
    krb5_crypto_destroy(Z_krb5_ctx, cryptctx);
    if (result) {
	free(cksumbuf.data);
	return result;
    }
    asn1_len = checksum.checksum.length;
    asn1_data = checksum.checksum.data;
    /* HOLDING: cksumbuf.data, checksum */
#endif
    
    /* 
     * OK....  we can zcode to a space starting at 'cstart',
     * with a length of buffer_len - (plain_len + cksum_len).
     * Then we tack on the end part, which is located at
     * cksumbuf.data + cksum0_len and has length cksum1_len
     */
    result = ZMakeZcode(cstart, buffer_len - (plain_len + cksum_len),
			asn1_data, asn1_len);
    if (!result) {
	zcode_len = strlen(cstart) + 1;
	memcpy(cstart + zcode_len, cksumbuf.data + cksum0_len, cksum1_len);
	*phdr_len -= cksum_len - (cksum0_len + cksum1_len);
	*phdr_len += zcode_len;
    }
    
    /* free stuff up, and then return the result from the last call */

    free(cksumbuf.data);
#if HAVE_KRB5_C_MAKE_CHECKSUM
    krb5_free_checksum_contents(Z_krb5_ctx, &checksum);
#else
    free_Checksum(&checksum);
#endif
    return (result);
#endif /* HAVE_KRB5 */
}
