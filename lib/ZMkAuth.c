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

Code_t
ZResetAuthentication(void)
{
    return ZERR_NONE;
}

Code_t
ZMakeAuthentication(register ZNotice_t *notice,
		    char *buffer,
		    int buffer_len,
		    int *len)
{
#ifdef HAVE_KRB5
    return ZMakeZcodeAuthentication(notice, buffer, buffer_len, len/*?XXX*/);
#else
#ifdef HAVE_KRB4
    int result;
    KTEXT_ST authent;
    char *cstart, *cend;
    ZChecksum_t checksum;
    CREDENTIALS cred;
    C_Block *session;

    result = krb_mk_req(&authent, SERVER_SERVICE,
			SERVER_INSTANCE, __Zephyr_realm, 0);
    if (result != MK_AP_OK)
	return (result+krb_err_base);
    result = krb_get_cred(SERVER_SERVICE, SERVER_INSTANCE,
			  __Zephyr_realm, &cred);
    if (result != KSUCCESS)
	return (result+krb_err_base);

    session = (C_Block *)cred.session;

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
    checksum = des_quad_cksum((unsigned char *)buffer, NULL, cstart - buffer, 0, session);
    checksum ^= des_quad_cksum((unsigned char *)cend, NULL, buffer + *len - cend, 0,
			       session);
    checksum ^= des_quad_cksum((unsigned char *)notice->z_message, NULL, notice->z_message_len,
			       0, session);
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
#endif
}

/* only used by server? */
Code_t
ZMakeZcodeAuthentication(register ZNotice_t *notice,
			 char *buffer,
			 int buffer_len,
			 int *phdr_len)
{
    return ZMakeZcodeRealmAuthentication(notice, buffer, buffer_len, phdr_len,
					 __Zephyr_realm);
}

Code_t
ZMakeZcodeRealmAuthentication(register ZNotice_t *notice,
			       char *buffer,
			       int buffer_len,
			       int *phdr_len,
			       char *realm)
{
#ifdef HAVE_KRB5
    krb5_error_code result;
    krb5_creds *creds;
    krb5_keyblock *keyblock;
    krb5_auth_context authctx;
    krb5_data *authent;
    char *cksum_start, *cstart, *cend;
    int cksum_len, zcode_len, phdr_adj;

    result = ZGetCredsRealm(&creds, realm);
    if (result)
	return result;
    /* HOLDING: creds */

    /* Figure out what checksum type to use */
    keyblock = Z_credskey(creds);
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
			(unsigned char *)authent->data, authent->length);
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
    result = Z_InsertZcodeChecksum(keyblock, notice, buffer, cksum_start,
                                   cksum_len, cstart, cend, buffer_len,
                                   &phdr_adj, 0);
    krb5_free_creds(Z_krb5_ctx, creds);
    if (result) {
         return result;
    }
    *phdr_len += phdr_adj;

    return (result);
#else /* HAVE_KRB5 */
    return ZERR_INTERNAL;
#endif
}

#ifdef HAVE_KRB5
int
ZGetCreds(krb5_creds **creds_out)
{
  return ZGetCredsRealm(creds_out, __Zephyr_realm);
}

int
ZGetCredsRealm(krb5_creds **creds_out,
	       char *realm)
{
  krb5_creds creds_in;
  krb5_ccache ccache; /* XXX make this a global or static?*/
  int result;

  result = krb5_cc_default(Z_krb5_ctx, &ccache);
  if (result)
    return result;

  memset((char *)&creds_in, 0, sizeof(creds_in));
  result = krb5_build_principal(Z_krb5_ctx, &creds_in.server,
				strlen(realm),
				realm,
				SERVER_SERVICE, SERVER_INSTANCE,
				NULL);
  if (result) {
    krb5_cc_close(Z_krb5_ctx, ccache);
    return result;
  }

  result = krb5_cc_get_principal(Z_krb5_ctx, ccache, &creds_in.client);
  if (!result)
      result = krb5_get_credentials(Z_krb5_ctx, 0, ccache, &creds_in, creds_out);

  krb5_cc_close(Z_krb5_ctx, ccache);
  krb5_free_cred_contents(Z_krb5_ctx, &creds_in); /* I also hope this is ok */

  return result;
}
#endif
