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
    Code_t result;
    krb5_creds *creds = NULL;

    result = ZGetCredsRealm(&creds, realm);
    if (!result)
	result = Z_MakeZcodeAuthentication(notice, buffer, buffer_len, phdr_len,
					   creds);
    if (creds != NULL)
	krb5_free_creds(Z_krb5_ctx, creds);
    return result;
#else /* HAVE_KRB5 */
    return ZERR_INTERNAL;
#endif
}

#ifdef HAVE_KRB5
Code_t
Z_MakeZcodeAuthentication(register ZNotice_t *notice,
			  char *buffer,
			  int buffer_len,
			  int *phdr_len,
			  krb5_creds *creds)
{
    krb5_error_code result = 0;
    krb5_keyblock *keyblock;
    krb5_auth_context authctx;
    krb5_data *authent;
    char *cksum_start, *cstart, *cend;
    int cksum_len, zcode_len = 0, phdr_adj = 0;

    notice->z_ascii_authent = NULL;

    keyblock = Z_credskey(creds);

    authent = (krb5_data *)malloc(sizeof(krb5_data));
    if (authent == NULL)
	result = ENOMEM;
    authent->data = NULL; /* so that we can blithely krb5_fre_data_contents on
			     the way out */

    if (!result)
	result = krb5_auth_con_init(Z_krb5_ctx, &authctx);

    if (!result) {
	result = krb5_mk_req_extended(Z_krb5_ctx, &authctx, 0 /* options */,
				      0 /* in_data */, creds, authent);
	krb5_auth_con_free(Z_krb5_ctx, authctx);
    }
    if (!result || result == KRB5KRB_AP_ERR_TKT_EXPIRED) {
	notice->z_auth = 1;
	if (result == 0) {
	    notice->z_authent_len = authent->length;
	} else {
	    notice->z_authent_len = 0;
	    result = 0;
	}
	zcode_len = notice->z_authent_len * 2 + 2; /* 2x growth plus Z and null */
	notice->z_ascii_authent = (char *)malloc(zcode_len);
	if (notice->z_ascii_authent == NULL)
	    result = ENOMEM;
    }
    if (!result)
	result = ZMakeZcode(notice->z_ascii_authent, zcode_len,
			    (unsigned char *)authent->data, notice->z_authent_len);

    /* format the notice header, with a zero checksum */
    if (!result)
	result = Z_NewFormatRawHeader(notice, buffer, buffer_len, phdr_len,
				      &cksum_start, &cksum_len, &cstart, &cend);
    notice->z_authent_len = 0;
    if (!result)
	result = Z_InsertZcodeChecksum(keyblock, notice, buffer, cksum_start,
				       cksum_len, cstart, cend, buffer_len,
				       &phdr_adj, 0);
    if (!result) 
	*phdr_len += phdr_adj;

    if (notice->z_ascii_authent != NULL)
	free(notice->z_ascii_authent);
    krb5_free_data_contents(Z_krb5_ctx, authent);
    if (authent != NULL)
	free(authent);
    return result;
}

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
  krb5_creds creds_tmp;
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
  if (!result) {
      result = krb5_cc_retrieve_cred(Z_krb5_ctx, ccache,
#ifdef KRB5_TC_SUPPORTED_KTYPES
				     KRB5_TC_SUPPORTED_KTYPES, /* MIT */
#else
                                     0, /* Heimdal or other Space KRB5 */
#endif
                                     &creds_in, &creds_tmp);
      if (!result) {
	  *creds_out = malloc(sizeof(creds_tmp));
	  if (*creds_out == NULL)
	      result = errno;
	  else
	      memcpy(*creds_out, &creds_tmp, sizeof(creds_tmp));
      }
  }
  if (result == KRB5_CC_NOTFOUND || result == KRB5_CC_END)
      result = krb5_get_credentials(Z_krb5_ctx, 0, ccache, &creds_in, creds_out);

  krb5_cc_close(Z_krb5_ctx, ccache);
  krb5_free_cred_contents(Z_krb5_ctx, &creds_in); /* I also hope this is ok */

  return result;
}
#endif
