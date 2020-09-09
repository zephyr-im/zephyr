/* This file is part of the Project Athena Zephyr Notification System.
 * It contains functions for dealing with Kerberos functions in the server.
 *
 *	Created by:	John T Kohl
 *
 *	Copyright (c) 1988 by the Massachusetts Institute of Technology.
 *	For copying and distribution information, see the file
 *	"mit-copyright.h".
 */
/*
 *	$Source$
 *	$Header$
 */

#include "zserver.h"

#ifndef lint
#ifndef SABER
static const char rcsid_kstuff_c[] = "$Id$";
#endif
#endif

#ifdef HAVE_KRB5
static ZChecksum_t compute_checksum(ZNotice_t *, unsigned char *);
static ZChecksum_t compute_rlm_checksum(ZNotice_t *, unsigned char *);
#endif

#ifdef HAVE_KRB5
Code_t
ReadKerberosData(int fd, int *size, char **data, int *proto) {
    char p[20];
    int i;
    char *dst;
    int len = 0;

    for (i=0; i<20; i++) {
	if (read(fd, &p[i], 1) != 1) {
	    p[i] = 0;
	    syslog(LOG_WARNING,"ReadKerberosData: bad read reply len @%d (got \"%s\"", i, p);
	    return ZSRV_LEN;
	}
	if (p[i] == ' ') {
	    p[i] = '\0';
	    break;
	}
    }

    if (i == 20) {
	syslog(LOG_WARNING, "ReadKerberosData: read reply len exceeds buffer");
	    return ZSRV_BUFSHORT;
    }

    if (!strncmp(p, "V5-", 3) && (len = atoi(p+3)) > 0)
	*proto = 5;
    else if ((len = atoi(p)) > 0)
	*proto = 4;

    if ((*proto < 4) | (*proto > 5)) {
	syslog(LOG_WARNING, "ReadKerberosData: error parsing authenticator length (\"%s\")", p);
	return ZSRV_LEN;
    }

    if (len <= 0) {
	syslog(LOG_WARNING, "ReadKerberosData: read reply len = %d", len);
	return ZSRV_LEN;
    }

    *data = malloc(len);
    if (! *data) {
	syslog(LOG_WARNING, "ReadKerberosData: failure allocating %d bytes: %m", len);
	return errno;
    }

    dst=*data;
    for (i=0; i < len; i++) {
	if (read(fd, dst++, 1) != 1) {
            free(*data);
	    *data = NULL;
	    *size = 0;
            syslog(LOG_WARNING,"ReadKerberosData: bad read reply string");
            return ZSRV_PKSHORT;
        }
    }
    *size = len;
    return 0;
}
#endif

#ifdef HAVE_KRB5
Code_t
GetKrb5Data(int fd, krb5_data *data) {
    char p[20];
    unsigned int i;
    char *dst;

    for (i=0; i<20; i++) {
	if (read(fd, &p[i], 1) != 1) {
	    p[i] = 0;
	    syslog(LOG_WARNING,"bad read reply len @%d (got \"%s\")", i, p);
	    return ZSRV_LEN;
	}
	if (p[i] == ' ') {
	    p[i] = '\0';
	    break;
	}
    }
    if (i == 20 || strncmp(p, "V5-", 3) || !atoi(p+3)) {
        syslog(LOG_WARNING,"bad reply len");
        return ZSRV_LEN;
    }
    data->length = atoi(p+3);
    data->data = malloc(data->length);
    if (! data->data) {
       data->length = 0;
       return errno;
    }
    dst=data->data;
    for (i=0; i < data->length; i++) {
	if (read(fd, dst++, 1) != 1) {
            free(data->data);
            memset((char *)data, 0, sizeof(krb5_data));
            syslog(LOG_WARNING,"bad read reply string");
            return ZSRV_PKSHORT;
        }
    }
    return 0;
}

Code_t
SendKrb5Data(int fd, krb5_data *data) {
    char p[32];
    size_t written, size_to_write;
    sprintf(p, "V5-%lu ", (unsigned long)data->length);
    size_to_write = strlen (p);
    if (size_to_write != (written = write(fd, p, size_to_write)) ||
        data->length != (written = write(fd, data->data, data->length))) {
        return ((ssize_t)written < 0) ? errno : ZSRV_PKSHORT;
    }
    return 0;
}
#endif

Code_t
ZCheckSrvAuthentication(ZNotice_t *notice,
			struct sockaddr_in *from,
			char *realm)
{
#ifdef HAVE_KRB5
    unsigned char *authbuf;
    krb5_principal princ;
    krb5_data packet;
    krb5_ticket *tkt;
    char *name;
    krb5_error_code result;
    krb5_principal server;
    krb5_keytab keytabid = 0;
    krb5_auth_context authctx;
    krb5_keyblock *keyblock;
    krb5_enctype enctype;
    krb5_cksumtype cksumtype;
    krb5_data cksumbuf;
    int valid;
    char *cksum0_base, *cksum1_base = NULL, *cksum2_base;
    char *x;
    unsigned char *asn1_data, *key_data, *cksum_data;
    int asn1_len, key_len, cksum0_len = 0, cksum1_len = 0, cksum2_len = 0;
    KRB5_AUTH_CON_FLAGS_TYPE acflags;
#ifdef KRB5_AUTH_CON_GETAUTHENTICATOR_TAKES_DOUBLE_POINTER
    krb5_authenticator *authenticator;
#define KRB5AUTHENT authenticator
#else
    krb5_authenticator authenticator;
#define KRB5AUTHENT &authenticator
#endif
    int len;
    char *sender;
    char rlmprincipal[MAX_PRINCIPAL_SIZE];

    if (!notice->z_auth)
        return ZAUTH_NO;

    /* Check for bogus authentication data length. */
    if (notice->z_authent_len <= 0) {
        syslog(LOG_DEBUG, "ZCheckSrvAuthentication: bogus authenticator length");
        return ZAUTH_FAILED;
    }

    len = strlen(notice->z_ascii_authent)+1;
    authbuf = malloc(len);

    /* Read in the authentication data. */
    if (ZReadZcode((unsigned char *)notice->z_ascii_authent,
                   authbuf,
                   len, &len) == ZERR_BADFIELD) {
        syslog(LOG_DEBUG, "ZCheckSrvAuthentication: ZReadZcode: Improperly formatted field");
        return ZAUTH_FAILED;
    }

    if (realm == NULL) {
	sender = notice->z_sender;
    } else {
	(void) snprintf(rlmprincipal, MAX_PRINCIPAL_SIZE, "%s/%s@%s", SERVER_SERVICE,
			SERVER_INSTANCE, realm);
	sender = rlmprincipal;
    }

    packet.length = len;
    packet.data = (char *)authbuf;

    result = krb5_kt_resolve(Z_krb5_ctx,
                        keytab_file, &keytabid);
    if (result) {
        free(authbuf);
        syslog(LOG_DEBUG, "ZCheckSrvAuthentication: krb5_kt_resolve: %s", error_message(result));
        return ZAUTH_FAILED;
    }

    /* HOLDING: authbuf, keytabid */
    /* Create the auth context */
    result = krb5_auth_con_init(Z_krb5_ctx, &authctx);
    if (result) {
        krb5_kt_close(Z_krb5_ctx, keytabid);
        free(authbuf);
        syslog(LOG_DEBUG, "ZCheckSrvAuthentication: krb5_auth_con_init: %s", error_message(result));
        return ZAUTH_FAILED;
    }

    /* HOLDING: authbuf, keytabid, authctx */
    result = krb5_auth_con_getflags(Z_krb5_ctx, authctx, &acflags);
    if (result) {
        krb5_auth_con_free(Z_krb5_ctx, authctx);
        krb5_kt_close(Z_krb5_ctx, keytabid);
        free(authbuf);
        syslog(LOG_DEBUG, "ZCheckSrvAuthentication: krb5_auth_con_getflags: %s", error_message(result));
        return ZAUTH_FAILED;
    }

    acflags &= ~KRB5_AUTH_CONTEXT_DO_TIME;

    result = krb5_auth_con_setflags(Z_krb5_ctx, authctx, acflags);
    if (result) {
        krb5_auth_con_free(Z_krb5_ctx, authctx);
        krb5_kt_close(Z_krb5_ctx, keytabid);
        free(authbuf);
        syslog(LOG_DEBUG, "ZCheckSrvAuthentication: krb5_auth_con_setflags: %s", error_message(result));
        return ZAUTH_FAILED;
    }

    result = krb5_build_principal(Z_krb5_ctx, &server, strlen(__Zephyr_realm),
				  __Zephyr_realm, SERVER_SERVICE,
				  SERVER_INSTANCE, NULL);
    if (!result) {
        result = krb5_rd_req(Z_krb5_ctx, &authctx, &packet, server,
                             keytabid, NULL, &tkt);
	krb5_free_principal(Z_krb5_ctx, server);
    }
    krb5_kt_close(Z_krb5_ctx, keytabid);

    /* HOLDING: authbuf, authctx */
    if (result) {
        if (result == KRB5KRB_AP_ERR_REPEAT)
            syslog(LOG_DEBUG, "ZCheckSrvAuthentication: k5 auth failed: %s",
                   error_message(result));
        else
            syslog(LOG_WARNING,"ZCheckSrvAuthentication: k5 auth failed: %s",
                   error_message(result));
        free(authbuf);
        krb5_auth_con_free(Z_krb5_ctx, authctx);
        return ZAUTH_FAILED;
    }

    /* HOLDING: authbuf, authctx, tkt */

    if (tkt == 0 || !Z_tktprincp(tkt)) {
        if (tkt)
            krb5_free_ticket(Z_krb5_ctx, tkt);
        free(authbuf);
        krb5_auth_con_free(Z_krb5_ctx, authctx);
        syslog(LOG_WARNING, "ZCheckSrvAuthentication: No Ticket");
        return ZAUTH_FAILED;
    }

    princ = Z_tktprinc(tkt);

    if (princ == 0) {
        krb5_free_ticket(Z_krb5_ctx, tkt);
        free(authbuf);
        krb5_auth_con_free(Z_krb5_ctx, authctx);
        syslog(LOG_WARNING, "ZCheckSrvAuthentication: No... Ticket?");
        return ZAUTH_FAILED;
    }

    /* HOLDING: authbuf, authctx, tkt */
    result = krb5_unparse_name(Z_krb5_ctx, princ, &name);
    if (result) {
        syslog(LOG_WARNING, "ZCheckSrvAuthentication: krb5_unparse_name failed: %s",
               error_message(result));
        free(authbuf);
        krb5_auth_con_free(Z_krb5_ctx, authctx);
        krb5_free_ticket(Z_krb5_ctx, tkt);
        return ZAUTH_FAILED;
    }

    krb5_free_ticket(Z_krb5_ctx, tkt);

    /* HOLDING: authbuf, authctx, name */
    if (strcmp(name, sender)) {
        syslog(LOG_WARNING, "ZCheckSrvAuthentication: name mismatch: '%s' vs '%s'",
               name, sender);
        krb5_auth_con_free(Z_krb5_ctx, authctx);
#ifdef HAVE_KRB5_FREE_UNPARSED_NAME
        krb5_free_unparsed_name(Z_krb5_ctx, name);
#else
        free(name);
#endif
        free(authbuf);
        return ZAUTH_FAILED;
    }
#ifdef HAVE_KRB5_FREE_UNPARSED_NAME
    krb5_free_unparsed_name(Z_krb5_ctx, name);
#else
    free(name);
#endif
    free(authbuf);

    /* HOLDING: authctx */
    /* Get an authenticator so we can get the keyblock */
    result = krb5_auth_con_getauthenticator (Z_krb5_ctx, authctx,
    					     &authenticator);
    if (result) {
        krb5_auth_con_free(Z_krb5_ctx, authctx);
        syslog(LOG_WARNING, "ZCheckSrvAuthentication: krb5_auth_con_getauthenticator failed: %s",
               error_message(result));
        return ZAUTH_FAILED;
    }

    /* HOLDING: authctx, authenticator */
    result = krb5_auth_con_getkey(Z_krb5_ctx, authctx, &keyblock);
    krb5_auth_con_free(Z_krb5_ctx, authctx);
    krb5_free_authenticator(Z_krb5_ctx, KRB5AUTHENT);
    if (result) {
        syslog(LOG_WARNING, "ZCheckSrvAuthentication: krb5_auth_con_getkey failed: %s",
               error_message(result));
        return (ZAUTH_FAILED);
    }

    /* HOLDING: keyblock */
    /* Figure out what checksum type to use */
    key_data = Z_keydata(keyblock);
    key_len = Z_keylen(keyblock);
    result = Z_ExtractEncCksum(keyblock, &enctype, &cksumtype);
    if (result) {
        krb5_free_keyblock(Z_krb5_ctx, keyblock);
        syslog(LOG_WARNING, "ZCheckSrvAuthentication: Z_ExtractEncCksum failed: %s",
               error_message(result));
        return (ZAUTH_FAILED);
    }
    /* HOLDING: keyblock */

    if (realm == NULL)
	ZSetSession(keyblock);

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
     * - z_sender_(sock)addr
     * - z_charset
     * - z_other_fields[]
     */
    if (notice->z_num_hdr_fields > 15 ) {
	cksum1_base = notice->z_multinotice;
	if (notice->z_num_other_fields)
	    x = notice->z_other_fields[notice->z_num_other_fields - 1];
	else {
	    /* see lib/ZCkZaut.c:ZCheckZcodeAuthentication  */
	    /* XXXXXXXXXXXXXXXXXXXXXXX */
	    if (notice->z_num_hdr_fields > 16)
		x = cksum1_base + strlen(cksum1_base) + 1; /* multinotice */
	    if (notice->z_num_hdr_fields > 17)
		x = x + strlen(x) + 1; /* multiuid */
	    if (notice->z_num_hdr_fields > 18)
		x = x + strlen(x) + 1; /* sender */
	}
	cksum1_len  = x + strlen(x) + 1 - cksum1_base; /* charset / extra field */
    }

    /* last part is the message body */
    cksum2_base = notice->z_message;
    cksum2_len  = notice->z_message_len;

    /*XXX we may wish to ditch this code someday?*/
    if ((!notice->z_ascii_checksum || *notice->z_ascii_checksum != 'Z') &&
        key_len == 8 &&
        (enctype == (krb5_enctype)ENCTYPE_DES_CBC_CRC ||
         enctype == (krb5_enctype)ENCTYPE_DES_CBC_MD4 ||
         enctype == (krb5_enctype)ENCTYPE_DES_CBC_MD5)) {
      /* try old-format checksum (covers cksum0 only) */

      ZChecksum_t our_checksum;

      if (realm == NULL)
	  our_checksum = compute_checksum(notice, key_data);
      else
	  our_checksum = compute_rlm_checksum(notice, key_data);

      krb5_free_keyblock(Z_krb5_ctx, keyblock);

      if (our_checksum == notice->z_checksum) {
          return ZAUTH_YES;
      } else {
          syslog(LOG_DEBUG, "ZCheckSrvAuthentication: des quad checksum mismatch");
          return ZAUTH_FAILED;
      }
    }

    /* HOLDING: keyblock */

    cksumbuf.length = cksum0_len + cksum1_len + cksum2_len;
    cksumbuf.data = malloc(cksumbuf.length);
    if (!cksumbuf.data) {
        krb5_free_keyblock(Z_krb5_ctx, keyblock);
        syslog(LOG_ERR, "ZCheckSrvAuthentication: malloc(cksumbuf.data): %m");
        return ZAUTH_FAILED;
    }
    /* HOLDING: keyblock, cksumbuf.data */

    cksum_data = (unsigned char *)cksumbuf.data;
    memcpy(cksum_data, cksum0_base, cksum0_len);
    if (cksum1_len)
	memcpy(cksum_data + cksum0_len, cksum1_base, cksum1_len);
    memcpy(cksum_data + cksum0_len + cksum1_len,
           cksum2_base, cksum2_len);

    /* decode zcoded checksum */
    /* The encoded form is always longer than the original */
    asn1_len = strlen(notice->z_ascii_checksum) + 1;
    asn1_data = malloc(asn1_len);
    if (!asn1_data) {
        krb5_free_keyblock(Z_krb5_ctx, keyblock);
        free(cksumbuf.data);
        syslog(LOG_ERR, "ZCheckSrvAuthentication: malloc(asn1_data): %m");
        return ZAUTH_FAILED;
    }
    /* HOLDING: keyblock, cksumbuf.data, asn1_data */
    result = ZReadZcode((unsigned char *)notice->z_ascii_checksum,
                        asn1_data, asn1_len, &asn1_len);
    if (result != ZERR_NONE) {
        krb5_free_keyblock(Z_krb5_ctx, keyblock);
        free(asn1_data);
        free(cksumbuf.data);
        syslog(LOG_WARNING, "ZCheckSrvAuthentication: ZReadZcode: %s",
               error_message(result));
        return ZAUTH_FAILED;
    }
    /* HOLDING: asn1_data, cksumbuf.data */

    valid = Z_krb5_verify_cksum(keyblock, &cksumbuf, cksumtype,
				Z_KEYUSAGE_CLT_CKSUM,
				asn1_data, asn1_len);

    /* XXX compatibility with unreleased interrealm krb5; drop in 3.1 */
    if (!valid && realm)
	valid = Z_krb5_verify_cksum(keyblock, &cksumbuf, cksumtype,
				    Z_KEYUSAGE_SRV_CKSUM,
				    asn1_data, asn1_len);

    free(asn1_data);
    krb5_free_keyblock(Z_krb5_ctx, keyblock);
    free(cksumbuf.data);

    if (valid) {
        return ZAUTH_YES;
    } else {
        syslog(LOG_DEBUG, "ZCheckSrvAuthentication: Z_krb5_verify_cksum: failed");
        return ZAUTH_FAILED;
    }
#else
    return (notice->z_auth) ? ZAUTH_YES : ZAUTH_NO;
#endif
}

#undef KRB5AUTHENT


#ifdef HAVE_KRB5
static ZChecksum_t
compute_checksum(ZNotice_t *notice,
		 unsigned char *session_key)
{
    ZChecksum_t checksum;
    char *cstart, *cend, *hstart = notice->z_packet, *hend = notice->z_message;

    cstart = notice->z_default_format + strlen(notice->z_default_format) + 1;
    cend = cstart + strlen(cstart) + 1;
    checksum = z_quad_cksum((unsigned char *)hstart, NULL, cstart - hstart, 0, session_key);
    checksum ^= z_quad_cksum((unsigned char *)cend, NULL, hend - cend, 0, session_key);
    checksum ^= z_quad_cksum((unsigned char *)notice->z_message, NULL, notice->z_message_len,
			     0, session_key);
    return checksum;
}

static ZChecksum_t compute_rlm_checksum(ZNotice_t *notice,
					unsigned char *session_key)
{
    ZChecksum_t checksum;
    char *cstart, *hstart = notice->z_packet;

    cstart = notice->z_default_format + strlen(notice->z_default_format) + 1;
    checksum = z_quad_cksum((unsigned char *)hstart, NULL,
			    cstart - hstart, 0, session_key);

    return checksum;
}
#endif

#ifdef HAVE_KRB5
krb5_error_code
Z_krb5_init_keyblock(krb5_context context,
	krb5_enctype type,
	size_t size,
	krb5_keyblock **key)
{
#ifdef HAVE_KRB5_CREDS_KEYBLOCK_ENCTYPE
	return krb5_init_keyblock(context, type, size, key);
#else
	krb5_error_code ret;
	krb5_keyblock *tmp, tmp_ss;
	tmp = &tmp_ss;

	*key = NULL;
	Z_enctype(tmp) = type;
	Z_keylen(tmp) = size;
	Z_keydata(tmp) = malloc(size);
	if (!Z_keydata(tmp))
		return ENOMEM;
	ret =  krb5_copy_keyblock(context, tmp, key);
	free(Z_keydata(tmp));
	return ret;
#endif
}

void
ZSetSession(krb5_keyblock *keyblock) {
    krb5_error_code result;

    if (__Zephyr_keyblock) {
         krb5_free_keyblock_contents(Z_krb5_ctx, __Zephyr_keyblock);
         result = krb5_copy_keyblock_contents(Z_krb5_ctx, keyblock, __Zephyr_keyblock);
    } else {
         result = krb5_copy_keyblock(Z_krb5_ctx, keyblock, &__Zephyr_keyblock);
    }

    if (result) /*XXX we're out of memory? */
	return;
}
#endif
