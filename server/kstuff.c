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

#if defined(HAVE_KRB4) && defined(HAVE_KRB5)
static ZChecksum_t compute_checksum(ZNotice_t *, C_Block);
static Code_t ZCheckAuthentication4(ZNotice_t *notice, struct sockaddr_in *from);
#endif
#ifdef HAVE_KRB5
static ZChecksum_t compute_rlm_checksum(ZNotice_t *, unsigned char *);
#endif

#ifdef HAVE_KRB4
/*
 * GetKerberosData
 *
 * get ticket from file descriptor and decode it.
 * Return KFAILURE if we barf on reading the ticket, else return
 * the value of rd_ap_req() applied to the ticket.
 */
int
GetKerberosData(int fd, /* file descr. to read from */
		struct in_addr haddr, /* address of foreign host on fd */
		AUTH_DAT *kdata,	/* kerberos data (returned) */
		char *service, /* service principal desired */
		char *srvtab) /* file to get keys from */
{
    char p[20];
    KTEXT_ST ticket;		/* will get Kerberos ticket from client */
    int i;
    char instance[INST_SZ];

    /*
     * Get the Kerberos ticket.  The first few characters, terminated
     * by a blank, should give us a length; then get than many chars
     * which will be the ticket proper.
     */
    for (i=0; i<20; i++) {
	if (read(fd, &p[i], 1) != 1) {
	    syslog(LOG_WARNING,"bad read tkt len");
	    return(KFAILURE);
	}
	if (p[i] == ' ') {
	    p[i] = '\0';
	    break;
	}
    }
    ticket.length = atoi(p);
    if ((i==20) || (ticket.length<=0) || (ticket.length>MAX_KTXT_LEN)) {
	syslog(LOG_WARNING,"bad tkt len %d",ticket.length);
	return(KFAILURE);
    }
    for (i=0; i<ticket.length; i++) {
	if (read(fd, (caddr_t) &(ticket.dat[i]), 1) != 1) {
	    syslog(LOG_WARNING,"bad tkt read");
	    return(KFAILURE);
	}
    }
    /*
     * now have the ticket.  use it to get the authenticated
     * data from Kerberos.
     */
    (void) strcpy(instance,"*");		/* let Kerberos fill it in */

    return(krb_rd_req(&ticket, service, instance, haddr.s_addr,
		      kdata, srvtab ? srvtab : ""));
}

/*
 * SendKerberosData
 * 
 * create and transmit a ticket over the file descriptor for service.host
 * return failure codes if appropriate, or 0 if we
 * get the ticket and write it to the file descriptor
 */

#if !defined(krb_err_base) && defined(ERROR_TABLE_BASE_krb)
#define krb_err_base ERROR_TABLE_BASE_krb
#endif

Code_t
SendKerberosData(int fd,	/* file descriptor to write onto */
		 KTEXT ticket,	/* where to put ticket (return) */
		 char *service,	/* service name, foreign host */
		 char *host)
		 
{
    int rem;
    char p[32];
    int written;
    int size_to_write;

    rem = krb_mk_req(ticket, service, host, (char *)ZGetRealm(), (u_long) 0);
    if (rem != KSUCCESS)
	return rem + krb_err_base;

    (void) sprintf(p,"%d ",ticket->length);
    size_to_write = strlen (p);
    if ((written = write(fd, p, size_to_write)) != size_to_write)
	return (written < 0) ? errno : ZSRV_PKSHORT;
    if ((written = write(fd, (caddr_t) (ticket->dat), ticket->length))
	!= ticket->length)
	return (written < 0) ? errno : ZSRV_PKSHORT;

    return 0;
}

#endif /* HAVE_KRB4 */

#if defined(HAVE_KRB5) || defined(HAVE_KRB4)
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
    int i;
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
    int written, size_to_write;
    sprintf(p, "V5-%d ", data->length);
    size_to_write = strlen (p);
    if (size_to_write != (written = write(fd, p, size_to_write)) ||
        data->length != (written = write(fd, data->data, data->length))) {
        return (written < 0) ? errno : ZSRV_PKSHORT; 
    }    
    return 0;
}
#endif

Code_t
ZCheckRealmAuthentication(ZNotice_t *notice,
			  struct sockaddr_in *from,
			  char *realm)
{       
#ifdef HAVE_KRB5
    char *authbuf;
    char rlmprincipal[MAX_PRINCIPAL_SIZE];
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
    char *cksum0_base, *cksum1_base, *cksum2_base; 
    char *x; 
    unsigned char *asn1_data;
    unsigned char *key_data; 
    int asn1_len, key_len, cksum0_len, cksum1_len, cksum2_len; 
#ifdef KRB5_AUTH_CON_GETAUTHENTICATOR_TAKES_DOUBLE_POINTER
    krb5_authenticator *authenticator;
#define KRB5AUTHENT authenticator
#else
    krb5_authenticator authenticator;
#define KRB5AUTHENT &authenticator
#endif
    int len;

    if (!notice->z_auth)
        return ZAUTH_NO;

    /* Check for bogus authentication data length. */
    if (notice->z_authent_len <= 0)
        return ZAUTH_FAILED;

    len = strlen(notice->z_ascii_authent)+1;
    authbuf = malloc(len);

    /* Read in the authentication data. */
    if (ZReadZcode((unsigned char *)notice->z_ascii_authent, 
                   (unsigned char *)authbuf,
                   len, &len) == ZERR_BADFIELD) {
        return ZAUTH_FAILED;
    }

    (void) snprintf(rlmprincipal, MAX_PRINCIPAL_SIZE, "%s/%s@%s", SERVER_SERVICE,
                   SERVER_INSTANCE, realm);

    packet.length = len;
    packet.data = authbuf;

    result = krb5_kt_resolve(Z_krb5_ctx, 
                        keytab_file, &keytabid);
    if (result) {
      free(authbuf);
      return (result);
    }

    /* HOLDING: authbuf, keytabid */
    /* Create the auth context */
    result = krb5_auth_con_init(Z_krb5_ctx, &authctx);
    if (result) {
        krb5_kt_close(Z_krb5_ctx, keytabid);
        free(authbuf);
        return (result);
    }

    /* HOLDING: authbuf, authctx */
    result = krb5_build_principal(Z_krb5_ctx, &server, strlen(__Zephyr_realm), 
				  __Zephyr_realm, SERVER_SERVICE, 
				  SERVER_INSTANCE, NULL);
    if (!result) {
        result = krb5_rd_req(Z_krb5_ctx, &authctx, &packet, server, 
                             keytabid, 0, &tkt);
	krb5_free_principal(Z_krb5_ctx, server);
    }
    krb5_kt_close(Z_krb5_ctx, keytabid);

    if (result) {
      if (result == KRB5KRB_AP_ERR_REPEAT)
	syslog(LOG_DEBUG, "ZCheckRealmAuthentication: k5 auth failed: %s", error_message(result));
      else
        syslog(LOG_WARNING,"ZCheckRealmAuthentication: k5 auth failed: %s", error_message(result));
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
	return ZAUTH_FAILED;
    }

    princ = Z_tktprinc(tkt);

    if (princ == 0) {
        krb5_free_ticket(Z_krb5_ctx, tkt);
        free(authbuf);
        krb5_auth_con_free(Z_krb5_ctx, authctx);
        return ZAUTH_FAILED;
    }

    /* HOLDING: authbuf, authctx, tkt */
    result = krb5_unparse_name(Z_krb5_ctx, princ, &name);
    if (result) {
        syslog(LOG_WARNING, "k5 unparse_name failed: %s",
               error_message(result));
        free(authbuf);
        krb5_auth_con_free(Z_krb5_ctx, authctx);
        krb5_free_ticket(Z_krb5_ctx, tkt);
        return ZAUTH_FAILED;
    }

    krb5_free_ticket(Z_krb5_ctx, tkt);

    /* HOLDING: authbuf, authctx, name */
    if (strcmp(name, rlmprincipal)) {
        syslog(LOG_WARNING, "k5 name mismatch: '%s' vs '%s'",
               name, rlmprincipal);
        krb5_auth_con_free(Z_krb5_ctx, authctx);
        free(name);
        free(authbuf);
        return ZAUTH_FAILED;
    }
    free(name);
    free(authbuf);

    /* HOLDING: authctx */
    /* Get an authenticator so we can get the keyblock */
    result = krb5_auth_con_getauthenticator (Z_krb5_ctx, authctx,
    					     &authenticator);
    if(result) {
        krb5_auth_con_free(Z_krb5_ctx, authctx);
        return result;
    }

    /* HOLDING: authctx, authenticator */
    result = krb5_auth_con_getkey(Z_krb5_ctx, authctx, &keyblock);
    if (result) {
      krb5_auth_con_free(Z_krb5_ctx, authctx);
      krb5_free_authenticator(Z_krb5_ctx, KRB5AUTHENT);
      return (ZAUTH_FAILED);
    }
    
    /* HOLDING: authctx, authenticator, keyblock */
    /* Figure out what checksum type to use */
    key_data = Z_keydata(keyblock);
    key_len = Z_keylen(keyblock);
    result = Z_ExtractEncCksum(keyblock, &enctype, &cksumtype);
    if (result) {
	krb5_free_keyblock(Z_krb5_ctx, keyblock);
        krb5_auth_con_free(Z_krb5_ctx, authctx);
        krb5_free_authenticator(Z_krb5_ctx, KRB5AUTHENT);
        return (ZAUTH_FAILED);
    }
    /* HOLDING: authctx, authenticator, keyblock */
 
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

      our_checksum = compute_rlm_checksum(notice, key_data);

      krb5_free_keyblock(Z_krb5_ctx, keyblock);
      krb5_auth_con_free(Z_krb5_ctx, authctx);
      krb5_free_authenticator(Z_krb5_ctx, KRB5AUTHENT);
      
      if (our_checksum == notice->z_checksum) { 
          return ZAUTH_YES; 
      } else
	  return ZAUTH_FAILED;
    }

    /* HOLDING: authctx, authenticator */
 
    cksumbuf.length = cksum0_len + cksum1_len + cksum2_len; 
    cksumbuf.data = malloc(cksumbuf.length); 
    if (!cksumbuf.data) { 
        krb5_free_keyblock(Z_krb5_ctx, keyblock);
        krb5_auth_con_free(Z_krb5_ctx, authctx);
        krb5_free_authenticator(Z_krb5_ctx, KRB5AUTHENT);
        return ZAUTH_FAILED; 
    } 
    /* HOLDING: authctx, authenticator, cksumbuf.data */ 
 
    memcpy(cksumbuf.data, cksum0_base, cksum0_len); 
    memcpy(cksumbuf.data + cksum0_len, cksum1_base, cksum1_len); 
    memcpy(cksumbuf.data + cksum0_len + cksum1_len, 
           cksum2_base, cksum2_len); 
 
    /* decode zcoded checksum */ 
    /* The encoded form is always longer than the original */ 
    asn1_len = strlen(notice->z_ascii_checksum) + 1; 
    asn1_data = malloc(asn1_len); 
    if (!asn1_data) { 
        krb5_free_keyblock(Z_krb5_ctx, keyblock);
        krb5_auth_con_free(Z_krb5_ctx, authctx);
        krb5_free_authenticator(Z_krb5_ctx, KRB5AUTHENT);
        free(cksumbuf.data); 
        return ZAUTH_FAILED; 
    } 
    /* HOLDING: authctx, authenticator, cksumbuf.data, asn1_data */ 
    result = ZReadZcode((unsigned char *)notice->z_ascii_checksum, 
                        asn1_data, asn1_len, &asn1_len); 
    if (result != ZERR_NONE) { 
        krb5_free_keyblock(Z_krb5_ctx, keyblock);
        krb5_auth_con_free(Z_krb5_ctx, authctx);
        krb5_free_authenticator(Z_krb5_ctx, KRB5AUTHENT);
        free(asn1_data); 
        free(cksumbuf.data); 
        return ZAUTH_FAILED; 
    } 
    /* HOLDING: asn1_data, cksumbuf.data */ 

    valid = Z_krb5_verify_cksum(keyblock, &cksumbuf, cksumtype, asn1_data, asn1_len);

    free(asn1_data); 
    krb5_auth_con_free(Z_krb5_ctx, authctx);
    krb5_free_authenticator(Z_krb5_ctx, KRB5AUTHENT);
    krb5_free_keyblock(Z_krb5_ctx, keyblock);
    free(cksumbuf.data); 
    
    if (valid) 
        return (ZAUTH_YES); 
    else 
        return (ZAUTH_FAILED); 
#else
    return (notice->z_auth) ? ZAUTH_YES : ZAUTH_NO;
#endif
}

Code_t
ZCheckAuthentication(ZNotice_t *notice,
		     struct sockaddr_in *from)
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
    char *cksum0_base, *cksum1_base, *cksum2_base; 
    char *x; 
    unsigned char *asn1_data, *key_data; 
    int asn1_len, key_len, cksum0_len, cksum1_len, cksum2_len; 
#ifdef KRB5_AUTH_CON_GETAUTHENTICATOR_TAKES_DOUBLE_POINTER
    krb5_authenticator *authenticator;
#define KRB5AUTHENT authenticator
#else
    krb5_authenticator authenticator;
#define KRB5AUTHENT &authenticator
#endif
    int len;

    if (!notice->z_auth)
        return ZAUTH_NO;

    /* Check for bogus authentication data length. */
    if (notice->z_authent_len <= 1)
        return ZAUTH_FAILED;

#ifdef HAVE_KRB4
    if (notice->z_ascii_authent[0] != 'Z')
      return ZCheckAuthentication4(notice, from);
#endif
    
    len = strlen(notice->z_ascii_authent)+1;
    authbuf = malloc(len);

    /* Read in the authentication data. */
    if (ZReadZcode((unsigned char *)notice->z_ascii_authent, 
                   authbuf,
                   len, &len) == ZERR_BADFIELD) {
        return ZAUTH_FAILED;
    }

    packet.length = len;
    packet.data = (char *)authbuf;

    result = krb5_kt_resolve(Z_krb5_ctx, 
                        keytab_file, &keytabid);
    if (result) {
      free(authbuf);
      return (result);
    }

    /* HOLDING: authbuf, keytabid */
    /* Create the auth context */
    result = krb5_auth_con_init(Z_krb5_ctx, &authctx);
    if (result) {
        krb5_kt_close(Z_krb5_ctx, keytabid);
        free(authbuf);
        return (result);
    }

    /* HOLDING: authbuf, authctx */
    result = krb5_build_principal(Z_krb5_ctx, &server, strlen(__Zephyr_realm), 
				  __Zephyr_realm, SERVER_SERVICE, 
				  SERVER_INSTANCE, NULL);
    if (!result) {
        result = krb5_rd_req(Z_krb5_ctx, &authctx, &packet, server, 
                             keytabid, 0, &tkt);
	krb5_free_principal(Z_krb5_ctx, server);
    }
    krb5_kt_close(Z_krb5_ctx, keytabid);

    if (result) {
      if (result == KRB5KRB_AP_ERR_REPEAT)
	syslog(LOG_DEBUG, "ZCheckAuthentication: k5 auth failed: %s", error_message(result));
      else
        syslog(LOG_WARNING,"ZCheckAuthentication: k5 auth failed: %s", error_message(result));
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
       return ZAUTH_FAILED;
    }
    princ = Z_tktprinc(tkt);

    if (princ == 0) {
        krb5_free_ticket(Z_krb5_ctx, tkt);
        free(authbuf);
        krb5_auth_con_free(Z_krb5_ctx, authctx);
        return ZAUTH_FAILED;
    }

    /* HOLDING: authbuf, authctx, tkt */
    result = krb5_unparse_name(Z_krb5_ctx, princ, &name);
    if (result) {
        syslog(LOG_WARNING, "k5 unparse_name failed: %s",
               error_message(result));
        free(authbuf);
        krb5_auth_con_free(Z_krb5_ctx, authctx);
        krb5_free_ticket(Z_krb5_ctx, tkt);
        return ZAUTH_FAILED;
    }

    krb5_free_ticket(Z_krb5_ctx, tkt);

    /* HOLDING: authbuf, authctx, name */
    if (strcmp(name, notice->z_sender)) {
        syslog(LOG_WARNING, "k5 name mismatch: '%s' vs '%s'",
               name, notice->z_sender);
        krb5_auth_con_free(Z_krb5_ctx, authctx);
        free(name);
        free(authbuf);
        return ZAUTH_FAILED;
    }
    free(name);
    free(authbuf);

    /* HOLDING: authctx */
    /* Get an authenticator so we can get the keyblock */
    result = krb5_auth_con_getauthenticator (Z_krb5_ctx, authctx,
    					     &authenticator);
    if(result) {
        krb5_auth_con_free(Z_krb5_ctx, authctx);
        return result;
    }

    /* HOLDING: authctx, authenticator */
    result = krb5_auth_con_getkey(Z_krb5_ctx, authctx, &keyblock);
    if (result) {
      krb5_auth_con_free(Z_krb5_ctx, authctx);
      krb5_free_authenticator(Z_krb5_ctx, KRB5AUTHENT);
      return (ZAUTH_FAILED);
    }
    
    /* HOLDING: authctx, authenticator, keyblock */
    /* Figure out what checksum type to use */
    key_data = Z_keydata(keyblock);
    key_len = Z_keylen(keyblock);
    result = Z_ExtractEncCksum(keyblock, &enctype, &cksumtype);
    if (result) { 
        krb5_free_keyblock(Z_krb5_ctx, keyblock);
        krb5_auth_con_free(Z_krb5_ctx, authctx);
        krb5_free_authenticator(Z_krb5_ctx, KRB5AUTHENT);
        return (ZAUTH_FAILED); 
    } 
    /* HOLDING: authctx, authenticator, keyblock */

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

#ifdef HAVE_KRB4 /*XXX*/
    if ((!notice->z_ascii_checksum || *notice->z_ascii_checksum != 'Z') && 
        key_len == 8 && 
        (enctype == ENCTYPE_DES_CBC_CRC || 
         enctype == ENCTYPE_DES_CBC_MD4 || 
         enctype == ENCTYPE_DES_CBC_MD5)) { 
      /* try old-format checksum (covers cksum0 only) */ 
 
      ZChecksum_t our_checksum; 
 
      our_checksum = compute_checksum(notice, key_data);
      
      krb5_free_keyblock(Z_krb5_ctx, keyblock);
      krb5_auth_con_free(Z_krb5_ctx, authctx);
      krb5_free_authenticator(Z_krb5_ctx, KRB5AUTHENT);

      if (our_checksum == notice->z_checksum)
	return ZAUTH_YES; 
      else
	return ZAUTH_FAILED;
    }
#endif

    /* HOLDING: authctx, authenticator */
 
    cksumbuf.length = cksum0_len + cksum1_len + cksum2_len; 
    cksumbuf.data = malloc(cksumbuf.length); 
    if (!cksumbuf.data) { 
        krb5_free_keyblock(Z_krb5_ctx, keyblock);
        krb5_auth_con_free(Z_krb5_ctx, authctx);
        krb5_free_authenticator(Z_krb5_ctx, KRB5AUTHENT);
        return ZAUTH_FAILED; 
    } 
    /* HOLDING: authctx, authenticator, cksumbuf.data */ 
 
    memcpy(cksumbuf.data, cksum0_base, cksum0_len); 
    memcpy(cksumbuf.data + cksum0_len, cksum1_base, cksum1_len); 
    memcpy(cksumbuf.data + cksum0_len + cksum1_len, 
           cksum2_base, cksum2_len); 
 
    /* decode zcoded checksum */ 
    /* The encoded form is always longer than the original */ 
    asn1_len = strlen(notice->z_ascii_checksum) + 1; 
    asn1_data = malloc(asn1_len); 
    if (!asn1_data) { 
        krb5_free_keyblock(Z_krb5_ctx, keyblock);
        krb5_auth_con_free(Z_krb5_ctx, authctx);
        krb5_free_authenticator(Z_krb5_ctx, KRB5AUTHENT);
        free(cksumbuf.data); 
        return ZAUTH_FAILED; 
    } 
    /* HOLDING: authctx, authenticator, cksumbuf.data, asn1_data */ 
    result = ZReadZcode((unsigned char *)notice->z_ascii_checksum, 
                        asn1_data, asn1_len, &asn1_len); 
    if (result != ZERR_NONE) { 
        krb5_free_keyblock(Z_krb5_ctx, keyblock);
        krb5_auth_con_free(Z_krb5_ctx, authctx);
        krb5_free_authenticator(Z_krb5_ctx, KRB5AUTHENT);
        free(asn1_data); 
        free(cksumbuf.data); 
        return ZAUTH_FAILED; 
    } 
    /* HOLDING: asn1_data, cksumbuf.data, authctx, authenticator */ 

    valid = Z_krb5_verify_cksum(keyblock, &cksumbuf, cksumtype, asn1_data, asn1_len);

    free(asn1_data); 
    krb5_auth_con_free(Z_krb5_ctx, authctx);
    krb5_free_authenticator(Z_krb5_ctx, KRB5AUTHENT);
    krb5_free_keyblock(Z_krb5_ctx, keyblock);
    free(cksumbuf.data); 
    
    if (valid) 
        return (ZAUTH_YES); 
    else 
        return (ZAUTH_FAILED); 
#else
    return (notice->z_auth) ? ZAUTH_YES : ZAUTH_NO;
#endif
}

#undef KRB5AUTHENT

#if defined(HAVE_KRB4) && defined(HAVE_KRB5)
static Code_t
ZCheckAuthentication4(ZNotice_t *notice,
		      struct sockaddr_in *from)
{	
    int result;
    char srcprincipal[ANAME_SZ+INST_SZ+REALM_SZ+4];
    KTEXT_ST authent;
    AUTH_DAT dat;
    ZChecksum_t checksum;
    char instance[INST_SZ+1];

    if (!notice->z_auth)
	return ZAUTH_NO;

    /* Check for bogus authentication data length. */
    if (notice->z_authent_len <= 0)
	return ZAUTH_FAILED;

    /* Read in the authentication data. */
    if (ZReadAscii(notice->z_ascii_authent, 
		   strlen(notice->z_ascii_authent)+1, 
		   (unsigned char *)authent.dat, 
		   notice->z_authent_len) == ZERR_BADFIELD) {
	return ZAUTH_FAILED;
    }
    authent.length = notice->z_authent_len;

    strcpy(instance, SERVER_INSTANCE);

    /* We don't have the session key cached; do it the long way. */
    result = krb_rd_req(&authent, SERVER_SERVICE, instance,
			from->sin_addr.s_addr, &dat, srvtab_file);
    if (result == RD_AP_OK) {
	ZSetSessionDES(&dat.session);
	sprintf(srcprincipal, "%s%s%s@%s", dat.pname, dat.pinst[0] ? "." : "",
		dat.pinst, dat.prealm);
	if (strcmp(srcprincipal, notice->z_sender))
	    return ZAUTH_FAILED;
    } else {
	return ZAUTH_FAILED;	/* didn't decode correctly */
    }

    /* Check the cryptographic checksum. */
    checksum = compute_checksum(notice, dat.session);

    if (checksum != notice->z_checksum)
	return ZAUTH_FAILED;

    return ZAUTH_YES;
}
#endif


#if defined(HAVE_KRB4) && defined(HAVE_KRB5)
static ZChecksum_t
compute_checksum(ZNotice_t *notice,
		 C_Block session_key)
{
    ZChecksum_t checksum;
    char *cstart, *cend, *hstart = notice->z_packet, *hend = notice->z_message;

    cstart = notice->z_default_format + strlen(notice->z_default_format) + 1;
    cend = cstart + strlen(cstart) + 1;
    checksum = des_quad_cksum((unsigned char *)hstart, NULL, cstart - hstart, 0, (C_Block *)session_key);
    checksum ^= des_quad_cksum((unsigned char *)cend, NULL, hend - cend, 0, (C_Block *)session_key);
    checksum ^= des_quad_cksum((unsigned char *)notice->z_message, NULL, notice->z_message_len,
			       0, (C_Block *)session_key);
    return checksum;
}
#endif

#ifdef HAVE_KRB5
static ZChecksum_t compute_rlm_checksum(ZNotice_t *notice,
					unsigned char *session_key)
{
    ZChecksum_t checksum;
    char *cstart, *cend, *hstart = notice->z_packet;

    cstart = notice->z_default_format + strlen(notice->z_default_format) + 1;
    cend = cstart + strlen(cstart) + 1;
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
	;
}
#endif
#ifdef HAVE_KRB4
void
ZSetSessionDES(C_Block *key) {
#ifdef HAVE_KRB5
     Code_t result;
     if (__Zephyr_keyblock) {
          krb5_free_keyblock(Z_krb5_ctx, __Zephyr_keyblock);
          __Zephyr_keyblock=NULL;
     }
     result = Z_krb5_init_keyblock(Z_krb5_ctx, ENCTYPE_DES_CBC_CRC, 
                                 sizeof(C_Block),
                                 &__Zephyr_keyblock);
     if (result) /*XXX we're out of memory? */
	return;

     memcpy(Z_keydata(__Zephyr_keyblock), key, sizeof(C_Block));
#else
    memcpy(__Zephyr_session, key, sizeof(C_Block));
#endif
}
#endif
