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

#ifdef HAVE_KRB4

/* Keep a hash table mapping tickets to session keys, so we can do a fast
 * check of the cryptographic checksum without doing and DES decryptions.
 * Also remember the expiry time of the ticket, so that we can sweep the
 * table periodically. */

#define HASHTAB_SIZE 4091

typedef struct hash_entry Hash_entry;

/* The ticket comes at the end, in a variable-length array. */
struct hash_entry {
    C_Block session_key;
    time_t expires;
    char srcprincipal[ANAME_SZ+INST_SZ+REALM_SZ+4];
    Hash_entry *next;
    int ticket_len;
    unsigned char ticket[1];
};

Hash_entry *hashtab[HASHTAB_SIZE];

static ZChecksum_t compute_checksum __P((ZNotice_t *, C_Block));
static ZChecksum_t compute_rlm_checksum __P((ZNotice_t *, C_Block));

/*
 * GetKerberosData
 *
 * get ticket from file descriptor and decode it.
 * Return KFAILURE if we barf on reading the ticket, else return
 * the value of rd_ap_req() applied to the ticket.
 */
int
GetKerberosData(fd, haddr, kdata, service, srvtab)
     int fd; /* file descr. to read from */
     struct in_addr haddr; /* address of foreign host on fd */
     AUTH_DAT *kdata;	/* kerberos data (returned) */
     char *service; /* service principal desired */
     char *srvtab; /* file to get keys from */
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

Code_t
SendKerberosData(fd, ticket, service, host)
     int fd;		/* file descriptor to write onto */
     KTEXT ticket;	/* where to put ticket (return) */
     char *service;	/* service name, foreign host */
     char *host;
{
    int rem;
    char p[32];
    int written;
    int size_to_write;

    rem = krb_mk_req(ticket, service, host, ZGetRealm(), (u_long) 0);
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

Code_t
ZCheckRealmAuthentication(notice, from, realm)
    ZNotice_t *notice;
    struct sockaddr_in *from;
    char *realm;
{       
#ifdef HAVE_KRB5
    char *authbuf;
    char rlmprincipal[ANAME_SZ+INST_SZ+REALM_SZ+4+1024];
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
#if HAVE_KRB5_C_MAKE_CHECKSUM 
    krb5_checksum checksum; 
    krb5_boolean valid; 
#else 
    krb5_crypto cryptctx; 
    Checksum checksum; 
    size_t xlen; 
#endif 
    char *cksum0_base, *cksum1_base, *cksum2_base; 
    char *svcinst, *x, *y; 
    char *asn1_data, *key_data; 
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
    authbuf=malloc(len);

    /* Read in the authentication data. */
    if (ZReadZcode(notice->z_ascii_authent, 
                   authbuf,
                   len, &len) == ZERR_BADFIELD) {
        return ZAUTH_FAILED;
    }

    (void) sprintf(rlmprincipal, "%s/%s@%s", SERVER_SERVICE,
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
	syslog(LOG_DEBUG, "k5 auth failed: %s", error_message(result));
      else
        syslog(LOG_WARNING,"k5 auth failed: %s", error_message(result));
        free(authbuf);
        krb5_auth_con_free(Z_krb5_ctx, authctx);
        return ZAUTH_FAILED;
    }

    /* HOLDING: authbuf, authctx */
#ifndef HAVE_KRB5_TICKET_ENC_PART2
    if (tkt == 0 || tkt->client == 0) {
       if (tkt) krb5_free_ticket(Z_krb5_ctx, tkt);
       free(authbuf);
       krb5_auth_con_free(Z_krb5_ctx, authctx);
       return ZAUTH_FAILED;
    }
    princ = tkt->client;
#else
    if (tkt == 0 || tkt->enc_part2 == 0) {
        if (tkt) krb5_free_ticket(Z_krb5_ctx, tkt);
        free(authbuf);
        krb5_auth_con_free(Z_krb5_ctx, authctx);
        return ZAUTH_FAILED;
    }
    princ = tkt->enc_part2->client;
#endif
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
#if HAVE_KRB5_CREDS_KEYBLOCK_ENCTYPE
    key_data = keyblock->contents; 
    key_len  = keyblock->length; 
    enctype  = keyblock->enctype; 
    result = Z_krb5_lookup_cksumtype(enctype, &cksumtype); 
    if (result) { 
        krb5_free_keyblock(Z_krb5_ctx, keyblock);
        krb5_auth_con_free(Z_krb5_ctx, authctx);
        krb5_free_authenticator(Z_krb5_ctx, KRB5AUTHENT);
        return (ZAUTH_FAILED); 
    } 
#else 
    key_data = keyblock->keyvalue.data; 
    key_len  = keyblock->keyvalue.length; 
    { 
       unsigned int len; 
       ENCTYPE *val; 
       int i = 0; 
 
       result  = krb5_keytype_to_enctypes(Z_krb5_ctx, keyblock->keytype, 
                                          &len, &val); 
       if (result) { 
	   krb5_free_keyblock(Z_krb5_ctx, keyblock);
           krb5_auth_con_free(Z_krb5_ctx, authctx); 
           krb5_free_authenticator(Z_krb5_ctx, KRB5AUTHENT); 
           return (ZAUTH_FAILED);  
       } 
 
       do { 
           if (i == len) break;
           result = Z_krb5_lookup_cksumtype(val[i], &cksumtype); 
           i++;
       } while (result != 0); 

       if (result) { 
	   krb5_free_keyblock(Z_krb5_ctx, keyblock);
           krb5_auth_con_free(Z_krb5_ctx, authctx); 
           krb5_free_authenticator(Z_krb5_ctx, KRB5AUTHENT); 
           return (ZAUTH_FAILED);  
       } 
       enctype = val[i-1]; 
    } 
#endif 
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
 
      our_checksum = des_quad_cksum(cksum0_base, NULL, cksum0_len, 0, 
                                    key_data); 
      if (our_checksum == notice->z_checksum) { 
	  krb5_free_keyblock(Z_krb5_ctx, keyblock);
          krb5_auth_con_free(Z_krb5_ctx, authctx);
          krb5_free_authenticator(Z_krb5_ctx, KRB5AUTHENT);
          return ZAUTH_YES; 
      } 
    } 

    /* HOLDING: authctx, authenticator */
 
    cksumbuf.length = cksum0_len + cksum1_len + cksum2_len; 
    cksumbuf.data = malloc(cksumbuf.length); 
    if (!cksumbuf.data) { 
        krb5_free_keyblock(Z_krb5_ctx, keyblock);
        krb5_auth_con_free(Z_krb5_ctx, authctx);
        krb5_free_authenticator(Z_krb5_ctx, KRB5AUTHENT);
        return ZAUTH_NO; 
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
    result = ZReadZcode(notice->z_ascii_checksum, 
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
 
#if HAVE_KRB5_C_MAKE_CHECKSUM 
    /* Verify the checksum -- MIT crypto API */ 
    memset(&checksum, 0, sizeof(checksum)); 
    checksum.length = asn1_len; 
    checksum.contents = asn1_data; 
    checksum.checksum_type = cksumtype;
    result = krb5_c_verify_checksum(Z_krb5_ctx, 
                                    keyblock, Z_KEYUSAGE_SRV_CKSUM, 
                                    &cksumbuf, &checksum, &valid); 
    free(asn1_data); 
    krb5_auth_con_free(Z_krb5_ctx, authctx);
    krb5_free_authenticator(Z_krb5_ctx, KRB5AUTHENT);
    krb5_free_keyblock(Z_krb5_ctx, keyblock);
    free(cksumbuf.data); 
    if (!result && valid) 
        return (ZAUTH_YES); 
    else 
        return (ZAUTH_FAILED); 
#else 
    /* Verify the checksum -- heimdal crypto API */ 
    checksum.checksum.length = asn1_len;
    checksum.checksum.data = asn1_data;
    checksum.cksumtype = cksumtype;

    /* HOLDING: authctx, authenticator, cksumbuf.data, asn1_data */

    result = krb5_crypto_init(Z_krb5_ctx, keyblock, enctype, &cryptctx); 
    if (result) { 
        krb5_auth_con_free(Z_krb5_ctx, authctx);
        krb5_free_authenticator(Z_krb5_ctx, KRB5AUTHENT);
	krb5_free_keyblock(Z_krb5_ctx, keyblock);
	free(asn1_data);
        free(cksumbuf.data); 
        return result; 
    } 
    /* HOLDING: authctx, authenticator, cryptctx, cksumbuf.data, checksum */ 
    result = krb5_verify_checksum(Z_krb5_ctx, cryptctx, 
                                  Z_KEYUSAGE_SRV_CKSUM, 
                                  cksumbuf.data, cksumbuf.length, 
                                  &checksum); 
    krb5_free_keyblock(Z_krb5_ctx, keyblock);
    krb5_crypto_destroy(Z_krb5_ctx, cryptctx); 
    krb5_auth_con_free(Z_krb5_ctx, authctx);
    krb5_free_authenticator(Z_krb5_ctx, KRB5AUTHENT);
    free(asn1_data);
    free(cksumbuf.data); 
    if (result) 
        return (ZAUTH_FAILED); 
    else 
        return (ZAUTH_YES); 
#endif
#else
    return (notice->z_auth) ? ZAUTH_YES : ZAUTH_NO;
#endif
}

Code_t
ZCheckAuthentication(notice, from)
    ZNotice_t *notice;
    struct sockaddr_in *from;
{       
#ifdef HAVE_KRB5
    char *authbuf;
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
    char *svcinst, *x, *y; 
    char *asn1_data, *key_data; 
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
    authbuf=malloc(len);

    /* Read in the authentication data. */
    if (ZReadZcode(notice->z_ascii_authent, 
                   authbuf,
                   len, &len) == ZERR_BADFIELD) {
        return ZAUTH_FAILED;
    }

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
	syslog(LOG_DEBUG, "k5 auth failed: %s", error_message(result));
      else
        syslog(LOG_WARNING,"k5 auth failed: %s", error_message(result));
        free(authbuf);
        krb5_auth_con_free(Z_krb5_ctx, authctx);
        return ZAUTH_FAILED;
    }

    /* HOLDING: authbuf, authctx, tkt */

    if (tkt == 0 || !Z_tktprincp(tkt)) {
       if (tkt) krb5_free_ticket(Z_krb5_ctx, tkt);
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

    memcpy(__Zephyr_session, key_data, sizeof(C_Block)); /* XXX */
 
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
 
      our_checksum = compute_checksum(notice, key_data);
      
      krb5_free_keyblock(Z_krb5_ctx, keyblock);
      krb5_auth_con_free(Z_krb5_ctx, authctx);
      krb5_free_authenticator(Z_krb5_ctx, KRB5AUTHENT);

      if (our_checksum == notice->z_checksum)
	return ZAUTH_YES; 
      else
	return ZAUTH_FAILED;
    } 

    /* HOLDING: authctx, authenticator */
 
    cksumbuf.length = cksum0_len + cksum1_len + cksum2_len; 
    cksumbuf.data = malloc(cksumbuf.length); 
    if (!cksumbuf.data) { 
        krb5_free_keyblock(Z_krb5_ctx, keyblock);
        krb5_auth_con_free(Z_krb5_ctx, authctx);
        krb5_free_authenticator(Z_krb5_ctx, KRB5AUTHENT);
        return ZAUTH_NO; 
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
    result = ZReadZcode(notice->z_ascii_checksum, 
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

Code_t
ZCheckAuthentication4(notice, from)
    ZNotice_t *notice;
    struct sockaddr_in *from;
{	
#ifdef HAVE_KRB4
    int result;
    char srcprincipal[ANAME_SZ+INST_SZ+REALM_SZ+4];
    KTEXT_ST authent, ticket;
    AUTH_DAT dat;
    ZChecksum_t checksum;
    C_Block session_key;
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
	memcpy(__Zephyr_session, dat.session, sizeof(C_Block));
	sprintf(srcprincipal, "%s%s%s@%s", dat.pname, dat.pinst[0] ? "." : "",
		dat.pinst, dat.prealm);
	if (strcmp(srcprincipal, notice->z_sender))
	    return ZAUTH_FAILED;
    } else {
	return ZAUTH_FAILED;	/* didn't decode correctly */
    }

    /* Check the cryptographic checksum. */
#ifdef NOENCRYPTION
    checksum = 0;
#else
    checksum = compute_checksum(notice, dat.session);
#endif
    if (checksum != notice->z_checksum)
	return ZAUTH_FAILED;

    return ZAUTH_YES;

#else /* !HAVE_KRB4 */
    return (notice->z_auth) ? ZAUTH_YES : ZAUTH_NO;
#endif
}


#ifdef HAVE_KRB4
static ZChecksum_t compute_checksum(notice, session_key)
    ZNotice_t *notice;
    C_Block session_key;
{
#ifdef NOENCRYPTION
    return 0;
#else
    ZChecksum_t checksum;
    char *cstart, *cend, *hstart = notice->z_packet, *hend = notice->z_message;

    cstart = notice->z_default_format + strlen(notice->z_default_format) + 1;
    cend = cstart + strlen(cstart) + 1;
    checksum = des_quad_cksum(hstart, NULL, cstart - hstart, 0, session_key);
    checksum ^= des_quad_cksum(cend, NULL, hend - cend, 0, session_key);
    checksum ^= des_quad_cksum(notice->z_message, NULL, notice->z_message_len,
			       0, session_key);
    return checksum;
#endif
}

static ZChecksum_t compute_rlm_checksum(notice, session_key)
    ZNotice_t *notice;
    C_Block session_key;
{
#ifdef NOENCRYPTION
    return 0;
#else
    ZChecksum_t checksum;
    char *cstart, *cend, *hstart = notice->z_packet, *hend = notice->z_message;

    cstart = notice->z_default_format + strlen(notice->z_default_format) + 1;
    cend = cstart + strlen(cstart) + 1;
    checksum = des_quad_cksum(hstart, NULL, cstart - hstart, 0, session_key);
    return checksum;
#endif
}

void sweep_ticket_hash_table(arg)
    void *arg;
{
    int i;
    Hash_entry **ptr, *entry;

    for (i = 0; i < HASHTAB_SIZE; i++) {
	ptr = &hashtab[i];
	while (*ptr) {
	    entry = *ptr;
	    if (entry->expires < NOW) {
		*ptr = entry->next;
		free(entry);
	    } else {
		ptr = &(*ptr)->next;
	    }
	}
    }
    timer_set_rel(SWEEP_INTERVAL, sweep_ticket_hash_table, NULL);
}

#endif /* HAVE_KRB4 */

