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
 *	$Id$
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

static int hash_ticket __P((unsigned char *, int));
static void add_session_key __P((KTEXT, C_Block, char *, time_t));
static int find_session_key __P((KTEXT, C_Block, char *));
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
    char krb_realm[REALM_SZ];
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
#ifdef HAVE_KRB4
    int result;
    char rlmprincipal[ANAME_SZ+INST_SZ+REALM_SZ+4];
    char srcprincipal[ANAME_SZ+INST_SZ+REALM_SZ+4];
    KTEXT_ST authent, ticket;
    AUTH_DAT dat;
    ZChecksum_t checksum;
    CREDENTIALS cred;
    C_Block session_key;

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

    /* Copy the ticket out of the authentication data. */
    if (krb_find_ticket(&authent, &ticket) != RD_AP_OK)
        return ZAUTH_FAILED;

    (void) sprintf(rlmprincipal, "%s.%s@%s", SERVER_SERVICE,
                   SERVER_INSTANCE, realm);

    /* Try to do a fast check against the cryptographic checksum. */
    if (find_session_key(&ticket, session_key, srcprincipal) >= 0) {
        if (strcmp(srcprincipal, rlmprincipal) != 0)
            return ZAUTH_FAILED;
        if (notice->z_time.tv_sec - NOW > CLOCK_SKEW)
            return ZAUTH_FAILED;
        checksum = compute_rlm_checksum(notice, session_key);

        /* If checksum matches, packet is authentic.  If not, we might
	 * have an outdated session key, so keep going the slow way.
	 */
        if (checksum == notice->z_checksum) {
	    memcpy(__Zephyr_session, session_key, sizeof(C_Block));
	    return ZAUTH_YES;
        }
    }

    /* We don't have the session key cached; do it the long way. */
    result = krb_rd_req(&authent, SERVER_SERVICE, SERVER_INSTANCE,
                        from->sin_addr.s_addr, &dat, srvtab_file);
    if (result == RD_AP_OK) {
        sprintf(srcprincipal, "%s%s%s@%s", dat.pname, dat.pinst[0] ? "." : "",
		dat.pinst, dat.prealm);
        if (strcmp(rlmprincipal, srcprincipal))
            return ZAUTH_FAILED;
    } else {
        return ZAUTH_FAILED;    /* didn't decode correctly */
    }

    /* Check the cryptographic checksum. */
#ifdef NOENCRYPTION
    our_checksum = 0;
#else
    checksum = compute_rlm_checksum(notice, dat.session);
#endif
    if (checksum != notice->z_checksum)
        return ZAUTH_FAILED;

    /* Record the session key, expiry time, and source principal in the
     * hash table, so we can do a fast check next time. */
    add_session_key(&ticket, dat.session, srcprincipal,
                    (time_t)(dat.time_sec + dat.life * 5 * 60));

    return ZAUTH_YES;

#else /* !HAVE_KRB4 */
    return (notice->z_auth) ? ZAUTH_YES : ZAUTH_NO;
#endif
}

Code_t
ZCheckAuthentication(notice, from)
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

    /* Copy the ticket out of the authentication data. */
    if (krb_find_ticket(&authent, &ticket) != RD_AP_OK)
	return ZAUTH_FAILED;

    /* Try to do a fast check against the cryptographic checksum. */
    if (find_session_key(&ticket, session_key, srcprincipal) >= 0) {
	if (strcmp(srcprincipal, notice->z_sender) != 0)
	    return ZAUTH_FAILED;
	if (notice->z_time.tv_sec - NOW > CLOCK_SKEW)
	    return ZAUTH_FAILED;
	checksum = compute_checksum(notice, session_key);

        /* If checksum matches, packet is authentic.  If not, we might
	 * have an outdated session key, so keep going the slow way.
	 */
	if (checksum == notice->z_checksum) {
	    memcpy(__Zephyr_session, session_key, sizeof(C_Block));
	    return ZAUTH_YES;
	}
    }

    /* We don't have the session key cached; do it the long way. */
    result = krb_rd_req(&authent, SERVER_SERVICE, SERVER_INSTANCE,
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
    our_checksum = 0;
#else
    checksum = compute_checksum(notice, dat.session);
#endif
    if (checksum != notice->z_checksum)
	return ZAUTH_FAILED;

    /* Record the session key, expiry time, and source principal in the
     * hash table, so we can do a fast check next time. */
    add_session_key(&ticket, dat.session, srcprincipal,
		    (time_t)(dat.time_sec + dat.life * 5 * 60));

    return ZAUTH_YES;

#else /* !HAVE_KRB4 */
    return (notice->z_auth) ? ZAUTH_YES : ZAUTH_NO;
#endif
}

#ifdef HAVE_KRB4

static int hash_ticket(p, len)
    unsigned char *p;
    int len;
{
    unsigned long hashval = 0, g;

    for (; len > 0; p++, len--) {
	hashval = (hashval << 4) + *p;
	g = hashval & 0xf0000000;
	if (g) {
	    hashval ^= g >> 24;
	    hashval ^= g;
	}
    }
    return hashval % HASHTAB_SIZE;
}

static void add_session_key(ticket, session_key, srcprincipal, expires)
    KTEXT ticket;
    C_Block session_key;
    char *srcprincipal;
    time_t expires;
{
    Hash_entry *entry;
    int hashval;

    /* If we can't allocate memory for the hash table entry, just forget
     * about it. */
    entry = (Hash_entry *) malloc(sizeof(Hash_entry) - 1 + ticket->length);
    if (!entry)
	return;

    /* Initialize the new entry. */
    memcpy(entry->session_key, session_key, sizeof(entry->session_key));
    strcpy(entry->srcprincipal, srcprincipal);
    entry->expires = expires;
    entry->ticket_len = ticket->length;
    memcpy(entry->ticket, ticket->dat, ticket->length * sizeof(unsigned char));

    /* Insert the new entry in the hash table. */
    hashval = hash_ticket(ticket->dat, ticket->length);
    entry->next = hashtab[hashval];
    hashtab[hashval] = entry;
}

static int find_session_key(ticket, key, srcprincipal)
    KTEXT ticket;
    C_Block key;
    char *srcprincipal;
{
    unsigned char *dat;
    int hashval, len;
    Hash_entry *entry;

    dat = ticket->dat;
    len = ticket->length;
    hashval = hash_ticket(dat, len);

    for (entry = hashtab[hashval]; entry; entry = entry->next) {
	if (entry->ticket_len == len && memcmp(entry->ticket, dat, len) == 0) {
	    memcpy(key, entry->session_key, sizeof(entry->session_key));
	    strcpy(srcprincipal, entry->srcprincipal);
	    return 0;
	}
    }
    return -1;
}

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

