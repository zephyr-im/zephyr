/*
 * $Source$
 * $Author$
 *
 * Copyright 1985, 1986, 1987, 1988, 1990, 1991 by the Massachusetts
 * Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <mit-copyright.h>.
 */

/*
 * This includes code taken from:
 * Kerberos: rd_req.c,v 4.16 89/03/22 14:52:06 jtkohl Exp
 * Kerberos: prot.h,v 4.13 89/01/24 14:27:22 jtkohl Exp
 * Kerberos: krb_conf.h,v 4.0 89/01/23 09:59:27 jtkohl Exp
 */

#ifndef lint
#ifndef SABER
static char *rcsid_rd_req_c =
    "$Id$";
#endif /* lint */
#endif /* SABER */

#ifdef KERBEROS
#ifndef NOENCRYPTION

#include <zephyr/mit-copyright.h>
#include <stdio.h>
#include <krb.h>

/* Byte ordering */
extern int krbONE;
#define		HOST_BYTE_ORDER	(* (char *) &krbONE)

#define		KRB_PROT_VERSION 	4

/* Message types , always leave lsb for byte order */

#define		AUTH_MSG_KDC_REQUEST			 1<<1
#define 	AUTH_MSG_KDC_REPLY			 2<<1
#define		AUTH_MSG_APPL_REQUEST			 3<<1
#define		AUTH_MSG_APPL_REQUEST_MUTUAL		 4<<1
#define		AUTH_MSG_ERR_REPLY			 5<<1
#define		AUTH_MSG_PRIVATE			 6<<1
#define		AUTH_MSG_SAFE				 7<<1
#define		AUTH_MSG_APPL_ERR			 8<<1
#define 	AUTH_MSG_DIE				63<<1

/* values for kerb error codes */

#define		KERB_ERR_OK				 0
#define		KERB_ERR_NAME_EXP			 1
#define		KERB_ERR_SERVICE_EXP			 2
#define		KERB_ERR_AUTH_EXP			 3
#define		KERB_ERR_PKT_VER			 4
#define		KERB_ERR_NAME_MAST_KEY_VER		 5
#define		KERB_ERR_SERV_MAST_KEY_VER		 6
#define		KERB_ERR_BYTE_ORDER			 7
#define		KERB_ERR_PRINCIPAL_UNKNOWN		 8
#define		KERB_ERR_PRINCIPAL_NOT_UNIQUE		 9
#define		KERB_ERR_NULL_KEY			10

#include <sys/time.h>
#include <strings.h>

extern int krb_ap_req_debug;

/*
 * Keep the following information around for subsequent calls
 * to this routine by the same server using the same key.
 */

/* Kerberos shouldn't stick us with array types... */
typedef struct {
    des_key_schedule s;
} Sched;

static Sched serv_key;	/* Key sched to decrypt ticket */
static des_cblock ky;		/* Initialization vector */
static int st_kvno;		/* version number for this key */
static char st_rlm[REALM_SZ];	/* server's realm */
static char st_nam[ANAME_SZ];	/* service name */
static char st_inst[INST_SZ];	/* server's instance */

/*
 * Cache of key schedules
 */
#define HASH_SIZE_1	255	/* not a power of 2 */
#define HASH_SIZE_2	3
static unsigned long last_use;
typedef struct {
    unsigned long last_time_used;
    des_cblock key;
    Sched schedule;
} KeySchedRec;
static KeySchedRec scheds[HASH_SIZE_1][HASH_SIZE_2];

#ifdef __STDC__
static Sched* check_key_sched_cache (des_cblock key)
#else
static Sched* check_key_sched_cache (key)
     des_cblock key;
#endif
{
    unsigned int hash_value = key[0] + key[1] * 256;
    KeySchedRec *rec = scheds[hash_value % HASH_SIZE_1];
    int i;

    for (i = HASH_SIZE_2 - 1; i >= 0; i--)
	if (rec[i].last_time_used
	    && key[0] == rec[i].key[0]
	    && !bcmp (key, rec[i].key, sizeof (des_cblock))) {
	    rec[i].last_time_used = last_use++;
	    return &rec[i].schedule;
	}
    return 0;
}

#ifdef __STDC__
static void add_to_key_sched_cache (des_cblock key, Sched* sched)
#else
static void add_to_key_sched_cache (key, sched)
     des_cblock key;
     Sched* sched;
#endif
{
    unsigned int hash_value = key[0] + key[1] * 256;
    KeySchedRec *rec = scheds[hash_value % HASH_SIZE_1];
    int i, oldest = HASH_SIZE_2 - 1;

    for (i = HASH_SIZE_2 - 1; i >= 0; i--) {
	if (rec[i].last_time_used == 0) {
	    oldest = i;
	    break;
	}
	if (rec[i].last_time_used < rec[oldest].last_time_used)
	    oldest = i;
    }
    bcopy (key, rec[oldest].key, sizeof (des_cblock));
    rec[oldest].schedule = *sched;
    rec[oldest].last_time_used = last_use++;
}

/*
 * This file contains two functions.  krb_set_key() takes a DES
 * key or password string and returns a DES key (either the original
 * key, or the password converted into a DES key) and a key schedule
 * for it.
 *
 * krb_rd_req() reads an authentication request and returns information
 * about the identity of the requestor, or an indication that the
 * identity information was not authentic.
 */

/*
 * krb_set_key() takes as its first argument either a DES key or a
 * password string.  The "cvt" argument indicates how the first
 * argument "key" is to be interpreted: if "cvt" is null, "key" is
 * taken to be a DES key; if "cvt" is non-null, "key" is taken to
 * be a password string, and is converted into a DES key using
 * string_to_key().  In either case, the resulting key is returned
 * in the external static variable "ky".  A key schedule is
 * generated for "ky" and returned in the external static variable
 * "serv_key".
 *
 * This routine returns the return value of des_key_sched.
 *
 * krb_set_key() needs to be in the same .o file as krb_rd_req() so that
 * the key set by krb_set_key() is available in private storage for
 * krb_rd_req().
 */

int
krb_set_key(key,cvt)
    char *key;
    int cvt;
{
#ifdef NOENCRYPTION
    bzero(ky, sizeof(ky));
    return KSUCCESS;
#else /* Encrypt */
    Sched *s;
    int ret;

    if (cvt)
	string_to_key(key,ky);
    else
	bcopy(key,(char *)ky,8);

    s = check_key_sched_cache (ky);
    if (s) {
	serv_key = *s;
	return 0;
    }
    ret = des_key_sched (ky, serv_key.s);
    add_to_key_sched_cache (ky, &serv_key);
    return ret;
#endif /* NOENCRYPTION */
}


/*
 * krb_rd_req() takes an AUTH_MSG_APPL_REQUEST or
 * AUTH_MSG_APPL_REQUEST_MUTUAL message created by krb_mk_req(),
 * checks its integrity and returns a judgement as to the requestor's
 * identity.
 *
 * The "authent" argument is a pointer to the received message.
 * The "service" and "instance" arguments name the receiving server,
 * and are used to get the service's ticket to decrypt the ticket
 * in the message, and to compare against the server name inside the
 * ticket.  "from_addr" is the network address of the host from which
 * the message was received; this is checked against the network
 * address in the ticket.  If "from_addr" is zero, the check is not
 * performed.  "ad" is an AUTH_DAT structure which is
 * filled in with information about the sender's identity according
 * to the authenticator and ticket sent in the message.  Finally,
 * "fn" contains the name of the file containing the server's key.
 * (If "fn" is NULL, the server's key is assumed to have been set
 * by krb_set_key().  If "fn" is the null string ("") the default
 * file KEYFILE, defined in "krb.h", is used.)
 *
 * krb_rd_req() returns RD_AP_OK if the authentication information
 * was genuine, or one of the following error codes (defined in
 * "krb.h"):
 *
 *	RD_AP_VERSION		- wrong protocol version number
 *	RD_AP_MSG_TYPE		- wrong message type
 *	RD_AP_UNDEC		- couldn't decipher the message
 *	RD_AP_INCON		- inconsistencies found
 *	RD_AP_BADD		- wrong network address
 *	RD_AP_TIME		- client time (in authenticator)
 *				  too far off server time
 *	RD_AP_NYV		- Kerberos time (in ticket) too
 *				  far off server time
 *	RD_AP_EXP		- ticket expired
 *
 * For the message format, see krb_mk_req().
 *
 * Mutual authentication is not implemented.
 */

krb_rd_req(authent,service,instance,from_addr,ad,fn)
    register KTEXT authent;	/* The received message */
    char *service;		/* Service name */
    char *instance;		/* Service instance */
    long from_addr;		/* Net address of originating host */
    AUTH_DAT *ad;		/* Structure to be filled in */
    char *fn;			/* Filename to get keys from */
{
    KTEXT_ST ticket;     /* Temp storage for ticket */
    KTEXT tkt = &ticket;
    KTEXT_ST req_id_st;  /* Temp storage for authenticator */
    register KTEXT req_id = &req_id_st;

    struct timeval t_local;

    char realm[REALM_SZ];	/* Realm of issuing kerberos */
    Sched seskey_sched, *sched;	/* Key sched for session key */
    unsigned char skey[KKEY_SZ]; /* Session key from ticket */
    char sname[SNAME_SZ];	/* Service name from ticket */
    char iname[INST_SZ];	/* Instance name from ticket */
    char r_aname[ANAME_SZ];	/* Client name from authenticator */
    char r_inst[INST_SZ];	/* Client instance from authenticator */
    char r_realm[REALM_SZ];	/* Client realm from authenticator */
    unsigned int r_time_ms;     /* Fine time from authenticator */
    unsigned long r_time_sec;   /* Coarse time from authenticator */
    register char *ptr;		/* For stepping through */
    unsigned long delta_t;      /* Time in authenticator - local time */
    long tkt_age;		/* Age of ticket */
    int swap_bytes;		/* Need to swap bytes? */
    int mutual;			/* Mutual authentication requested? */
    unsigned char s_kvno;	/* Version number of the server's key
				 * Kerberos used to encrypt ticket */
    int status;

    if (authent->length <= 0)
	return(RD_AP_MODIFIED);

    ptr = (char *) authent->dat;

    /* get msg version, type and byte order, and server key version */

    /* check version */
    if (KRB_PROT_VERSION != (unsigned int) *ptr++)
        return(RD_AP_VERSION);

    /* byte order */
    swap_bytes = 0;
    if ((*ptr & 1) != HOST_BYTE_ORDER)
        swap_bytes++;

    /* check msg type */
    mutual = 0;
    switch (*ptr++ & ~1) {
    case AUTH_MSG_APPL_REQUEST:
        break;
    case AUTH_MSG_APPL_REQUEST_MUTUAL:
        mutual++;
        break;
    default:
        return(RD_AP_MSG_TYPE);
    }

#ifdef lint
    /* XXX mutual is set but not used; why??? */
    /* this is a crock to get lint to shut up */
    if (mutual)
        mutual = 0;
#endif /* lint */
    s_kvno = *ptr++;		/* get server key version */
    (void) strcpy(realm,ptr);   /* And the realm of the issuing KDC */
    ptr += strlen(ptr) + 1;     /* skip the realm "hint" */

    /*
     * If "fn" is NULL, key info should already be set; don't
     * bother with ticket file.  Otherwise, check to see if we
     * already have key info for the given server and key version
     * (saved in the static st_* variables).  If not, go get it
     * from the ticket file.  If "fn" is the null string, use the
     * default ticket file.
     */
    if (fn && (strcmp(st_nam,service) || strcmp(st_inst,instance) ||
               strcmp(st_rlm,realm) || (st_kvno != s_kvno))) {
        if (*fn == 0) fn = KEYFILE;
        st_kvno = s_kvno;
#ifndef NOENCRYPTION
        if (read_service_key(service,instance,realm,(int) s_kvno,
                            fn,(char *)skey))
            return(RD_AP_UNDEC);
        if ((status = krb_set_key((char *)skey,0)) != 0)
	    return(status);
#endif /* !NOENCRYPTION */
        (void) strcpy(st_rlm,realm);
        (void) strcpy(st_nam,service);
        (void) strcpy(st_inst,instance);
    }

    /* Get ticket from authenticator */
    tkt->length = (int) *ptr++;
    if ((tkt->length + (ptr+1 - (char *) authent->dat)) > authent->length)
	return(RD_AP_MODIFIED);
    bcopy(ptr+1,(char *)(tkt->dat),tkt->length);

    if (krb_ap_req_debug)
        log("ticket->length: %d",tkt->length);

#ifndef NOENCRYPTION
    /* Decrypt and take apart ticket */
#endif

    if (decomp_ticket(tkt,&ad->k_flags,ad->pname,ad->pinst,ad->prealm,
                      &(ad->address),ad->session, &(ad->life),
                      &(ad->time_sec),sname,iname,ky,serv_key.s))
        return(RD_AP_UNDEC);

    if (krb_ap_req_debug) {
        log("Ticket Contents.");
        log(" Aname:   %s.%s",ad->pname,
            ((int)*(ad->prealm) ? ad->prealm : "Athena"));
        log(" Service: %s%s%s",sname,((int)*iname ? "." : ""),iname);
    }

    /* Extract the authenticator */
    req_id->length = (int) *(ptr++);
    if ((req_id->length + (ptr + tkt->length - (char *) authent->dat)) >
	authent->length)
	return(RD_AP_MODIFIED);
    bcopy(ptr + tkt->length, (char *)(req_id->dat),req_id->length);

#ifndef NOENCRYPTION
    /* And decrypt it with the session key from the ticket */
    if (krb_ap_req_debug) log("About to decrypt authenticator");
    sched = check_key_sched_cache (ad->session);
    if (!sched) {
	sched = &seskey_sched;
	key_sched (ad->session, seskey_sched.s);
	add_to_key_sched_cache (ad->session, &seskey_sched);
    }
    /* can't do much to optimize this... */
    pcbc_encrypt((C_Block *)req_id->dat,(C_Block *)req_id->dat,
		 (long) req_id->length, sched->s, ad->session,DES_DECRYPT);
    if (krb_ap_req_debug) log("Done.");
#endif /* NOENCRYPTION */

#define check_ptr() if ((ptr - (char *) req_id->dat) > req_id->length) return(RD_AP_MODIFIED);

    ptr = (char *) req_id->dat;
    (void) strcpy(r_aname,ptr);	/* Authentication name */
    ptr += strlen(r_aname)+1;
    check_ptr();
    (void) strcpy(r_inst,ptr);	/* Authentication instance */
    ptr += strlen(r_inst)+1;
    check_ptr();
    (void) strcpy(r_realm,ptr);	/* Authentication name */
    ptr += strlen(r_realm)+1;
    check_ptr();
    bcopy(ptr,(char *)&ad->checksum,4);	/* Checksum */
    ptr += 4;
    check_ptr();
    if (swap_bytes) swap_u_long(ad->checksum);
    r_time_ms = *(ptr++);	/* Time (fine) */
#ifdef lint
    /* XXX r_time_ms is set but not used.  why??? */
    /* this is a crock to get lint to shut up */
    if (r_time_ms)
        r_time_ms = 0;
#endif /* lint */
    check_ptr();
    /* assume sizeof(r_time_sec) == 4 ?? */
    bcopy(ptr,(char *)&r_time_sec,4); /* Time (coarse) */
    if (swap_bytes) swap_u_long(r_time_sec);

    /* Check for authenticity of the request */
    if (krb_ap_req_debug)
        log("Pname:   %s %s",ad->pname,r_aname);
    if (strcmp(ad->pname,r_aname) != 0)
        return(RD_AP_INCON);
    if (strcmp(ad->pinst,r_inst) != 0)
        return(RD_AP_INCON);
    if (krb_ap_req_debug)
        log("Realm:   %s %s",ad->prealm,r_realm);
    if ((strcmp(ad->prealm,r_realm) != 0))
        return(RD_AP_INCON);

    if (krb_ap_req_debug)
        log("Address: %d %d",ad->address,from_addr);
    if (from_addr && (ad->address != from_addr))
        return(RD_AP_BADD);

    (void) gettimeofday(&t_local,(struct timezone *) 0);
    delta_t = abs((int)(t_local.tv_sec - r_time_sec));
    if (delta_t > CLOCK_SKEW) {
        if (krb_ap_req_debug)
            log("Time out of range: %d - %d = %d",
                t_local.tv_sec,r_time_sec,delta_t);
        return(RD_AP_TIME);
    }

    /* Now check for expiration of ticket */

    tkt_age = t_local.tv_sec - ad->time_sec;
    if (krb_ap_req_debug)
        log("Time: %d Issue Date: %d Diff: %d Life %x",
            t_local.tv_sec,ad->time_sec,tkt_age,ad->life);

    if (t_local.tv_sec < ad->time_sec) {
        if ((ad->time_sec - t_local.tv_sec) > CLOCK_SKEW)
            return(RD_AP_NYV);
    }
    else if ((t_local.tv_sec - ad->time_sec) > 5 * 60 * ad->life)
        return(RD_AP_EXP);

    /* All seems OK */
    ad->reply.length = 0;

    return(RD_AP_OK);
}
#endif /* NOENCRYPTION */

static char local_realm_buffer[REALM_SZ+1];

krb_get_lrealm(r,n)
    char *r;
    int n;
{
    FILE *cnffile, *fopen();

    if (n > 1)
	return(KFAILURE);  /* Temporary restriction */

    if (local_realm_buffer[0]) {
	strcpy (r, local_realm_buffer);
	return KSUCCESS;
    }
    
    if ((cnffile = fopen(KRB_CONF, "r")) == NULL) {
	if (n == 1) {
	    (void) strcpy(r, KRB_REALM);
	    return(KSUCCESS);
	}
	else
	    return(KFAILURE);
    }

    if (fscanf(cnffile,"%s",r) != 1) {
        (void) fclose(cnffile);
        return(KFAILURE);
    }
    (void) fclose(cnffile);
    return(KSUCCESS);
}

#endif /* KERBEROS */

#ifdef ibm032

#if defined (__GNUC__) || defined (__HIGHC__)
#ifdef __HIGHC__
#define asm _ASM
#endif

/*
 * Copyright (C) 1990 by the Massachusetts Institute of Technology
 *
 * Permission to use, copy, modify, and distribute this software and its
 * documentation for any purpose and without fee is hereby granted.
 */

void asm_wrapper_kopt_c () {
    /*
     * Multiply routine.  The C library routine tries to optimize around
     * the multiply-step instruction, which was slower in earlier versions
     * of the processor; this is no longer useful.  Derived from assembly
     * code written by John Carr.
     */
    
    /* data section */
    asm(".data\n.align 2");
    asm(".globl _ulmul$$ \n _ulmul$$:");
    asm(".globl _lmul$$  \n _lmul$$: .long lmul$$");
    /* text section */
    asm(".text \n .align 1");
    asm(".globl lmul$$    \n lmul$$:");
    asm(".globl ulmul$$   \n ulmul$$:");
    asm(".globl _.lmul$$  \n _.lmul$$:");
    asm(".globl _.ulmul$$ \n _.ulmul$$:");
    asm("   s r0,r0 \n mts r10,r2"); /* set up multiply, and go: */
    asm("   m r0,r3 \n m r0,r3 \n m r0,r3 \n m r0,r3"); /* execute 4 steps */
    asm("   m r0,r3 \n m r0,r3 \n m r0,r3 \n m r0,r3"); /* execute 4 steps */
    asm("   m r0,r3 \n m r0,r3 \n m r0,r3 \n m r0,r3"); /* execute 4 steps */
    asm("   m r0,r3 \n m r0,r3 \n m r0,r3 \n m r0,r3"); /* execute 4 steps */
    asm("   brx r15 \n mfs r10,r2"); /* return result */
    asm("   .long 0xdf02df00");	/* for debugging */
    
#ifdef USE_LIBC_STRLEN
  }
#else
    /* Note- do not use this version of strlen when compiling with -g; -g */
    /* causes extra no-ops to be inserted between instructions, which cause */
    /* the delayed branch instructions to fail. */

    /*
     * Fast strlen, with optional trapping of null pointers.  Also from
     * John Carr.
     */
    /* data */
    asm(".data\n.align 2");
    asm(".globl _strlen \n _strlen: .long _.strlen");
    /* text */
    asm(".text\n.align 1");
    asm(".globl _.strlen \n _.strlen:");
#if 1
    asm("	ti	2,r2,0"); /* trap if r2 is NULL */
#endif
    asm("	ls      r4,0(r2)");
    asm("	mr	r0,r2");
    asm("	nilz	r3,r2,3");
    asm("	beqx	0f");
    asm("	nilo	r2,r2,0xfffc");	/* clear low bits */
    asm("	sis	r3,2");	/* test appropriate bytes of 1st word */
    asm("	jeq	2f");	/* s & 3 == 2 */
    asm("	jm	1f");	/* s & 3 == 1 */
    asm("	j	3f");	/* s & 3 == 3 */
    asm("0:	srpi16	r4,8");	/* byte 0 */
    asm("	jeq	4f");
    asm("1:	niuz	r5,r4,0xff"); /* byte 1 */
    asm("	jeq	5f");
    asm("2:	nilz	r5,r4,0xff00");	/* byte 2 */
    asm("	jeq	6f");
    asm("3:	sli16	r4,8");	/* byte 3 */
    asm("	jeq	7f");
    asm("	ls	r4,4(r2)"); /* get next word and continue */
    asm("	bx	0b");
    asm("	inc	r2,4");
    asm("4:	brx	r15");	/* byte 0 is zero */
    asm("	s	r2,r0");
    asm("5:	s	r2,r0"); /* byte 1 is zero */
    asm("	brx	r15");
    asm("	inc	r2,1");
    asm("6:	s	r2,r0"); /* byte 2 is zero */
    asm("	brx	r15");
    asm("	inc	r2,2");
    asm("7:	s	r2,r0"); /* byte 3 is zero */
    asm("	brx	r15");
    asm("	inc	r2,3");
    asm("	.long	0xdf02df00"); /* trace table */
}
#endif /* USE_LIBC_STRLEN */
#endif /* __GNUC__ || __HIGHC__ */
#endif /* ibm032 */
