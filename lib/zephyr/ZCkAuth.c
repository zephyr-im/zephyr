/* This file is part of the Project Athena Zephyr Notification System.
 * It contains source for the ZCheckAuthentication function.
 *
 *	Created by:	Robert French
 *
 *	$Source$
 *	$Author$
 *
 *	Copyright (c) 1987 by the Massachusetts Institute of Technology.
 *	For copying and distribution information, see the file
 *	"mit-copyright.h". 
 */
/* $Header$ */

#ifndef lint
static char rcsid_ZCheckAuthentication_c[] = "$Header$";
#endif lint

#include <zephyr/mit-copyright.h>

#include <zephyr/zephyr_internal.h>

/* Check authentication of the notice.
   If it looks authentic but fails the Kerberos check, return -1.
   If it looks authentic and passes the Kerberos check, return 1.
   If it doesn't look authentic, return 0
  
   When not using Kerberos, return (looks-authentic-p)
 */
int ZCheckAuthentication(notice, from)
    ZNotice_t *notice;
    struct sockaddr_in *from;
{	
#ifdef KERBEROS
    int result;
    char srcprincipal[ANAME_SZ+INST_SZ+REALM_SZ+4];
    KTEXT_ST authent;
    AUTH_DAT dat;
    ZChecksum_t our_checksum;
    CREDENTIALS cred;

    if (!notice->z_auth)
	return (ZAUTH_NO);
	
    if (__Zephyr_server) {
	if (notice->z_authent_len <= 0)	/* bogus length */
	    return(ZAUTH_FAILED);
	if (ZReadAscii(notice->z_ascii_authent, 
		       strlen(notice->z_ascii_authent)+1, 
		       (unsigned char *)authent.dat, 
		       notice->z_authent_len) == ZERR_BADFIELD) {
	    return (ZAUTH_FAILED);
	}
	authent.length = notice->z_authent_len;
	result = krb_rd_req(&authent, SERVER_SERVICE, 
			    SERVER_INSTANCE, from->sin_addr.s_addr, 
			    &dat, SERVER_SRVTAB);
	if (result == RD_AP_OK) {
		bcopy((char *)dat.session, (char *)__Zephyr_session, 
		      sizeof(C_Block));
		(void) sprintf(srcprincipal, "%s%s%s@%s", dat.pname, 
			       dat.pinst[0]?".":"", dat.pinst, dat.prealm);
		if (strcmp(srcprincipal, notice->z_sender))
			return (ZAUTH_FAILED);
		return(ZAUTH_YES);
	} else
		return (ZAUTH_FAILED);	/* didn't decode correctly */
    }

    if (result = krb_get_cred(SERVER_SERVICE, SERVER_INSTANCE, 
			      __Zephyr_realm, &cred))
	return (ZAUTH_NO);

    our_checksum = (ZChecksum_t)quad_cksum(notice->z_packet, NULL, 
					   notice->z_default_format+
					   strlen(notice->z_default_format)+1-
					   notice->z_packet, 0, cred.session);

    /* if mismatched checksum, then the packet was corrupted */
    return ((our_checksum == notice->z_checksum) ? ZAUTH_YES : ZAUTH_FAILED);

#else
    return (notice->z_auth ? ZAUTH_YES : ZAUTH_NO);
#endif
} 
