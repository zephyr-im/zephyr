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

int ZCheckAuthentication(notice,buffer,from)
	ZNotice_t	*notice;
	ZPacket_t	buffer;
	struct		sockaddr_in *from;
{	
	int result;
	char srcprincipal[ANAME_SZ+INST_SZ+REALM_SZ+4];
	KTEXT_ST authent;
	AUTH_DAT dat;
	ZChecksum_t our_checksum;
	CREDENTIALS cred;

	if (!notice->z_auth)
		return (0);
	
	if (__Zephyr_server) {
		if (ZReadAscii(notice->z_ascii_authent,
			       strlen(notice->z_ascii_authent)+1,
			       (char *)authent.dat,
			       notice->z_authent_len) == ZERR_BADFIELD) {
			return (0);
		}
		authent.length = notice->z_authent_len;
		result = rd_ap_req(&authent,SERVER_SERVICE,
				   SERVER_INSTANCE,from->sin_addr.s_addr,
				   &dat,SERVER_SRVTAB);
		bcopy((char *)dat.session,(char *)__Zephyr_session,
		      sizeof(C_Block));
		(void) sprintf(srcprincipal,"%s%s%s@%s",dat.pname,
			       dat.pinst[0]?".":"",dat.pinst,dat.prealm);
		if (strcmp(srcprincipal,notice->z_sender))
			return (0);
		return (result == RD_AP_OK);
	}

	if (result = get_credentials(SERVER_SERVICE,SERVER_INSTANCE,
				     __Zephyr_realm,&cred))
		return (result+krb_err_base);

	our_checksum = (ZChecksum_t)quad_cksum(buffer,NULL,
					       notice->z_recipient+
					       strlen(notice->z_recipient)+1-
					       buffer,0,cred.session);

	return (our_checksum == notice->z_checksum);
} 
