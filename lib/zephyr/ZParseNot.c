/* This file is part of the Project Athena Zephyr Notification System.
 * It contains source for the ZParseNotice function.
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

#include <zephyr/mit-copyright.h>

#include <zephyr/zephyr_internal.h>

Code_t ZParseNotice(buffer,len,notice,auth,from)
	ZPacket_t	buffer;
	int		len;
	ZNotice_t	*notice;
	int		*auth;
	struct		sockaddr_in *from;
{
	char *ptr,*cksum;
	int result;
	unsigned int temp[3];
	AUTH_DAT dat;
	KTEXT_ST authent;
	ZChecksum_t our_checksum;
	CREDENTIALS cred;
	
	ptr = buffer;
	
	if (ZReadAscii(ptr,temp,sizeof(int)) == ZERR_BADFIELD)
		return (ZERR_BADPKT);
	ptr += strlen(ptr)+1;
	
	if (*temp != ZVERSION)
		return (ZERR_VERS);

	if (ZReadAscii(ptr,temp,sizeof(int)) == ZERR_BADFIELD)
		return (ZERR_BADPKT);
	notice->z_kind = (ZNotice_Kind_t)*temp;
	ptr += strlen(ptr)+1;
	
	if (ZReadAscii(ptr,temp,sizeof(ZUnique_Id_t)) == ZERR_BADFIELD)
		return (ZERR_BADPKT);
	bcopy(temp,&notice->z_uid,sizeof(ZUnique_Id_t));
	ptr += strlen(ptr)+1;
	
	if (ZReadAscii(ptr,temp,sizeof(u_short)) == ZERR_BADFIELD)
		return (ZERR_BADPKT);
	notice->z_port = (u_short)*temp;
	ptr += strlen(ptr)+1;
	
	if (ZReadAscii(ptr,temp,sizeof(int)) == ZERR_BADFIELD)
		return (ZERR_BADPKT);
	notice->z_auth = *temp;
	ptr += strlen(ptr)+1;

	if (ZReadAscii(ptr,temp,sizeof(int)) == ZERR_BADFIELD)
		return (ZERR_BADPKT);
	notice->z_authent_len = *temp;
	ptr += strlen(ptr)+1;
	
	notice->z_ascii_authent = ptr;
	ptr += strlen(ptr)+1;
	notice->z_class = ptr;
	ptr += strlen(ptr)+1;
	notice->z_class_inst = ptr;
	ptr += strlen(ptr)+1;
	notice->z_opcode = ptr;
	ptr += strlen(ptr)+1;
	notice->z_sender = ptr;
	ptr += strlen(ptr)+1;
	notice->z_recipient = ptr;
	ptr += strlen(ptr)+1;

	cksum = ptr;
	
	if (ZReadAscii(ptr,&notice->z_checksum,sizeof(ZChecksum_t))
	    == ZERR_BADFIELD)
		return (ZERR_BADPKT);
	ptr += strlen(ptr)+1;

	notice->z_message = (caddr_t) ptr;
	notice->z_message_len = len-(ptr-buffer);

	if (!auth)
		return (ZERR_NONE);
	if (!notice->z_auth) {
		*auth = 0;
		return (ZERR_NONE);
	}
	
	if (__Zephyr_server) {
		if (ZReadAscii(notice->z_ascii_authent,authent.dat,
			       notice->z_authent_len) == ZERR_BADFIELD) {
			*auth = 0;
			return (ZERR_NONE);
		}
		authent.length = notice->z_authent_len;
		result = rd_ap_req(&authent,SERVER_SERVICE,
				   SERVER_INSTANCE,from->sin_addr.s_addr,
				   &dat,SERVER_SRVTAB);
		bcopy(dat.session,__Zephyr_session,sizeof(C_Block));
		*auth = (result == RD_AP_OK);
		return (ZERR_NONE);
	}

	if (result = get_credentials(SERVER_SERVICE,SERVER_INSTANCE,
			    __Zephyr_realm,&cred))
		return (result+krb_err_base);

/*	if (result = key_sched(cred.session,sess_sched))
		return (result+krb_err_base);
*/
	our_checksum = (ZChecksum_t)quad_cksum(buffer,NULL,cksum-buffer,0,
					       cred.session);

	*auth = (our_checksum == notice->z_checksum);
	
	return (ZERR_NONE);
}
