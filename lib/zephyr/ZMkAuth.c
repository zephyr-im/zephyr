/* This file is part of the Project Athena Zephyr Notification System.
 * It contains source for the internal Zephyr routines.
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

Code_t ZMakeAuthentication(notice,buffer,buffer_len,len)
	ZNotice_t	*notice;
	ZPacket_t	buffer;
	int		buffer_len;
	int		*len;
{
	int retval,result;
	KTEXT_ST authent;

	notice->z_auth = 1;
	if ((result = mk_ap_req(&authent,SERVER_SERVICE,
			        SERVER_INSTANCE,__Zephyr_realm,0))
	    != MK_AP_OK)
		return (result+krb_err_base);
	notice->z_authent_len = authent.length;
	notice->z_ascii_authent = (char *)malloc((unsigned)authent.length*3);
	if (!notice->z_ascii_authent)
		return (ENOMEM);
	if ((retval = ZMakeAscii(notice->z_ascii_authent,
				 authent.length*3,
				 authent.dat,
				 authent.length)) != ZERR_NONE) {
		free(notice->z_ascii_authent);
		return (retval);
	}
	retval = Z_FormatRawHeader(notice,buffer,buffer_len,len);
	free(notice->z_ascii_authent);
	notice->z_authent_len = 0;

	return (retval);
}
