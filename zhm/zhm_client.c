/* This file is part of the Project Athena Zephyr Notification System.
 * It contains the hostmanager <--> client interaction routines.
 *
 *      Created by:     David C. Jedlinsky
 *
 *      $Id$
 *
 *      Copyright (c) 1987 by the Massachusetts Institute of Technology.
 *      For copying and distribution information, see the file
 *      "mit-copyright.h". 
 */

#include "zhm.h"

#ifndef lint
#ifndef SABER
static char rcsid_hm_client_c[] = "$Id$";
#endif /* SABER */
#endif /* lint */

extern int noflushflag;
extern struct sockaddr_in cli_sin;

void transmission_tower(notice, from, packet, pak_len)
     ZNotice_t *notice;
     struct sockaddr_in *from;
     char *packet;
     int pak_len;
{
    int i;
    galaxy_info *gi;
    ZNotice_t gack;
    Code_t ret;
    struct sockaddr_in gsin;

    if (notice->z_dest_galaxy) {
	for (i=0; i<ngalaxies; i++)
	    if (strcasecmp(galaxy_list[i].galaxy_config.galaxy,
			   notice->z_dest_galaxy) == 0) {
		gi = &galaxy_list[i];
		break;
	    }
	if (i == ngalaxies) {
	    /* XXX I should generate some sort of error here.  Fortunately,
	       only new clients can elicit this error, so I can use a new
	       error value (message body string, probably) here.  For now,
	       just return and let the sender time out. */
	    return;
	}
    } else {
	gi = &galaxy_list[0];
    }

    if (notice->z_kind == HMCTL) {
	if (!strcmp(notice->z_opcode, CLIENT_FLUSH)) {
	    if (noflushflag)
		syslog(LOG_INFO, "Client requested hm flush (disabled).");
	    else
		galaxy_flush(gi);
	} else if (!strcmp(notice->z_opcode, CLIENT_NEW_SERVER)) {
	    galaxy_new_server(gi, NULL);
	} else {
	    syslog (LOG_INFO, "Bad control notice from client.");
	}
	return;
    } 

    if (notice->z_kind != UNSAFE) {
	gack = *notice;
	gack.z_kind = HMACK;
	gack.z_message_len = 0;
	gack.z_multinotice = "";
	gsin = cli_sin;
	gsin.sin_port = from->sin_port;
	if (gack.z_port == 0)
	    gack.z_port = from->sin_port;
	notice->z_port = gack.z_port;
	/* Bounce ACK to library */
	if ((ret = send_outgoing(&gsin, &gack)) != ZERR_NONE) {
	    Zperr(ret);
	    com_err("hm", ret, "sending raw notice");
	}
    }

    /* remove the dest galaxy, since the servers aren't prepared for it */
    notice->z_dest_galaxy = NULL;

    if (gi->current_server != NO_SERVER) {
	if ((ret = send_outgoing(&gi->sin, notice)) != ZERR_NONE) {
	    Zperr(ret);
	    com_err("hm", ret, "while sending raw notice");
	}
    }

    add_notice_to_galaxy(gi, notice, &gsin, pak_len);
}

Code_t
send_outgoing(sin, notice)
     struct sockaddr_in *sin;
     ZNotice_t *notice;
{
    Code_t retval;
    char *packet;
    int length;

    if ((retval = ZSetDestAddr(sin)) != ZERR_NONE)
       return(retval);

    if (!(packet = (char *) malloc((unsigned)sizeof(ZPacket_t))))
	return(ENOMEM);

    if ((retval = ZFormatSmallRawNotice(notice, packet, &length))
	!= ZERR_NONE) {
	free(packet);
	return(retval);
    }

    retval = ZSendPacket(packet, length, 0);

    free(packet);

    return(retval);
}

