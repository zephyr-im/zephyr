/* This file is part of the Project Athena Zephyr Notification System.
 * It contains the hostmanager <--> server interaction routines.
 *
 *      Created by:     David C. Jedlinsky
 *
 *      $Source$
 *      $Author$
 *
 *      Copyright (c) 1987 by the Massachusetts Institute of Technology.
 *      For copying and distribution information, see the file
 *      "mit-copyright.h". 
 */

#include "zhm.h"

#ifndef lint
#ifndef SABER
static char rcsid_hm_server_c[] = "$Header$";
#endif /* SABER */
#endif /* lint */

static void send_back __P((realm_info *, ZNotice_t *));
static void boot_timeout __P((void *));

extern int hmdebug;
extern u_short cli_port;

static void send_hmctl_notice(ri, op)
     realm_info *ri;
     char *op;
{
     ZNotice_t notice;
     Code_t ret;
  
     /* Set up server notice */
     notice.z_kind = HMCTL;
     notice.z_port = cli_port;
     notice.z_class = ZEPHYR_CTL_CLASS;
     notice.z_class_inst = ZEPHYR_CTL_HM;
     notice.z_opcode = op;
     notice.z_sender = "HM";
     notice.z_recipient = "";
     notice.z_default_format = "";
     notice.z_dest_realm = "";
     notice.z_num_other_fields = 0;
     notice.z_message_len = 0;
  
     if ((ret = ZSetDestAddr(&ri->sin)) != ZERR_NONE) {
	  Zperr(ret);
	  com_err("hm", ret, "setting destination");
     }
     if ((ret = ZSendNotice(&notice, ZNOAUTH)) != ZERR_NONE) {
	  Zperr(ret);
	  com_err("hm", ret, "sending hmctl notice %s", op);
     }
}

static int choose_next_server(ri)
     realm_info *ri;
{
    int new_server;

     if (ri->current_server < 0) {
	 new_server = random() % ri->realm_config.nservers;
     } else if (ri->realm_config.nservers == 1) {
	 new_server = NO_SERVER;
     } else if ((new_server = (random() % (ri->realm_config.nservers - 1))) ==
		ri->current_server) {
	 new_server = ri->realm_config.nservers - 1;
     }

     return(new_server);
}

void server_manager(notice, from)
     ZNotice_t *notice;
     struct sockaddr_in *from;
{
    int i;
    realm_info *ri;

    for (i=0; i<nrealms; i++)
	if ((memcmp((char *)&realm_list[i].sin.sin_addr,
		    (char *)&from->sin_addr, 4) == 0) &&
	    (realm_list[i].sin.sin_port == from->sin_port)) {
	    ri = &realm_list[i];
	    break;
	}

    if (!ri) {
	syslog(LOG_INFO, "Bad server notice from %s:%u.",
	       inet_ntoa(from->sin_addr), from->sin_port);
	return;
    }

    DPR ("A notice came in from the server.\n");

    if (ri->boot_timer) {
	timer_reset(ri->boot_timer);
	ri->boot_timer = NULL;
    }

    ri->nsrvpkts++;

    switch (ri->state) {
    case NEED_SERVER:
	/* there's a server which thinks it cares about us.  it's
	   wrong.  reboot the hm. */
	send_hmctl_notice(ri, HM_BOOT);

	ri->state = BOOTING;
	ri->boot_timer = timer_set_rel(BOOT_TIMEOUT, boot_timeout, ri);

	return;
    case DEAD_SERVER:
	/* the server is back from the dead.  reanimate the queue and
	   pretend it never went away */
	/* fall through */
    case BOOTING:
	/* got the ack. */
	retransmit_realm(ri);
	ri->state = ATTACHED;
	break;
    }

    switch(notice->z_kind) {
    case HMCTL:
	hm_control(ri, notice);
	break;
    case SERVNAK:
    case SERVACK:
	send_back(ri, notice);
	break;
    default:
	syslog (LOG_INFO, "Bad notice kind %d", notice->z_kind);
	break;
    }
}

void hm_control(ri, notice)
     realm_info *ri;
     ZNotice_t *notice;
{
    Code_t ret;
    struct hostent *hp;
    char suggested_server[64];
    struct in_addr addr;
     
    DPR("Control message!\n");
    if (!strcmp(notice->z_opcode, SERVER_SHUTDOWN)) {
	if (notice->z_message_len) {
	    addr.s_addr = inet_addr(notice->z_message);
	    realm_new_server(ri, &addr);
	} else {
	    realm_new_server(ri, NULL);
	}
    } else if (!strcmp(notice->z_opcode, SERVER_PING)) {
	notice->z_kind = HMACK;
	if ((ret = send_outgoing(&ri->sin, notice)) != ZERR_NONE) {
	    Zperr(ret);
	    com_err("hm", ret, "sending ACK");
	}
    } else {
	syslog (LOG_INFO, "Bad control message.");
    }
}

static void send_back(ri, notice)
     realm_info *ri;
     ZNotice_t *notice;
{
    ZNotice_Kind_t kind;
    struct sockaddr_in repl;
    Code_t ret;
  
    if ((strcmp(notice->z_opcode, HM_BOOT) == 0) ||
	(strcmp(notice->z_opcode, HM_ATTACH) == 0))
	return;

    if (remove_notice_from_realm(ri, notice, &kind, &repl) != ZERR_NONE) {
	syslog (LOG_INFO, "Hey! This packet isn't in my queue!");
	return;
    }

    /* check if client wants an ACK, and send it */
    if (kind == ACKED) {
	DPR2 ("Client ACK port: %u\n", ntohs(repl.sin_port));
	if ((ret = send_outgoing(&repl, notice)) != ZERR_NONE) {
	    Zperr(ret);
	    com_err("hm", ret, "sending ACK");
	}
    }
}

void realm_new_server(ri, addr)
     realm_info *ri;
     struct in_addr *addr;
{
    int i;
    int new_server;

    if (ri->state == ATTACHED) {
	disable_realm_retransmits(ri);
	ri->nchange++;
	syslog(LOG_INFO, "Server went down, finding new server.");
    }

    if (ri->current_server != NO_SERVER)
	send_hmctl_notice(ri, HM_DETACH);

    if (addr) {
	ri->current_server = EXCEPTION_SERVER;
	ri->sin.sin_addr = *addr;

	for (i=0; i<ri->realm_config.nservers; i++)
	    if (ri->realm_config.server_list[i].addr.s_addr ==
		ri->sin.sin_addr.s_addr) {
		ri->current_server = i;
		break;
	    }

	ri->state = ATTACHING;
    } else if ((new_server = choose_next_server(ri)) == NO_SERVER) {
	/* the only server went away.  Set a boot timer, try again
	   later */

	ri->current_server = -1;

	ri->state = (ri->state == BOOTING)?NEED_SERVER:DEAD_SERVER;
	ri->boot_timer = timer_set_rel(DEAD_TIMEOUT, boot_timeout, ri);

	return;
    } else {
	ri->current_server = new_server;
	ri->sin.sin_addr =
	    ri->realm_config.server_list[ri->current_server].addr;

	ri->state = (ri->state == NEED_SERVER)?BOOTING:ATTACHING;
    }

    send_hmctl_notice(ri, (ri->state == BOOTING)?HM_BOOT:HM_ATTACH);
    ri->boot_timer = timer_set_rel(BOOT_TIMEOUT, boot_timeout, ri);
}

void realm_flush(ri)
     realm_info *ri;
{
    init_realm_queue(ri);

    /* to flush, actually do a boot, because this causes an ACK to
       come back when it completes */

    if (ri->state == ATTACHED) {
	send_hmctl_notice(ri, HM_BOOT);

	ri->state = BOOTING;
	ri->boot_timer = timer_set_rel(BOOT_TIMEOUT, boot_timeout, ri);
    } else {
	ri->state = NEED_SERVER;
    }
}

void realm_reset(ri)
     realm_info *ri;
{
    ri->current_server = NO_SERVER;
    ri->nchange = 0;
    ri->nsrvpkts = 0;
    ri->ncltpkts = 0;

    realm_flush(ri);
}

static void boot_timeout(arg)
void *arg;
{
    realm_new_server((realm_info *) arg, NULL);
}

