/* This file is part of the Project Athena Zephyr Notification System.
 * It contains the hostmanager <--> server interaction routines.
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
static char rcsid_hm_server_c[] = "$Id$";
#endif /* SABER */
#endif /* lint */

static void send_back __P((galaxy_info *, ZNotice_t *));
static void boot_timeout __P((void *));

extern int hmdebug;
extern u_short cli_port;

static void send_hmctl_notice(gi, op)
     galaxy_info *gi;
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
     notice.z_dest_galaxy = "";
     notice.z_num_other_fields = 0;
     notice.z_message_len = 0;
  
     if ((ret = ZSetDestAddr(&gi->sin)) != ZERR_NONE) {
	  Zperr(ret);
	  com_err("hm", ret, "setting destination");
     }
     if ((ret = ZSendNotice(&notice, ZNOAUTH)) != ZERR_NONE) {
	  Zperr(ret);
	  com_err("hm", ret, "sending hmctl notice %s", op);
     }
}

static int choose_next_server(gi)
     galaxy_info *gi;
{
    int new_server;

     if (gi->current_server < 0) {
	 new_server = random() % gi->galaxy_config.nservers;
     } else if (gi->galaxy_config.nservers == 1) {
	 new_server = NO_SERVER;
     } else if ((new_server = (random() % (gi->galaxy_config.nservers - 1))) ==
		gi->current_server) {
	 new_server = gi->galaxy_config.nservers - 1;
     }

     return(new_server);
}

void server_manager(notice, from)
     ZNotice_t *notice;
     struct sockaddr_in *from;
{
    int i;
    galaxy_info *gi;

    for (i=0; i<ngalaxies; i++)
	if ((memcmp((char *)&galaxy_list[i].sin.sin_addr,
		    (char *)&from->sin_addr, 4) == 0) &&
	    (galaxy_list[i].sin.sin_port == from->sin_port)) {
	    gi = &galaxy_list[i];
	    break;
	}

    if (!gi) {
	syslog(LOG_INFO, "Bad server notice from %s:%u.",
	       inet_ntoa(from->sin_addr), from->sin_port);
	return;
    }

    DPR ("A notice came in from the server.\n");

    if (gi->boot_timer) {
	timer_reset(gi->boot_timer);
	gi->boot_timer = NULL;
    }

    gi->nsrvpkts++;

    switch (gi->state) {
    case NEED_SERVER:
	/* there's a server which thinks it cares about us.  it's
	   wrong.  reboot the hm. */
	send_hmctl_notice(gi, HM_BOOT);

	gi->state = BOOTING;
	gi->boot_timer = timer_set_rel(BOOT_TIMEOUT, boot_timeout, gi);

	return;
    case DEAD_SERVER:
	/* the server is back from the dead.  reanimate the queue and
	   pretend it never went away */
	/* fall through */
    case BOOTING:
	/* got the ack. */
	retransmit_galaxy(gi);
	gi->state = ATTACHED;
	break;
    }

    switch(notice->z_kind) {
    case HMCTL:
	hm_control(gi, notice);
	break;
    case SERVNAK:
    case SERVACK:
	send_back(gi, notice);
	break;
    default:
	syslog (LOG_INFO, "Bad notice kind %d", notice->z_kind);
	break;
    }
}

void hm_control(gi, notice)
     galaxy_info *gi;
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
	    galaxy_new_server(gi, &addr);
	} else {
	    galaxy_new_server(gi, NULL);
	}
    } else if (!strcmp(notice->z_opcode, SERVER_PING)) {
	notice->z_kind = HMACK;
	if ((ret = send_outgoing(&gi->sin, notice)) != ZERR_NONE) {
	    Zperr(ret);
	    com_err("hm", ret, "sending ACK");
	}
    } else {
	syslog (LOG_INFO, "Bad control message.");
    }
}

static void send_back(gi, notice)
     galaxy_info *gi;
     ZNotice_t *notice;
{
    ZNotice_Kind_t kind;
    struct sockaddr_in repl;
    Code_t ret;
  
    if ((strcmp(notice->z_opcode, HM_BOOT) == 0) ||
	(strcmp(notice->z_opcode, HM_ATTACH) == 0))
	return;

    if (remove_notice_from_galaxy(gi, notice, &kind, &repl) != ZERR_NONE) {
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

void galaxy_new_server(gi, addr)
     galaxy_info *gi;
     struct in_addr *addr;
{
    int i;
    int new_server;

    if (gi->state == ATTACHED) {
	disable_galaxy_retransmits(gi);
	gi->nchange++;
	syslog(LOG_INFO, "Server went down, finding new server.");
    }

    if (gi->current_server != NO_SERVER)
	send_hmctl_notice(gi, HM_DETACH);

    if (gi->boot_timer) {
	timer_reset(gi->boot_timer);
	gi->boot_timer = 0;
    }

    if (addr) {
	gi->current_server = EXCEPTION_SERVER;
	gi->sin.sin_addr = *addr;

	for (i=0; i<gi->galaxy_config.nservers; i++)
	    if (gi->galaxy_config.server_list[i].addr.s_addr ==
		gi->sin.sin_addr.s_addr) {
		gi->current_server = i;
		break;
	    }

	gi->state = ATTACHING;
    } else if ((new_server = choose_next_server(gi)) == NO_SERVER) {
	/* the only server went away.  Set a boot timer, try again
	   later */

	gi->current_server = NO_SERVER;

	gi->state = (gi->state == BOOTING)?NEED_SERVER:DEAD_SERVER;
	gi->boot_timer = timer_set_rel(DEAD_TIMEOUT, boot_timeout, gi);

	return;
    } else {
	gi->current_server = new_server;
	gi->sin.sin_addr =
	    gi->galaxy_config.server_list[gi->current_server].addr;

	gi->state = (gi->state == NEED_SERVER)?BOOTING:ATTACHING;
    }

    send_hmctl_notice(gi, (gi->state == BOOTING)?HM_BOOT:HM_ATTACH);
    gi->boot_timer = timer_set_rel(BOOT_TIMEOUT, boot_timeout, gi);
}

void galaxy_flush(gi)
     galaxy_info *gi;
{
    init_galaxy_queue(gi);

    /* to flush, actually do a boot, because this causes an ACK to
       come back when it completes */

    if (gi->state == ATTACHED) {
	send_hmctl_notice(gi, HM_BOOT);

	gi->state = BOOTING;
	gi->boot_timer = timer_set_rel(BOOT_TIMEOUT, boot_timeout, gi);
    } else {
	gi->state = NEED_SERVER;
    }
}

void galaxy_reset(gi)
     galaxy_info *gi;
{
    gi->current_server = NO_SERVER;
    gi->nchange = 0;
    gi->nsrvpkts = 0;
    gi->ncltpkts = 0;

    galaxy_flush(gi);
}

static void boot_timeout(arg)
void *arg;
{
    galaxy_new_server((galaxy_info *) arg, NULL);
}

