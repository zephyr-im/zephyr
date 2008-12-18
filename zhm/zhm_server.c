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
static const char rcsid_hm_server_c[] = "$Id$";
#endif /* SABER */
#endif /* lint */

static void boot_timeout __P((void *));
static int get_serv_timeout __P((void));

static Timer *boot_timer = NULL;
static int serv_rexmit_times[] = { 5, 10, 20, 40 };
static int serv_timeouts = 0;

int serv_loop = 0;
extern u_short cli_port;
extern struct sockaddr_in serv_sin, from;
extern int timeout_type, hmdebug, nservchang, booting, nserv, no_server;
extern int deactivated, rebootflag;
extern int numserv;
extern char **serv_list;
extern char cur_serv[], prim_serv[];
extern void die_gracefully(void);

void hm_control(ZNotice_t *);
void send_back(ZNotice_t *);
void new_server(char *);

/* Argument is whether we are actually booting, or just attaching
 * after a server switch */
void
send_boot_notice(char *op)
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
     notice.z_num_other_fields = 0;
     notice.z_message_len = 0;
  
     /* Notify server that this host is here */
     if ((ret = ZSetDestAddr(&serv_sin)) != ZERR_NONE) {
	  Zperr(ret);
	  com_err("hm", ret, "setting destination");
     }
     if ((ret = ZSendNotice(&notice, ZNOAUTH)) != ZERR_NONE) {
	  Zperr(ret);
	  com_err("hm", ret, "sending startup notice");
     }
     boot_timer = timer_set_rel(get_serv_timeout(), boot_timeout, NULL);
}

/* Argument is whether we are detaching or really going down */
void
send_flush_notice(char *op)
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
     notice.z_num_other_fields = 0;
     notice.z_message_len = 0;

     /* Tell server to lose us */
     if ((ret = ZSetDestAddr(&serv_sin)) != ZERR_NONE) {
	  Zperr(ret);
	  com_err("hm", ret, "setting destination");
     }
     if ((ret = ZSendNotice(&notice, ZNOAUTH)) != ZERR_NONE) {
	  Zperr(ret);
	  com_err("hm", ret, "sending flush notice");
     }
}

void
find_next_server(char *sugg_serv)
{
     struct hostent *hp;
     int done = 0;
     char **parse = serv_list;
     char *new_serv;
  
     if (sugg_serv) {
	  do {
	       if (!strcmp(*parse, sugg_serv))
		    done = 1;
	  } while ((done == 0) && (*++parse != NULL));
     }
     if (done) {
	  if ((hp = gethostbyname(sugg_serv)) != NULL) {
	       DPR2 ("Server = %s\n", sugg_serv);	
	       (void)strncpy(cur_serv, sugg_serv, MAXHOSTNAMELEN);
	       cur_serv[MAXHOSTNAMELEN - 1] = '\0';
	       if (hmdebug)
		    syslog(LOG_DEBUG, "Suggested server: %s\n", sugg_serv);
	  } else {
	       done = 0; 
	  }
     }
     while (!done) {
	 if ((++serv_loop > 3) && (strcmp(cur_serv, prim_serv))) {
	     serv_loop = 0;
	     if ((hp = gethostbyname(prim_serv)) != NULL) {
		 DPR2 ("Server = %s\n", prim_serv);
		 (void)strncpy(cur_serv, prim_serv, MAXHOSTNAMELEN);
		 cur_serv[MAXHOSTNAMELEN - 1] = '\0';
		 done = 1;
		 break;
	     }
	 }

	 switch (numserv) {
	 case 1:
	     if ((hp = gethostbyname(*serv_list)) != NULL) {
		 DPR2 ("Server = %s\n", *serv_list);
		 (void)strncpy(cur_serv, *serv_list, MAXHOSTNAMELEN);
		 cur_serv[MAXHOSTNAMELEN - 1] = '\0';
		 done = 1;
		 break;
	     }
	     /* fall through */
	 case 0:
	     if (rebootflag)
		 die_gracefully();
	     else
		 sleep(1);
	     break;
	 default:
	     do {
		 new_serv = serv_list[random() % numserv];
	     } while (!strcmp(new_serv, cur_serv));

	     if ((hp = gethostbyname(new_serv)) != NULL) {
		 DPR2 ("Server = %s\n", new_serv);
		 (void)strncpy(cur_serv, new_serv, MAXHOSTNAMELEN);
		 cur_serv[MAXHOSTNAMELEN - 1] = '\0';
		 done = 1;
	     } else
		 sleep(1);

	     break;
	 }
     }
     (void) memcpy((char *)&serv_sin.sin_addr, hp->h_addr, 4);
     nservchang++;
}

void
server_manager(ZNotice_t *notice)
{
    if (memcmp((char *)&serv_sin.sin_addr, (char *)&from.sin_addr, 4) ||
	(serv_sin.sin_port != from.sin_port)) {
	syslog (LOG_INFO, "Bad notice from port %u.", notice->z_port);
    } else {
	/* This is our server, handle the notice */
	booting = 0;
	serv_timeouts = 0;
	if (boot_timer) {
	    timer_reset(boot_timer);
	    boot_timer = NULL;
	}
	DPR ("A notice came in from the server.\n");
	nserv++;
	switch(notice->z_kind) {
	case HMCTL:
	    hm_control(notice);
	    break;
	case SERVNAK:
	case SERVACK:
	    send_back(notice);
	    break;
	default:
	    syslog (LOG_INFO, "Bad notice kind!?");
	    break;
	}
    }
}

void
hm_control(ZNotice_t *notice)
{
    Code_t ret;
    struct hostent *hp;
    char suggested_server[MAXHOSTNAMELEN];
    unsigned long addr;
     
    DPR("Control message!\n");
    if (!strcmp(notice->z_opcode, SERVER_SHUTDOWN)) {
	if (notice->z_message_len) {
	    addr = inet_addr(notice->z_message);
	    hp = gethostbyaddr((char *) &addr, sizeof(addr), AF_INET);
	    if (hp != NULL) {
		strncpy(suggested_server, hp->h_name, sizeof(suggested_server));
		suggested_server[sizeof(suggested_server) - 1] = '\0';
		new_server(suggested_server);
	    } else {
		new_server(NULL);
	    }
	} else {
	    new_server((char *)NULL);
	}
    } else if (!strcmp(notice->z_opcode, SERVER_PING)) {
	notice->z_kind = HMACK;
	if ((ret = ZSetDestAddr(&serv_sin)) != ZERR_NONE) {
	    Zperr(ret);
	    com_err("hm", ret, "setting destination");
	}
	if ((ret = send_outgoing(notice)) != ZERR_NONE) {
	    Zperr(ret);
	    com_err("hm", ret, "sending ACK");
	}
	if (no_server) {
	    no_server = 0;
	    retransmit_queue(&serv_sin);
	}
    } else {
	syslog (LOG_INFO, "Bad control message.");
    }
}

void
send_back(ZNotice_t *notice)
{
    ZNotice_Kind_t kind;
    struct sockaddr_in repl;
    Code_t ret;
  
    if (!strcmp(notice->z_opcode, HM_BOOT) ||
	!strcmp(notice->z_opcode, HM_ATTACH)) {
	/* ignore message, just an ack from boot, but exit if we
	 * are rebooting.
	 */
	if (rebootflag)
	    die_gracefully();
    } else {
	if (remove_notice_from_queue(notice, &kind, &repl) != ZERR_NONE) {
	    syslog (LOG_INFO, "Hey! This packet isn't in my queue!");
	} else {
	    /* check if client wants an ACK, and send it */
	    if (kind == ACKED) {
		DPR2 ("Client ACK port: %u\n", ntohs(repl.sin_port));
		if ((ret = ZSetDestAddr(&repl)) != ZERR_NONE) {
		    Zperr(ret);
		    com_err("hm", ret, "setting destination");
		}
		if ((ret = send_outgoing(notice)) != ZERR_NONE) {
		    Zperr(ret);
		    com_err("hm", ret, "sending ACK");
		}
	    }
	}
    }
    if (no_server) {
	no_server = 0;
	retransmit_queue(&serv_sin);
    }
}

void
new_server(char *sugg_serv)
{
    no_server = 1;
    syslog (LOG_INFO, "Server went down, finding new server.");
    send_flush_notice(HM_DETACH);
    find_next_server(sugg_serv);
    if (booting) {
	send_boot_notice(HM_BOOT);
	deactivated = 0;
    } else {
	send_boot_notice(HM_ATTACH);
    }
    disable_queue_retransmits();
}

static void
boot_timeout(void *arg)
{
    serv_timeouts++;
    new_server(NULL);
}

static int get_serv_timeout(void)
{
    int ind, ntimeouts;

    ind = (numserv == 0) ? serv_timeouts : serv_timeouts / numserv;
    ntimeouts = sizeof(serv_rexmit_times) / sizeof(*serv_rexmit_times);
    if (ind >= ntimeouts)
	ind = ntimeouts - 1;
    return serv_rexmit_times[ind];
}
