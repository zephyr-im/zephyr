/* This file is part of the Project Athena Zephyr Notification System.
 * It contains the hostmanager client program.
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

#include "hm.h"

#ifndef lint
#ifndef SABER
static char rcsid_hm_c[] = "$Header$";
#endif SABER
#endif lint

#include <ctype.h>
#include <signal.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <hesiod.h>
#include <sys/ioctl.h>
#include <sys/file.h>

#ifdef vax
#define MACHINE "vax"
#define ok
#endif vax
#ifdef ibm032
#define MACHINE "rtpc"
#define ok
#endif ibm032
#ifndef ok
#define MACHINE "unknown"
#endif ok

int hmdebug = 0; /* Goddamned kerberos stole debug variable!!! */
int no_server = 1, timeout_type = 0, serv_loop = 0;
int nserv = 0, nclt = 0, nservchang = 0, sig_type = 0;
long starttime;
struct sockaddr_in cli_sin, serv_sin, from;
struct hostent *hp;
char **serv_list, **cur_serv_list, **clust_info;
u_short cli_port;
char hostname[MAXHOSTNAMELEN], prim_serv[MAXHOSTNAMELEN], loopback[4];
char *cur_serv, *PidFile = "/etc/athena/hm.pid";

extern int errno;
extern char *index();

void init_hm(), detach(), handle_timeout(), resend_notices(), die_gracefully();
void set_sig_type();
char *upcase();

main(argc, argv)
char *argv[];
{
    ZPacket_t packet;
    ZNotice_t notice;
    Code_t ret;
    int optch;
    extern int optind;

    /* Override server argument? */
    if (gethostname(hostname, MAXHOSTNAMELEN) < 0) {
	  printf("Can't find my hostname?!\n");
	  exit(-1);
    }
    (void)strcpy(prim_serv, "");
    if ((optch = getopt(argc, argv, "d")) != EOF)
      hmdebug++;
    if (optind <= argc) 
      (void)strcpy(prim_serv, argv[optind]);
    else {
	  if ((clust_info = hes_resolve(hostname, "CLUSTER")) == NULL) {
		printf("No hesiod information available.\n");
		exit(ZERR_SERVNAK);
	  }
	  for ( ; *clust_info; clust_info++)
	    if (!strncmp("ZEPHYR", upcase(*clust_info), 6)) {
		  (void)strcpy(prim_serv, index(*clust_info, ' ')+1);
		  break;
	    }
    }
    
    init_hm();

    DPR2 ("zephyr server port: %u\n", ntohs(serv_sin.sin_port));
    DPR2 ("zephyr client port: %u\n", ntohs(cli_port));
    
    /* Main loop */
    for ever {
	  DPR ("Waiting for a packet...");
	  ret = ZReceiveNotice(packet, Z_MAXPKTLEN, &notice, &from);
	  if ((ret != ZERR_NONE) && (ret != EINTR)){
		Zperr(ret);
		com_err("hm", ret, "receiving notice");
	  } else if (ret != EINTR) {
		/* Where did it come from? */
		DPR ("Got a packet.\n");
		DPR ("notice:\n");
		DPR2("\tz_kind: %d\n", notice.z_kind);
		DPR2("\tz_port: %u\n", ntohs(notice.z_port));
		DPR2("\tz_class: %s\n", notice.z_class);
		DPR2("\tz_class_inst: %s\n", notice.z_class_inst);
		DPR2("\tz_opcode: %s\n", notice.z_opcode);
		DPR2("\tz_sender: %s\n", notice.z_sender);
		DPR2("\tz_recip: %s\n", notice.z_recipient);
		DPR2("\tz_default_format: %s\n", notice.z_default_format);
		if ((notice.z_kind == SERVACK) ||
		    (notice.z_kind == SERVNAK) ||
		    (notice.z_kind == HMCTL)) {
		      server_manager(&notice);
		} else {
		      if ((bcmp(loopback, &from.sin_addr, 4) == 0) &&
			  ((notice.z_kind == UNSAFE) ||
			   (notice.z_kind == UNACKED) ||
			   (notice.z_kind == ACKED))) {
			    /* Client program... */
			    transmission_tower(&notice, packet);
			    DPR2 ("Pending = %d\n", ZPending());
		      } else {
			    if (notice.z_kind == STAT) {
				  send_stats(&notice, &from);
			    } else {
				  syslog(LOG_INFO, "Unknown notice type: %d",
					 notice.z_kind);
			    }
		      }
		}
	  } else {
		switch(sig_type) {
		    case SIGHUP:
		      new_server(NULL);
		      break;
		    case SIGTERM:
		      die_gracefully();
		      break;
		    case SIGALRM:
		      handle_timeout();
		      break;
		    default:
		      syslog (LOG_INFO, "Unknown system interrupt.");
		      break;
		}
	  }
    }
}

void init_hm()
{
      struct servent *sp;
      Code_t ret;
      FILE *fp;

      starttime = time(0);
      openlog("hm", LOG_PID, LOG_DAEMON);

      if ((ret = ZInitialize()) != ZERR_NONE) {
	    Zperr(ret);
	    com_err("hm", ret, "initializing");
	    closelog();
	    exit(-1);
      }
      (void)ZSetServerState(1);  /* Aargh!!! */
      init_queue();
      if ((serv_list = hes_resolve("zephyr", "sloc")) == (char **)NULL) {
	    syslog(LOG_ERR, "No servers or no hesiod");
	    serv_list = (char **)malloc(2 * sizeof(char *));
	    serv_list[0] = (char *)malloc(MAXHOSTNAMELEN);
	    strcpy(serv_list[0], prim_serv);
	    serv_list[1] = "";
      }
      cur_serv_list = serv_list;
      if (!strcmp(prim_serv, ""))
	(void)strcpy(prim_serv, *cur_serv_list);
      
      loopback[0] = 127;
      loopback[1] = 0;
      loopback[2] = 0;
      loopback[3] = 1;
      
      /* Open client socket, for receiving client and server notices */
      
      if ((sp = getservbyname("zephyr-hm", "udp")) == NULL) {
	    printf("No zephyr-hm entry in /etc/services.\n");
	    exit(1);
      }
      cli_port = sp->s_port;
      
      if ((ret = ZOpenPort(&cli_port)) != ZERR_NONE) {
	    Zperr(ret);
	    com_err("hm", ret, "opening port");
	    exit(ret);
      }
      cli_sin = ZGetDestAddr();
      cli_sin.sin_port = sp->s_port;
      
      /* Open the server socket */
      
      if ((sp = getservbyname("zephyr-clt", "udp")) == NULL) {
	    printf("No zephyr-clt entry in /etc/services.\n");
	    exit(1);
      }

#ifndef DEBUG
      detach();

      /* Write pid to file */
      fp = fopen(PidFile, "w");
      if (fp != NULL) {
	    fprintf(fp, "%d\n", getpid());
	    (void) fclose(fp);
      }
      if (hmdebug)
	syslog(LOG_DEBUG, "Debugging on.");
#endif DEBUG

      bzero(&serv_sin, sizeof(struct sockaddr_in));
      serv_sin.sin_port = sp->s_port;
      
      /* Set up communications with server */
      /* target is "zephyr-clt" port on server machine */

      serv_sin.sin_family = AF_INET;

      /* who to talk to */
      if ((hp = gethostbyname(prim_serv)) == NULL) {
	    DPR("gethostbyname failed\n");
	    find_next_server(NULL);
      } else {
	    DPR2 ("Server = %s\n", prim_serv);
	    cur_serv = prim_serv;
	    bcopy(hp->h_addr, &serv_sin.sin_addr, hp->h_length);
      }

      send_boot_notice(HM_BOOT);

      (void)signal (SIGHUP,  set_sig_type);
      (void)signal (SIGALRM, set_sig_type);
      (void)signal (SIGTERM, set_sig_type);
}

char *upcase(s)
     register char *s;
{
      char *r = s;

      for (; *s; s++)
	if (islower(*s)) *s = toupper(*s);
      return(r);
}

/* Argument is whether we are actually booting, or just attaching
   after a server switch */
send_boot_notice(op)
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
      notice.z_sender = "sender";
      notice.z_recipient = "";
      notice.z_default_format = 0;
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
      timeout_type = BOOTING;
      (void)alarm(SERV_TIMEOUT);
}

/* Argument is whether we are detaching or really going down */
send_flush_notice(op)
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
      notice.z_sender = "sender";
      notice.z_recipient = "";
      notice.z_default_format = 0;
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

static void
detach()
{
        /* detach from terminal and fork. */
        register int i, x = ZGetFD(), size = getdtablesize();

        if (i = fork()) {
                if (i < 0)
                        perror("fork");
                exit(0);
        }

        for (i = 0; i < size; i++)
	  if (i != x)
	    (void) close(i);

        i = open("/dev/tty", O_RDWR, 666);
        (void) ioctl(i, TIOCNOTTY, (caddr_t) 0);
        (void) close(i);
}

find_next_server(sugg_serv)
     char *sugg_serv;
{
      struct hostent *hp;
      int done = 0;
      char **parse = serv_list;

      if (sugg_serv) {
	    do {
		  if (!strcmp(*parse, sugg_serv))
		    done = 1;
	    } while ((done == 0) && (*++parse != NULL));
      }
      if (done) {
	    if (hmdebug)
	      syslog(LOG_DEBUG, "Suggested server: %s\n", sugg_serv);
	    hp = gethostbyname(sugg_serv);
	    DPR2 ("Server = %s\n", sugg_serv);
	    strcpy(cur_serv, sugg_serv);
      } else {		  
	    if ((++serv_loop > 3) && (strcmp(cur_serv, prim_serv))) {
		  serv_loop = 0;
		  hp = gethostbyname(prim_serv);
		  DPR2 ("Server = %s\n", prim_serv);
		  cur_serv = prim_serv;
	    } else
	      do {
		    if (*++cur_serv_list == NULL)
		      cur_serv_list = serv_list;
		    if (strcmp(*cur_serv_list, cur_serv)) {
			  hp = gethostbyname(*cur_serv_list);
			  DPR2 ("Server = %s\n", *cur_serv_list);
			  cur_serv = *cur_serv_list;
			  done = 1;
		    }
	      } while (done == 0);
      }
      bcopy(hp->h_addr, &serv_sin.sin_addr, hp->h_length);
      nservchang++;
}

void set_sig_type(sig)
     int sig;
{
      sig_type = sig;
}

server_manager(notice)
     ZNotice_t *notice;
{
      if ((bcmp(&serv_sin.sin_addr, &from.sin_addr, 4) != 0) ||
	  (serv_sin.sin_port != from.sin_port)) {
	    syslog (LOG_INFO, "Bad notice from port %u.", notice->z_port);
	    /* Sent a notice back saying this hostmanager isn't theirs */
      } else {
	    /* This is our server, handle the notice */
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

hm_control(notice)
     ZNotice_t *notice;
{
      Code_t ret;
      struct hostent *hp;
      char suggested_server[64];
      long addr;

      DPR("Control message!\n");
      if (!strcmp(notice->z_opcode, SERVER_SHUTDOWN)) {
	      if (notice->z_message_len) {
		      addr = inet_addr(notice->z_message);
		      if ((hp = gethostbyaddr(&addr,
					      4,
					      AF_INET)) != NULL) {
			      strcpy(suggested_server, hp->h_name);
			      new_server(suggested_server);
		      } else
			      new_server(NULL);
	      }
	      else
		      new_server(NULL);
      } else if (!strcmp(notice->z_opcode, SERVER_PING)) {
	    if (no_server)
	      (void)alarm(0);
	    notice->z_kind = HMACK;
	    if ((ret = ZSetDestAddr(&serv_sin)) != ZERR_NONE) {
		  Zperr(ret);
		  com_err("hm", ret, "setting destination");
	    }
	    if ((ret = ZSendRawNotice(notice)) != ZERR_NONE) {
		  Zperr(ret);
		  com_err("hm", ret, "sending ACK");
	    }
	    if (no_server) {
		  no_server = 0;
		  retransmit_queue(&serv_sin);
	    }
      } else
	syslog (LOG_INFO, "Bad control message.");
}

send_back(notice)
     ZNotice_t *notice;
{
      ZNotice_Kind_t kind;
      struct sockaddr_in repl;
      Code_t ret;

      if (no_server)
	(void)alarm(0);
      if (!strcmp(notice->z_opcode, HM_BOOT) ||
	  !strcmp(notice->z_opcode, HM_ATTACH)) {
	    /* ignore message, just an ack from boot */
      } else {
	    if (remove_notice_from_queue(notice, &kind,
					 &repl) != ZERR_NONE) {
		  syslog (LOG_INFO, "Hey! This packet isn't in my queue!");
	    } else {
		  /* check if client wants an ACK, and send it */
		  if (kind == ACKED) {
			DPR2 ("Client ACK port: %u\n", ntohs(repl.sin_port));
			if ((ret = ZSetDestAddr(&repl)) != ZERR_NONE) {
			      Zperr(ret);
			      com_err("hm", ret, "setting destination");
			}
			if ((ret = ZSendRawNotice(notice)) != ZERR_NONE) {
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

transmission_tower(notice, packet)
     ZNotice_t *notice;
     caddr_t packet;
{
      ZNotice_t gack;
      Code_t ret;
      struct sockaddr_in gsin;
      int tleft;

      nclt++;
      if (notice->z_kind != UNSAFE) {
	    gack = *notice;
	    gack.z_kind = HMACK;
	    gack.z_message_len = 0;
	    gsin = cli_sin;
	    gsin.sin_port = from.sin_port;
	    if (gack.z_port == 0)
	      gack.z_port = from.sin_port;
	    DPR2 ("Client Port = %u\n", ntohs(gack.z_port));
	    notice->z_port = gack.z_port;
	    if ((ret = ZSetDestAddr(&gsin)) != ZERR_NONE) {
		  Zperr(ret);
		  com_err("hm", ret, "setting destination");
	    }
	    /* Bounce ACK to library */
	    if ((ret = ZSendRawNotice(&gack)) != ZERR_NONE) {
		  Zperr(ret);
		  com_err("hm", ret, "sending raw notice");
	    }
      }
      if (!no_server) {
	    DPR2 ("Server Port = %u\n", ntohs(serv_sin.sin_port));
	    if ((ret = ZSetDestAddr(&serv_sin)) != ZERR_NONE) {
		  Zperr(ret);
		  com_err("hm", ret, "setting destination");
	    }
	    if ((ret = ZSendRawNotice(notice)) != ZERR_NONE) {
		  Zperr(ret);
		  com_err("hm", ret, "while sending raw notice");
	    }
	    if ((tleft = alarm(0)) > 0)
	      (void)alarm(tleft);
	    else {
		  timeout_type = NOTICES;
		  (void)alarm(NOTICE_TIMEOUT);
	    }
      }
      (void)add_notice_to_queue(notice, packet, &gsin);
}

send_stats(notice, sin)
     ZNotice_t *notice;
     struct sockaddr_in *sin;
{
      Code_t ret;
      ZPacket_t bfr;
      char *list[20];
      int len, i, nitems = 10;

      if ((ret = ZSetDestAddr(sin)) != ZERR_NONE) {
	    Zperr(ret);
	    com_err("hm", ret, "setting destination");
      }
      notice->z_kind = HMACK;

      list[0] = (char *)malloc(MAXHOSTNAMELEN);
      strcpy(list[0], cur_serv);
      list[1] = (char *)malloc(64);
      sprintf(list[1], "%d", queue_len());
      list[2] = (char *)malloc(64);
      sprintf(list[2], "%d", nclt);
      list[3] = (char *)malloc(64);
      sprintf(list[3], "%d", nserv);
      list[4] = (char *)malloc(64);
      sprintf(list[4], "%d", nservchang);
      list[5] = (char *)malloc(64);
      strcpy(list[5], rcsid_hm_c);
      list[6] = (char *)malloc(64);
      if (no_server)
	sprintf(list[6], "yes");
      else
	sprintf(list[6], "no");
      list[7] = (char *)malloc(64);
      sprintf(list[7], "%ld", time(0) - starttime);
      list[8] = (char *)malloc(64);
      sprintf(list[8], "%ld", sbrk(0));
      list[9] = (char *)malloc(32);
      strcpy(list[9], MACHINE);

      if ((ret = ZFormatRawNoticeList(notice, list, nitems, bfr,
				      Z_MAXPKTLEN, &len)) != ZERR_NONE) {
	    syslog(LOG_INFO, "Couldn't format stats packet");
      } else
	if ((ret = ZSendPacket(bfr, len)) != ZERR_NONE) {
	      Zperr(ret);
	      com_err("hm", ret, "sending stats");
	}
      for(i=0;i<nitems;i++)
	free(list[i]);
}

new_server(sugg_serv)
     char *sugg_serv;
{
      no_server = 1;
      syslog (LOG_INFO, "Server went down, finding new server.");
      send_flush_notice(HM_DETACH);
      find_next_server(sugg_serv);
      send_boot_notice(HM_ATTACH);
}

void handle_timeout()
{
      switch(timeout_type) {
	  case BOOTING:
	    new_server(NULL);
	    break;
	  case NOTICES:
	    DPR ("Notice timeout\n");
	    resend_notices(&serv_sin);
	    break;
	  default:
	    syslog (LOG_ERR, "Unknown timeout type: %d\n", timeout_type);
	    break;
      }
}

void die_gracefully()
{
      syslog(LOG_INFO, "Terminate signal caught...");
      send_flush_notice(HM_FLUSH);
      unlink(PidFile);
      closelog();
      exit(0);
}
