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

#include <zephyr/mit-copyright.h>
#include <zephyr/zephyr.h>

#ifndef lint
#ifndef SABER
static char rcsid_hm_c[] = "$Header$";
#endif SABER
#endif lint

#include <syslog.h>
#include <signal.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <hesiod.h>

#ifdef DEBUG
#define DPR(a) fprintf(stderr, a); fflush(stderr)
#define DPR2(a,b) fprintf(stderr, a, b); fflush(stderr)
#else
#define DPR(a)
#define DPR2(a,b)
#endif

#define ever (;;)
#define Zperr(e) fprintf(stderr, "Error = %d\n", e)

int serv_sock, no_server = 1, exp_serv = 0;
struct sockaddr_in cli_sin, serv_sin, from;
struct hostent *hp;
char **serv_list, **cur_serv;
u_short cli_port;
char hostname[MAXHOSTNAMELEN], loopback[4];

extern int errno;
extern char *malloc();

void init_hm();

main(argc, argv)
char *argv[];
{
    caddr_t packet;
    ZNotice_t notice;
    Code_t ret;

    /* Override server argument? */
    if (argc > 1) {
	  exp_serv = 1;
	  /* who to talk to */
	  if ((hp = gethostbyname(argv[1])) == NULL) {
		DPR("gethostbyname failed\n");
		exp_serv = 0;
	  }
	  DPR2 ("Server = %s\n", argv[1]);
    }

    init_hm();

    DPR2 ("zephyr server port: %u\n", ntohs(serv_sin.sin_port));
    DPR2 ("zephyr client port: %u\n", ntohs(cli_port));
    
    /* Put in a fork here... */

    /* Sleep with wakeup call set */
    for ever {
	  DPR ("Waiting for a packet...");
	  packet = (char *) malloc(Z_MAXPKTLEN);
	  if ((ret = ZReceiveNotice(packet, Z_MAXPKTLEN, &notice,
				    NULL, &from)) != ZERR_NONE) {
		Zperr(ret);
		com_err("hm", ret, "receiving notice");
		free(packet);
	  } else {
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
		if ((notice.z_kind == SERVACK) ||
		    (notice.z_kind == SERVNAK) ||
		    (notice.z_kind == HMCTL)) {
		      server_manager(&notice);
		      free(packet);
		} else {
		      if (bcmp(loopback, &from.sin_addr, 4) == 0) {
			    /* Client program... */
			    transmission_tower(&notice, packet);
			    DPR2 ("Pending = %d\n", ZPending());
		      } else {
			    fprintf(stderr, "Unknown notice type: %d\n",
				    notice.z_kind);
			    free(packet);
		      }
		}
	  }
    }
}

void init_hm()
{
      struct servent *sp;
      Code_t ret;

      ZInitialize();
      ZSetServerState(1);  /* Aargh!!! */
      gethostname(hostname, MAXHOSTNAMELEN);
      init_queue();
      if ((serv_list = hes_resolve("*", "ZEPHYR-SERVER")) == (char **)NULL) {
	    syslog(LOG_ERR, "No servers?!?");
	    exit(1);
      }
      cur_serv = serv_list;
      --cur_serv;
      
      loopback[0] = 127;
      loopback[1] = 0;
      loopback[2] = 0;
      loopback[3] = 1;
      
      /* Open client socket, for receiving client and server notices */
      
      sp = getservbyname("zephyr-hm", "udp");
      cli_port = sp->s_port;
      
      if ((ret = ZOpenPort(&cli_port)) != ZERR_NONE) {
	    Zperr(ret);
	    com_err("hm", ret, "opening port");
      }
      cli_sin = ZGetDestAddr();
      cli_sin.sin_port = sp->s_port;
      
      /* Open the server socket */
      
      sp = getservbyname("zephyr-clt", "udp");
      bzero(&serv_sin, sizeof(struct sockaddr_in));
      serv_sin.sin_port = sp->s_port;
      
      if ((serv_sock = socket(PF_INET, SOCK_DGRAM, 0)) < 0) {
	    printf("server socket failed\n");
	    exit(1);
      }

      /* Set up communications with server */
      /* target is "zephyr-clt" port on server machine */

      serv_sin.sin_family = AF_INET;
      if (!exp_serv)
	find_next_server();
      else 
	bcopy(hp->h_addr, &serv_sin.sin_addr, hp->h_length);

      send_boot_notice();
}

send_boot_notice()
{
      ZNotice_t notice;
      Code_t ret;

      /* Set up server notice */
      notice.z_kind = ACKED;
      notice.z_port = cli_port;
      notice.z_class = ZEPHYR_CTL_CLASS;
      notice.z_class_inst = ZEPHYR_CTL_HM;
      notice.z_opcode = HM_BOOT;
      notice.z_sender = "sender";
      notice.z_recipient = "recip";
      notice.z_message_len = 0;
      
      /* Notify server that this host is here */
      if ((ret = ZSetDestAddr(&serv_sin)) != ZERR_NONE) {
	    Zperr(ret);
	    com_err("hm", ret, "setting destination");
      }
      if ((ret = ZSendNotice(&notice, 0)) != ZERR_NONE) {
	    Zperr(ret);
	    com_err("hm", ret, "sending startup notice");
      }
}

find_next_server()
{
      struct hostent *hp;

      if (*++cur_serv == NULL)
	cur_serv = serv_list;
      DPR2 ("Server = %s\n", *cur_serv);
      hp = gethostbyname(*cur_serv);
      bcopy(hp->h_addr, &serv_sin.sin_addr, hp->h_length);
}

server_manager(notice)
     ZNotice_t *notice;
{
      DPR ("A notice came in from the server.\n");
      if (bcmp(&serv_sin.sin_addr, &from.sin_addr, 4) != 0) {
	    DPR2 ("Bad notice from port %u\n", notice->z_port);
	    /* Sent a notice back saying this hostmanager isn't theirs */
      } else {
	    /* This is our server, handle the notice */
	    no_server = 0;
	    switch(notice->z_kind) {
		case HMCTL:
		  hm_control(notice);
		  break;
		case SERVNAK:
		  send_nak(notice);
		  break;
		case SERVACK:
		  send_ack(notice);
		  break;
		default:
		  DPR ("Bad notice kind!?\n");
		  break;
	    }
      }
}

hm_control(notice)
     ZNotice_t *notice;
{
      Code_t ret;

      DPR("Control message!\n");
      if (strcmp(notice->z_opcode, SERVER_SHUTDOWN))
	    new_server();
      else if (strcmp(notice->z_opcode, SERVER_PING)) {
	    notice->z_kind = HMACK;
	    if ((ret = ZSetDestAddr(&serv_sin)) != ZERR_NONE) {
		  Zperr(ret);
		  com_err("hm", ret, "setting destination");
	    }
	    if ((ret = ZSendRawNotice(notice)) != ZERR_NONE) {
		  Zperr(ret);
		  com_err("hm", ret, "sending ACK");
	    }
      } else
	fprintf(stderr, "Bad control message.\n");
}

send_nak(notice)
     ZNotice_t *notice;
{
      caddr_t packet;
      struct sockaddr_in repl;
      Code_t ret;

      if (!strcmp(notice->z_opcode, HM_BOOT)) {
	    /* ignore message, just a nak from boot */
      } else {
	    if (remove_notice_from_queue(notice, &packet,
					 &repl) != ZERR_NONE) {
		  DPR ("Hey! This packet isn't in my queue!\n");
	    } else {
		  /* check if client wants an ACK, and send it */
		  if (notice->z_kind == ACKED) {
			notice->z_kind = SERVNAK;
			DPR2 ("Client ACK port: %u\n", ntohs(repl.sin_port));
			if ((ret = ZSetDestAddr(&repl)) != ZERR_NONE) {
			      Zperr(ret);
			      com_err("hm", ret, "setting destination");
			}
			if ((ret = ZSendRawNotice(notice)) != ZERR_NONE) {
			      Zperr(ret);
			      com_err("hm", ret, "sending NAK");
			}
		  }
		  free(packet);
	    }
      }
}

send_ack(notice)
     ZNotice_t *notice;
{
      caddr_t packet;
      struct sockaddr_in repl;
      Code_t ret;

      if (!strcmp(notice->z_opcode, HM_BOOT)) {
	    /* ignore message, just an ack from boot */
      } else {
	    if (remove_notice_from_queue(notice, &packet,
					 &repl) != ZERR_NONE) {
		  DPR ("Hey! This packet isn't in my queue!\n");
	    } else {
		  /* check if client wants an ACK, and send it */
		  if (notice->z_kind == ACKED) {
			notice->z_kind = SERVACK;
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
		  free(packet);
	    }
      }
}

transmission_tower(notice, packet)
     ZNotice_t *notice;
     caddr_t packet;
{
      ZNotice_t gack;
      Code_t ret;
      struct sockaddr_in gsin;

      gack = *notice;
      DPR2 ("Message = %s\n", gack.z_message);
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
      DPR2 ("Server Port = %u\n", ntohs(serv_sin.sin_port));
      if ((ret = ZSetDestAddr(&serv_sin)) != ZERR_NONE) {
	    Zperr(ret);
	    com_err("hm", ret, "setting destination");
      }
      if ((ret = ZSendRawNotice(notice)) != ZERR_NONE) {
	    Zperr(ret);
	    com_err("hm", ret, "while sending raw notice");
      }
      add_notice_to_queue(notice, packet, &gsin);
}

new_server()
{
      ZNotice_t notice;
      Code_t ret;

      no_server = 1;
      DPR ("server going down.\n");
      notice.z_kind = ACKED;
      notice.z_port = cli_port;
      notice.z_class = ZEPHYR_CTL_CLASS;
      notice.z_class_inst = ZEPHYR_CTL_HM;
      notice.z_opcode = HM_FLUSH;
      notice.z_sender = "sender";
      notice.z_recipient = "recip";
      notice.z_message_len = 0;
      if ((ret = ZSetDestAddr(&serv_sin)) != ZERR_NONE) {
	    Zperr(ret);
	    com_err("hm", ret, "setting destination");
      }
      if ((ret = ZSendNotice(&notice, 0)) != ZERR_NONE) {
	    Zperr(ret);
	    com_err("hm", ret, "sending flush notice");
      }
      find_next_server();
      send_boot_notice();
      retransmit_queue();
}

