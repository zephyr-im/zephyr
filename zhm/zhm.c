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

static char rcsid_hm_c[] = "$Header$";

#include <ctype.h>
#include <signal.h>
#include <hesiod.h>
#include <sys/ioctl.h>
#include <sys/file.h>

int hmdebug = 0; /* kerberos stole variable called 'debug' */
int no_server = 1, nservchang = 0, nserv = 0, nclt = 0;
int booting = 1, timeout_type = 0, deactivated = 1;
long starttime;
u_short cli_port;
struct sockaddr_in cli_sin, serv_sin, from;
char **serv_list, **cur_serv_list;
char prim_serv[MAXHOSTNAMELEN], cur_serv[MAXHOSTNAMELEN];
int sig_type = 0;
struct hostent *hp;
char **clust_info;
char hostname[MAXHOSTNAMELEN], loopback[4];
char *PidFile = "/etc/athena/hm.pid";

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
    int pak_len;
    extern int optind;

    /* Override server argument? */
    if (gethostname(hostname, MAXHOSTNAMELEN) < 0) {
	  printf("Can't find my hostname?!\n");
	  exit(-1);
    }
    *prim_serv = NULL;
    if (getopt(argc, argv, "d") != EOF)
      hmdebug++;
    if (optind <= argc) {
	  (void)strcpy(prim_serv, argv[optind]);
	  if ((hp = gethostbyname(prim_serv)) == NULL) {
		printf("Unknown server name: %s\n", prim_serv);
		*prim_serv = NULL;
	  }
    }
    if (*prim_serv == NULL) {
	  if ((clust_info = hes_resolve(hostname, "CLUSTER")) == NULL) {
		printf("No hesiod information available.\n");
		exit(ZERR_SERVNAK);
	  }
	  for ( ; *clust_info; clust_info++)
	    if (!strncmp("ZEPHYR", upcase(*clust_info), 6)) {
		  register char *c;

		  if ((c = index(*clust_info, ' ')) == 0) {
			printf("Hesiod error getting cluster info.\n");
		  } else
		    (void)strcpy(prim_serv, c+1);
		  break;
	    }
    }
    
    init_hm();

    DPR2 ("zephyr server port: %u\n", ntohs(serv_sin.sin_port));
    DPR2 ("zephyr client port: %u\n", ntohs(cli_port));
    
    /* Main loop */
    for ever {
	  DPR ("Waiting for a packet...");
	  switch(sig_type) {
	      case 0:
		break;
	      case SIGHUP:
		sig_type = 0;
		syslog(LOG_INFO, "Flushing this client...");
		send_flush_notice(HM_FLUSH);
		deactivated = 1;
		break;
	      case SIGTERM:
		sig_type = 0;
		die_gracefully();
		break;
	      case SIGALRM:
		sig_type = 0;
		handle_timeout();
		break;
	      default:
		sig_type = 0;
		syslog (LOG_INFO, "Unknown system interrupt.");
		break;
	  }
	  ret = ZReceivePacket(packet, Z_MAXPKTLEN, &pak_len, &from);
	  if ((ret != ZERR_NONE) && (ret != EINTR)){
		Zperr(ret);
		com_err("hm", ret, "receiving notice");
	  } else if (ret != EINTR) {
		/* Where did it come from? */
		if ((ret = ZParseNotice(packet, pak_len, &notice))
		    != ZERR_NONE) {
		      Zperr(ret);
		      com_err("hm", ret, "parsing notice");
		} else {
		      DPR ("Got a packet.\n");
		      DPR ("notice:\n");
		      DPR2("\tz_kind: %d\n", notice.z_kind);
		      DPR2("\tz_port: %u\n", ntohs(notice.z_port));
		      DPR2("\tz_class: %s\n", notice.z_class);
		      DPR2("\tz_class_inst: %s\n", notice.z_class_inst);
		      DPR2("\tz_opcode: %s\n", notice.z_opcode);
		      DPR2("\tz_sender: %s\n", notice.z_sender);
		      DPR2("\tz_recip: %s\n", notice.z_recipient);
		      DPR2("\tz_def_format: %s\n", notice.z_default_format);
		      if ((bcmp(loopback, &from.sin_addr, 4) != 0) &&
			  ((notice.z_kind == SERVACK) ||
			   (notice.z_kind == SERVNAK) ||
			   (notice.z_kind == HMCTL))) {
			    server_manager(&notice);
		      } else {
			    if ((bcmp(loopback, &from.sin_addr, 4) == 0) &&
				((notice.z_kind == UNSAFE) ||
				 (notice.z_kind == UNACKED) ||
				 (notice.z_kind == ACKED) ||
				 (notice.z_kind == HMCTL))) {
				  /* Client program... */
				  if (deactivated) {
					send_boot_notice(HM_BOOT);
					deactivated = 0;
				  }
				  transmission_tower(&notice, packet, pak_len);
				  DPR2 ("Pending = %d\n", ZPending());
			    } else {
				  if (notice.z_kind == STAT) {
					send_stats(&notice, &from);
				  } else {
					syslog(LOG_INFO,
					       "Unknown notice type: %d",
					       notice.z_kind);
				  }
			    }
		      }
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
	    (void)strcpy(serv_list[0], prim_serv);
	    serv_list[1] = "";
	    if (*prim_serv == NULL) {
		  printf("No hesiod, no valid server found, exiting.\n");
		  exit(ZERR_SERVNAK);
	    }
      }
      cur_serv_list = serv_list;
      if (*prim_serv == NULL)
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
#endif DEBUG

      if (hmdebug)
	syslog(LOG_DEBUG, "Debugging on.");

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
	    (void)strcpy(cur_serv, prim_serv);
	    bcopy(hp->h_addr, &serv_sin.sin_addr, hp->h_length);
      }

      send_boot_notice(HM_BOOT);
      deactivated = 0;

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

void detach()
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

        if ((i = open("/dev/tty", O_RDWR, 666)) < 0)
	  syslog(LOG_ERR, "Cannot open /dev/tty to detach.");
	else {
	      (void) ioctl(i, TIOCNOTTY, (caddr_t) 0);
	      (void) close(i);
	}
}

void set_sig_type(sig)
     int sig;
{
      sig_type = sig;
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
      (void)strcpy(list[0], cur_serv);
      list[1] = (char *)malloc(64);
      sprintf(list[1], "%d", queue_len());
      list[2] = (char *)malloc(64);
      sprintf(list[2], "%d", nclt);
      list[3] = (char *)malloc(64);
      sprintf(list[3], "%d", nserv);
      list[4] = (char *)malloc(64);
      sprintf(list[4], "%d", nservchang);
      list[5] = (char *)malloc(64);
      (void)strcpy(list[5], rcsid_hm_c);
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
      (void)strcpy(list[9], MACHINE);

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
