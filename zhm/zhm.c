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
static char rcsid_hm_c[] = "$Header$";
#endif lint

#include <syslog.h>
#include <signal.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/param.h>

#ifdef DEBUG
#define DPR(a) fprintf(stderr, a)
#define DPR2(a,b) fprintf(stderr, a, b)
#else
#define DPR(a)
#define DPR2(a,b)
#endif

#define ever (;;)
#define Zperr(e) fprintf(stderr, "Error = %d\n", e)

int serv_sock;
struct sockaddr_in cli_sin, serv_sin, from;

extern int errno;

main(argc, argv)
char *argv[];
{
    struct hostent *hp;
    struct servent *sp;
    int cli_port;
    ZPacket_t packet;
    ZNotice_t notice;
    int auth, len;
    Code_t repl;
    char hostname[MAXHOSTNAMELEN];

    if (argc < 2) {
	  printf("Usage: %s server_machine\n", argv[0]);
	  exit(-1);
    }

    ZInitialize();
    gethostname(hostname, MAXHOSTNAMELEN);

    /* Open client socket, for receiving client and server notices */

    sp = getservbyname("zephyr-hm", "udp");
    cli_port = ntohs(sp->s_port);

    if ((repl = ZOpenPort(&cli_port)) != ZERR_NONE) {
	  Zperr(repl);
	  com_err("hm", repl, "opening port");
    }
    cli_sin = ZGetDestAddr();
    cli_sin.sin_port = sp->s_port;

    /* Open the server socket */

    sp = getservbyname("zephyr-clt", "udp");
    serv_sin.sin_port = sp->s_port;

    if ((serv_sock = socket(PF_INET, SOCK_DGRAM, 0)) < 0) {
	  printf("server socket failed\n");
	  exit(1);
    }

    DPR2 ("zephyr server port: %u\n", ntohs(serv_sin.sin_port));
    DPR2 ("zephyr client port: %u\n", cli_port);
    
    /* This is here until hesiod or something that can find NS is put in */

    /* who to talk to */
    if ((hp = gethostbyname(argv[1])) == NULL) {
	printf("gethostbyname failed\n");
	exit(1);
    }

    /* Set up communications with server */
    /* target is "zephyr-clt" port on server machine */

    serv_sin.sin_family = AF_INET;
    bcopy(hp->h_addr, &serv_sin.sin_addr, hp->h_length);
    
    /* Set up server notice */
    notice.z_kind = ACK;
    notice.z_checksum[0] = 0x100;
    notice.z_checksum[1] = 0x200;
    notice.z_port = (short) cli_port;
    notice.z_class = "HMBOOT";
    notice.z_class_inst = hostname;
    notice.z_opcode = "opcode";
    notice.z_sender = "sender";
    notice.z_recipient = "recip";
    notice.z_message_len = 0;

    /* send it off, using ZSendNotice */


    /* Sleep with wakeup call set */
    for ever {
	  DPR ("Waiting for a packet...");
	  if ((repl = ZReceivePacket(packet, sizeof packet,
				     &len, &from)) != ZERR_NONE) {
		Zperr(repl);
		com_err("hm", repl, "receiving packet");
	  } else {
		if ((repl = ZParseNotice(packet, len,
					 &notice, &auth)) != ZERR_NONE) {
		      Zperr(repl);
		      com_err("hm", repl, "parsing notice");
		}
		/* Where did it come from? */
		DPR ("Got a packet.\n");

		/* Client program... */
		transmission_tower(&notice);
	  }
	    
    }

}

/* This will eventually use Hesiod */

find_next_server(current_hostent)
struct hostent **current_hostent;
{
      if ((*current_hostent = gethostbyname("hal")) == NULL) {
	    perror("gethostbyname failed\n");
	    exit(1);
      }
}

server_manager(notice)
ZNotice_t notice;
{
      printf("A notice came in from the server.\n");
}

transmission_tower(notice)
ZNotice_t *notice;
{
      ZNotice_t gack;
      Code_t repl;
      struct sockaddr_in gsin;

      gack = *notice;
      DPR2 ("Message = %s\n", gack.z_message);
      gack.z_kind = HMACK;
      gack.z_message_len = 0;
      /* Make library think the client is the HM */
      gsin = cli_sin;
      gsin.sin_port = htons(gack.z_port);
      if (gack.z_port == 0) {
	    gack.z_port = ntohs(from.sin_port);
	    gsin.sin_port = from.sin_port;
      }
      DPR2 ("Client Port = %u\n", gack.z_port);
      if ((repl = ZSetDestAddr(&gsin)) != ZERR_NONE) {
	    Zperr(repl);
	    com_err("hm", repl, "setting destination");
      }
      if ((repl = ZSendRawNotice(&gack)) != ZERR_NONE) {
	    Zperr(repl);
	    com_err("hm", repl, "sending raw notice");
      }
      gsin = serv_sin;
      DPR2 ("Server Port = %u\n", ntohs(gsin.sin_port));
      if ((repl = ZSetDestAddr(&gsin)) != ZERR_NONE) {
	    printf("Error = %d\n", repl);
	    com_err("hm", repl, "setting destination");
      }
      if ((repl = ZSendRawNotice(notice)) != ZERR_NONE) {
	    printf("Error = %d\n", repl);
	    com_err("hm", repl, "while sending raw notice");
      }
      add_notice_to_queue(notice);
}

new_server()
{
      perror("server going down.\n");
      exit(1);
}

