
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
#include <sys/un.h>

#define CLIENT_SOCK "/tmp/*Z|&"   /* :-) */

#ifdef DEBUG
#define DPR(a) fprintf(stderr, a)
#define DPR2(a,b) fprintf(stderr, a, b)
#else
#define DPR(a)
#define DPR2(a,b)
#endif

int serv_sock, recv_sock, cli_sock;

extern int errno;

main(argc, argv)
char *argv[];
{
    char buf[BUFSIZ];
    struct hostent *hp;
    struct servent *sp;
    struct sockaddr_in serv_sin;
    struct sockaddr_in recv_sin;
    struct sockaddr_un cli_sun;

    fd_set readable, copy;
    int funix, cc, repl, nfound;


    if (argc < 2) {
	  printf("Usage: %s server_machine\n", argv[0]);
	  exit(-1);
    }


/* Open a random socket here, using recv_sock, to talk to server */

    

    if ((cli_sock = socket(PF_UNIX, SOCK_DGRAM, 0)) < 0) {
	  printf("client socket failed\n");
	  exit(1);
    }

    /* bind the socket to Unix domain port on the local host */
    cli_sun.sun_family = AF_UNIX;
    strcpy (cli_sun.sun_path, CLIENT_SOCK);

    if (bind(cli_sock, &cli_sun, strlen (cli_sun.sun_path) + 2) < 0) {
	  perror("bind");
	  exit(1);
    }


    sp = getservbyname("zephyr-clt", "udp");
    serv_sin.sin_port = sp->s_port;

    if ((serv_sock = socket(PF_INET, SOCK_DGRAM, 0)) < 0) {
	  printf("server socket failed\n");
	  exit(1);
    }

    DPR2 ("zephyr server port: %u\n", ntohs(serv_sin.sin_port));
    DPR2 ("zephyr client port: %s\n", cli_sun.sun_path);
    
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
    
    sprintf(buf, "This message will be an ident. notice later.\n");

    /* send it off */
    if ((cc = sendto(serv_sock, buf, strlen(buf) + 1,
		     0, &recv_sin, sizeof(recv_sin))) < 0)
      perror("sendto");
    else
      printf("%d bytes sent\n",cc);

    FD_ZERO(&readable);
    FD_SET(serv_sock, &readable);
    FD_SET(cli_sock, &readable);

    do {
	  bcopy(&readable, &copy, sizeof(fd_set));

	  /* Select on this port until response received */
	  if ((repl = recvfrom(serv_sock, buf, sizeof(buf),
			       0, &recv_sin, sizeof(recv_sin))) < 0) {
		perror("recvfrom");
		find_next_server(&hp);
	  }
	  else
	    printf("reply: %s\n",buf);
    } while (repl < 0);

    /* Right at end... */
    unlink(CLIENT_SOCK);
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

client_manager(notice)
ZNotice_t notice;
{
      printf("A notice came in from a client.\n");
}

server_timeout()
{
      perror ("server timed out.\n");
      exit(1);
}

new_server()
{
      perror("server going down.\n");
      exit(1);
}
