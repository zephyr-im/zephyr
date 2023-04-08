/* This file is part of the Project Athena Zephyr Notification System.
 * It contains the zstat program.
 *
 *      Created by:     David C. Jedlinsky
 *
 *      $Id$
 *
 *      Copyright (c) 1987,1988 by the Massachusetts Institute of Technology.
 *      For copying and distribution information, see the file
 *      "mit-copyright.h".
 */

/* There should be library interfaces for the operations in zstat; for now,
 * however, zstat is more or less internal to the Zephyr system. */
#include <internal.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include "zserver.h"

#if !defined(lint) && !defined(SABER)
static const char rcsid_zstat_c[] = "$Id$";
#endif

const char *hm_head[] = {
    "Current server =",
    "Items in queue:",
    "Client packets received:",
    "Server packets received:",
    "Server changes:",
    "Version:",
    "Looking for a new server:",
    "Time running:",
    "Size:",
    "Machine type:",
    "External IP:",
    "UPnP IGD Root URL:",
};
#define	HM_SIZE	(sizeof(hm_head) / sizeof (char *))
const char *srv_head[] = {
    "Current server version =",
    "Packets handled:",
    "Uptime:",
    "Server states:",
};
#define	SRV_SIZE	(sizeof(srv_head) / sizeof (char *))

int outoftime = 0;

int serveronly = 0,hmonly = 0;
u_short srv_port;

void usage(char *);
void do_stat(char *);
int srv_stat(char *);
int hm_stat(char *, char *);

static RETSIGTYPE
timeout(int ignored)
{
	outoftime = 1;
}

int
main(int argc,
     char *argv[])
{
	Code_t ret;
	char hostname[NS_MAXDNAME];
	int optchar;
	struct servent *sp;

	if ((ret = ZInitialize()) != ZERR_NONE) {
		com_err("zstat", ret, "initializing");
		exit(-1);
	}

	if ((ret = ZOpenPort((u_short *)0)) != ZERR_NONE) {
		com_err("zstat", ret, "opening port");
		exit(-1);
	}

	while ((optchar = getopt(argc, argv, "sh")) != EOF) {
		switch(optchar) {
		case 's':
			serveronly++;
			break;
		case 'h':
			hmonly++;
			break;
		case '?':
		default:
			usage(argv[0]);
			exit(1);
		}
	}

	if (serveronly && hmonly) {
		fprintf(stderr,"Only one of -s and -h may be specified\n");
		exit(1);
	}

	sp = getservbyname(SERVER_SVCNAME,"udp");
	srv_port = (sp) ? sp->s_port : SERVER_SVC_FALLBACK;

	if (optind == argc) {
		do_stat("127.0.0.1");
		exit(0);
	}

	for (;optind<argc;optind++)
		do_stat(argv[optind]);

	exit(0);
}

void
do_stat(char *host)
{
	char srv_host[NS_MAXDNAME];

	if (serveronly) {
		(void) srv_stat(host);
		return;
	}

	if (hm_stat(host,srv_host))
		return;

	if (!hmonly)
		(void) srv_stat(srv_host);
}

int
hm_stat(char *host,
	char *server)
{
	struct in_addr inaddr;
	Code_t code;

	char *line[20],*mp;
	unsigned int i,nf;
	struct hostent *hp;
	time_t runtime;
	struct tm *tim;
	ZNotice_t notice;

	if ((inaddr.s_addr = inet_addr(host)) == (unsigned)(-1)) {
	    if ((hp = gethostbyname(host)) == NULL) {
		fprintf(stderr,"Unknown host: %s\n",host);
		exit(-1);
	    }
	    (void) memcpy((char *) &inaddr, hp->h_addr, hp->h_length);

	    printf("Hostmanager stats: %s\n", hp->h_name);
	} else {
	    printf("Hostmanager stats: %s\n", host);
	}

	if ((code = ZhmStat(&inaddr, &notice)) != ZERR_NONE) {
	    com_err("zstat", code, "getting hostmanager status");
	    exit(-1);
	}

	mp = notice.z_message;
	for (nf=0;mp<notice.z_message+notice.z_message_len;nf++) {
		line[nf] = mp;
		mp += strlen(mp)+1;
	}

	(void) strcpy(server,line[0]);

	printf("HostManager protocol version = %s\n",notice.z_version);

	for (i=0; (i < nf) && (i < HM_SIZE); i++) {
		if (!strncmp("Time",hm_head[i],4)) {
			runtime = atol(line[i]);
			tim = gmtime(&runtime);
			printf("%s %d days, %02d:%02d:%02d\n", hm_head[i],
				tim->tm_yday,
				tim->tm_hour,
				tim->tm_min,
				tim->tm_sec);
		}
		else
			printf("%s %s\n",hm_head[i],line[i]);
	}

	printf("\n");

	ZFreeNotice(&notice);
	return(0);
}

int
srv_stat(char *host)
{
	char *line[20],*mp;
	int sock,i,nf,ret;
	struct hostent *hp;
	struct sockaddr_in sin;
	ZNotice_t notice;
	time_t runtime;
	struct tm *tim;
#ifdef _POSIX_VERSION
	struct sigaction sa;
#endif

	(void) memset((char *) &sin, 0, sizeof(struct sockaddr_in));

	sin.sin_port = srv_port;

	if ((sock = socket(PF_INET, SOCK_DGRAM, 0)) < 0) {
		perror("socket:");
		exit(-1);
	}

	sin.sin_family = AF_INET;

	if ((sin.sin_addr.s_addr = inet_addr(host)) == (unsigned)(-1)) {
	    if ((hp = gethostbyname(host)) == NULL) {
		fprintf(stderr,"Unknown host: %s\n",host);
		exit(-1);
	    }
	    (void) memcpy((char *) &sin.sin_addr, hp->h_addr, hp->h_length);

	    printf("Server stats: %s\n", hp->h_name);
	} else {
	    printf("Server stats: %s\n", host);
	}

	(void) memset((char *)&notice, 0, sizeof(notice));
	notice.z_kind = UNSAFE;
	notice.z_port = 0;
	notice.z_charset = ZCHARSET_UNKNOWN;
	notice.z_class = ZEPHYR_ADMIN_CLASS;
	notice.z_class_inst = "";
	notice.z_opcode = ADMIN_STATUS;
	notice.z_sender = "";
	notice.z_recipient = "";
	notice.z_default_format = "";
	notice.z_message_len = 0;

	if ((ret = ZSetDestAddr(&sin)) != ZERR_NONE) {
		com_err("zstat", ret, "setting destination");
		exit(-1);
	}
	if ((ret = ZSendNotice(&notice, ZNOAUTH)) != ZERR_NONE) {
		com_err("zstat", ret, "sending notice");
		exit(-1);
	}

#ifdef _POSIX_VERSION
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	sa.sa_handler = timeout;
	(void) sigaction(SIGALRM, &sa, (struct sigaction *)0);
#else
	(void) signal(SIGALRM,timeout);
#endif
	outoftime = 0;
	(void) alarm(10);
	if (((ret = ZReceiveNotice(&notice, (struct sockaddr_in *) 0))
	    != ZERR_NONE) &&
	    ret != EINTR) {
		com_err("zstat", ret, "receiving notice");
		return (1);
	}
	(void) alarm(0);
	if (outoftime) {
		fprintf(stderr,"No response after 10 seconds.\n");
		return (1);
	}

	mp = notice.z_message;
	for (nf=0;mp<notice.z_message+notice.z_message_len;nf++) {
		line[nf] = mp;
		mp += strlen(mp)+1;
	}

	printf("Server protocol version = %s\n",notice.z_version);

	for (i=0; i < nf; i++) {
		if (i < 2)
			printf("%s %s\n",srv_head[i],line[i]);
		else if (i == 2) { /* uptime field */
			runtime = atol(line[i]);
			tim = gmtime(&runtime);
			printf("%s %d days, %02d:%02d:%02d\n",
			       srv_head[i],
			       tim->tm_yday,
			       tim->tm_hour,
			       tim->tm_min,
			       tim->tm_sec);
		} else if (i == 3) {
			printf("%s\n",srv_head[i]);
			printf("%s\n",line[i]);
		} else printf("%s\n",line[i]);
	}
	printf("\n");

	(void) close(sock);
	ZFreeNotice(&notice);
	return(0);
}

void
usage(char *s)
{
	fprintf(stderr,"usage: %s [-s] [-h] [host ...]\n",s);
	exit(1);
}
