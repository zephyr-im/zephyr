/* This file is part of the Project Athena Zephyr Notification System.
 * It contains the global variables used by the server.  (moved from main.c)
 *
 *	Created by:	Karl Ramm
 *
 *	Copyright (c) 1987,1988,1991 by the Massachusetts Institute of Technology.
 *	For copying and distribution information, see the file
 *	"mit-copyright.h".
 */

#include <zephyr/mit-copyright.h>
#include "zserver.h"
#include <sys/socket.h>
#include <sys/resource.h>

int nfds;				/* max file descriptor for select() */
int srv_socket;				/* dgram socket for clients
					   and other servers */
int bdump_socket = -1;			/* brain dump socket fd
					   (closed most of the time) */
#ifdef HAVE_ARES
ares_channel achannel;			/* C-ARES resolver channel */
#endif
fd_set interesting;			/* the file descrips we are listening
					   to right now */
struct sockaddr_in srv_addr;		/* address of the socket */

Unacked *nacklist = NULL;		/* list of packets waiting for ack's */

unsigned short hm_port;			/* host manager receiver port */
unsigned short hm_srv_port;		/* host manager server sending port */

char myname[NS_MAXDNAME];		/* my host name */

char list_file[128];
#ifdef HAVE_KRB5
char keytab_file[128];
#endif
#ifdef HAVE_KRB4
char srvtab_file[128];
#endif
char acl_dir[128];
char subs_file[128];

int zdebug;
#ifdef DEBUG
int zalone;
#endif

struct timeval t_local;			/* store current time for other uses */


u_long npackets;			/* number of packets processed */
time_t uptime;				/* when we started operations */
struct in_addr my_addr;
char *bdump_version = "1.2";

#ifdef HAVE_KRB5
int bdump_auth_proto = 5;
#else /* HAVE_KRB5 */
#ifdef HAVE_KRB4
int bdump_auth_proto = 4;
#else /* HAVE_KRB4 */
int bdump_auth_proto = 0;
#endif /* HAVE_KRB4 */
#endif /* HAVE_KRB5 */

#ifdef HAVE_KRB5
krb5_ccache Z_krb5_ccache;
krb5_keyblock *__Zephyr_keyblock;
#else
#ifdef HAVE_KRB4
C_Block __Zephyr_session;
#endif
#endif
