/* This file is part of the Project Athena Zephyr Notification System.
 * It contains the main loop of the Zephyr server
 *
 *	Created by:	John T. Kohl
 *
 *	$Source$
 *	$Author$
 *
 *	Copyright (c) 1987,1988,1991 by the Massachusetts Institute of Technology.
 *	For copying and distribution information, see the file
 *	"mit-copyright.h".
 */

#include <zephyr/mit-copyright.h>
#include "zserver.h"
#include <sys/socket.h>
#include <sys/resource.h>

#ifndef lint
#ifndef SABER
static const char rcsid_main_c[] =
    "$Id$";
#endif
#endif

/*
 * Server loop for Zephyr.
 */

/*
  The Zephyr server maintains several linked lists of information.

  There is an array of servers (otherservers) initialized and maintained
  by server_s.c.

  Each server descriptor contains a pointer to a linked list of hosts
  which are ``owned'' by that server.  The first server is the ``limbo''
  server which owns any host which was formerly owned by a dead server.

  Each of these host list entries has an IP address and a pointer to a
  linked list of clients on that host.

  Each client has a sockaddr_in, a list of subscriptions, and possibly
  a session key.

  In addition, the class manager has copies of the pointers to the
  clients which are registered with a particular class, the
  not-yet-acknowledged list has copies of pointers to some clients,
  and the hostm manager may have copies of pointers to some clients
  (if the client has not acknowledged a packet after a given timeout).
*/

static int do_net_setup(void);
static int initialize(void);
static void usage(void);
static void do_reset(void);
static RETSIGTYPE bye(int);
static RETSIGTYPE dbug_on(int);
static RETSIGTYPE dbug_off(int);
static RETSIGTYPE sig_dump_db(int);
static RETSIGTYPE reset(int);
static RETSIGTYPE reap(int);
static void read_from_dump(char *dumpfile);
static void dump_db(void);
static void dump_strings(void);

#ifndef DEBUG
static void detach(void);
#endif

static short doreset = 0;		/* if it becomes 1, perform
					   reset functions */

int nfds;				/* max file descriptor for select() */
int srv_socket;				/* dgram socket for clients
					   and other servers */
int bdump_socket = -1;			/* brain dump socket fd
					   (closed most of the time) */
fd_set interesting;			/* the file descrips we are listening
					   to right now */
struct sockaddr_in srv_addr;		/* address of the socket */

Unacked *nacklist = NULL;		/* list of packets waiting for ack's */

unsigned short hm_port;			/* host manager receiver port */
unsigned short hm_srv_port;		/* host manager server sending port */

char *programname;			/* set to the basename of argv[0] */
char myname[NS_MAXDNAME];		/* my host name */

char list_file[128];
#ifdef HAVE_KRB5
char keytab_file[128];
static char tkt5_file[256];
#endif
#ifdef HAVE_KRB4
char srvtab_file[128];
static char tkt_file[128];
#endif
#if defined(HAVE_KRB4) || defined(HAVE_KRB5)
char my_realm[REALM_SZ];
#endif
char acl_dir[128];
char subs_file[128];

int zdebug;
#ifdef DEBUG
int zalone;
#endif

struct timeval t_local;			/* store current time for other uses */

static int dump_db_flag = 0;
static int dump_strings_flag = 0;

u_long npackets;			/* number of packets processed */
time_t uptime;				/* when we started operations */
static int nofork;
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

int
main(int argc,
     char **argv)
{
    int nfound;			/* #fildes ready on select */
    fd_set readable;
    struct timeval tv;
    int init_from_dump = 0;
    char *dumpfile;
#ifdef _POSIX_VERSION
    struct sigaction action;
#endif
    int optchar;			/* option processing */
    extern char *optarg;
    extern int optind;

    sprintf(list_file, "%s/zephyr/%s", SYSCONFDIR, SERVER_LIST_FILE);
#ifdef HAVE_KRB4
    sprintf(srvtab_file, "%s/zephyr/%s", SYSCONFDIR, ZEPHYR_SRVTAB);
    strcpy(tkt_file, ZEPHYR_TKFILE);
#endif
#ifdef HAVE_KRB5
    sprintf(keytab_file, "%s/zephyr/%s", SYSCONFDIR, ZEPHYR_KEYTAB);
    strcpy(tkt5_file, ZEPHYR_TK5FILE);
#endif
    sprintf(acl_dir, "%s/zephyr/%s", SYSCONFDIR, ZEPHYR_ACL_DIR);
    sprintf(subs_file, "%s/zephyr/%s", SYSCONFDIR, DEFAULT_SUBS_FILE);

    /* set name */
    programname = strrchr(argv[0],'/');
    programname = (programname) ? programname + 1 : argv[0];

    /* process arguments */
    while ((optchar = getopt(argc, argv, "dsnv4f:k:")) != EOF) {
	switch(optchar) {
	  case 'd':
	    zdebug = 1;
	    break;
#ifdef DEBUG
	  case 's':
	    zalone = 1;
	    break;
#endif
	  case 'n':
	    nofork = 1;
	    break;
	  case 'k':
#if defined(HAVE_KRB4) || defined(HAVE_KRB5)
	    strncpy(my_realm, optarg, REALM_SZ);
#endif
	    break;
	  case 'v':
	    bdump_version = optarg;
	    break;
	  case 'f':
	    init_from_dump = 0;
	    dumpfile = optarg;
	    break;
	case '4':
	    bdump_auth_proto = 4;
	    break;
	  case '?':
	  default:
	    usage();
	    /*NOTREACHED*/
	}
    }

#ifdef HAVE_KRB4
    /* if there is no readable srvtab and we are not standalone, there
       is no possible way we can succeed, so we exit */

    if (access(srvtab_file, R_OK)
#ifdef DEBUG
	&& !zalone
#endif /* DEBUG */
	) {
	fprintf(stderr, "NO ZEPHYR SRVTAB (%s) available; exiting\n",
		srvtab_file);
	exit(1);
    }
    /* Use local realm if not specified on command line. */
    if (!*my_realm) {
	if (krb_get_lrealm(my_realm, 1) != KSUCCESS) {
	    fputs("Couldn't get local Kerberos realm; exiting.\n", stderr);
	    exit(1);
	}
    }
#endif /* HAVE_KRB4 */

#ifndef DEBUG
    if (!nofork)
	detach();
#endif /* DEBUG */

    /* open log */
    OPENLOG(programname, LOG_PID, LOG_LOCAL6);

#if defined (DEBUG) && 0
    if (zalone)
	syslog(LOG_DEBUG, "standalone operation");
#endif
    if (zdebug)
	syslog(LOG_DEBUG, "debugging on");

    /* set up sockets & my_addr and myname,
       find other servers and set up server table, initialize queues
       for retransmits, initialize error tables,
       set up restricted classes */

    /* Initialize t_local for other uses */
    gettimeofday(&t_local, NULL);

    if (initialize())
	exit(1);

    if (init_from_dump)
	read_from_dump(dumpfile);

    /* Seed random number set.  */
    srandom(getpid() ^ time(0));

    /* chdir to somewhere where a core dump will survive */
    if (chdir(TEMP_DIRECTORY) != 0)
	syslog(LOG_ERR, "chdir failed (%m) (execution continuing)");

    FD_ZERO(&interesting);
    FD_SET(srv_socket, &interesting);

    nfds = srv_socket + 1;


#ifdef _POSIX_VERSION
    action.sa_flags = 0;
    sigemptyset(&action.sa_mask);

    action.sa_handler = bye;
    sigaction(SIGINT, &action, NULL);
    sigaction(SIGTERM, &action, NULL);

    action.sa_handler = dbug_on;
    sigaction(SIGUSR1, &action, NULL);

    action.sa_handler = dbug_off;
    sigaction(SIGUSR2, &action, NULL);

    action.sa_handler = reap;
    sigaction(SIGCHLD, &action, NULL);

    action.sa_handler = sig_dump_db;
    sigaction(SIGFPE, &action, NULL);

    action.sa_handler = reset;
    sigaction(SIGHUP, &action, NULL);
#else /* !posix */
    signal(SIGINT, bye);
    signal(SIGTERM, bye);
    signal(SIGUSR1, dbug_on);
    signal(SIGUSR2, dbug_off);
    signal(SIGCHLD, reap);
    signal(SIGFPE, sig_dump_db);
    signal(SIGHUP, reset);
#endif /* _POSIX_VERSION */

    syslog(LOG_NOTICE, "Ready for action");

    /* Reinitialize t_local now that initialization is done. */
    gettimeofday(&t_local, NULL);
    uptime = NOW;

    realm_wakeup();

    for (;;) {
	if (doreset)
	    do_reset();

	if (dump_db_flag)
	    dump_db();
	if (dump_strings_flag)
	    dump_strings();

	timer_process();

	readable = interesting;
	if (msgs_queued()) {
	    /* when there is input in the queue, we
	       artificially set up to pick up the input */
	    nfound = 1;
	    FD_ZERO(&readable);
	} else  {
	    nfound = select(nfds, &readable, NULL, NULL, timer_timeout(&tv));
	}

	/* Initialize t_local for other uses */
	gettimeofday(&t_local, (struct timezone *)0);

	/* don't flame about EINTR, since a SIGUSR1 or SIGUSR2
	   can generate it by interrupting the select */
	if (nfound < 0) {
	    if (errno != EINTR)
		syslog(LOG_WARNING, "select error: %m");
	    continue;
	}

	if (nfound == 0) {
	    /* either we timed out or we were just
	       polling for input.  Either way we want to continue
	       the loop, and process the next timeout */
	    continue;
	} else {
	    if (bdump_socket >= 0 && FD_ISSET(bdump_socket,&readable))
		bdump_send();
	    else if (msgs_queued() || FD_ISSET(srv_socket, &readable))
		handle_packet();
	    else
		syslog(LOG_ERR, "select weird?!?!");
	}
    }
}

/* Initialize net stuff.
   Set up the server array.
   Initialize the packet ack queues to be empty.
   Initialize the error tables.
   Restrict certain classes.
   */

static int
initialize(void)
{
    if (do_net_setup())
	return(1);

    server_init();

#ifdef HAVE_KRB4
    krb_set_tkt_string(tkt_file);
#endif
    realm_init();

    ZSetServerState(1);
    ZInitialize();		/* set up the library */
#ifdef HAVE_KRB5
    krb5_cc_resolve(Z_krb5_ctx, tkt5_file, &Z_krb5_ccache);
#ifdef HAVE_KRB5_CC_SET_DEFAULT_NAME
    krb5_cc_set_default_name(Z_krb5_ctx, tkt5_file);
#else
    {
	/* Hack to make krb5_cc_default do something reasonable */
	char *env=(char *)malloc(strlen(tkt5_file)+12);
	if (!env) return(1);
	sprintf(env, "KRB5CCNAME=%s", tkt5_file);
	putenv(env);
    }
#endif
#endif
#if defined(HAVE_KRB4) || defined(HAVE_KRB5)
    /* Override what Zinitialize set for ZGetRealm() */
    if (*my_realm)
      strcpy(__Zephyr_realm, my_realm);
#endif

    /* set up err table */
#if defined(__APPLE__) && defined(__MACH__)
    add_error_table(&et_zsrv_error_table);
#else
    init_zsrv_err_tbl();
#endif

    ZSetFD(srv_socket);		/* set up the socket as the input fildes */

    /* set up default strings */

    class_control = make_string(ZEPHYR_CTL_CLASS, 1);
    class_admin = make_string(ZEPHYR_ADMIN_CLASS, 1);
    class_hm = make_string(HM_CTL_CLASS, 1);
    class_ulogin = make_string(LOGIN_CLASS, 1);
    class_ulocate = make_string(LOCATE_CLASS, 1);
    wildcard_instance = make_string(WILDCARD_INSTANCE, 1);
    empty = make_string("", 0);

    /* restrict certain classes */
    access_init();
    return 0;
}

/*
 * Set up the server and client sockets, and initialize my_addr and myname
 */

static int
do_net_setup(void)
{
    struct servent *sp;
    struct hostent *hp;
    char hostname[NS_MAXDNAME];
    int flags;

    if (gethostname(hostname, sizeof(hostname))) {
	syslog(LOG_ERR, "no hostname: %m");
	return 1;
    }
    hp = gethostbyname(hostname);
    if (!hp || hp->h_addrtype != AF_INET) {
	syslog(LOG_ERR, "no gethostbyname repsonse");
	strncpy(myname, hostname, sizeof(myname));
	return 1;
    }
    strncpy(myname, hp->h_name, sizeof(myname));
    memcpy(&my_addr, hp->h_addr_list[0], hp->h_length);

    setservent(1);		/* keep file/connection open */

    memset(&srv_addr, 0, sizeof(srv_addr));
    srv_addr.sin_family = AF_INET;
    sp = getservbyname(SERVER_SVCNAME, "udp");
    srv_addr.sin_port = (sp) ? sp->s_port : SERVER_SVC_FALLBACK;

    sp = getservbyname(HM_SVCNAME, "udp");
    hm_port = (sp) ? sp->s_port : HM_SVC_FALLBACK;

    sp = getservbyname(HM_SRV_SVCNAME, "udp");
    hm_srv_port = (sp) ? sp->s_port : HM_SRV_SVC_FALLBACK;

    srv_socket = socket(AF_INET, SOCK_DGRAM, 0);
    if (srv_socket < 0) {
	syslog(LOG_ERR, "client_sock failed: %m");
	return 1;
    }
    if (bind(srv_socket, (struct sockaddr *) &srv_addr,
	     sizeof(srv_addr)) < 0) {
	syslog(LOG_ERR, "client bind failed: %m");
	return 1;
    }

    /* set not-blocking */
#ifdef _POSIX_VERSION
    flags = fcntl(srv_socket, F_GETFL);
    flags |= O_NONBLOCK;
    fcntl(srv_socket, F_SETFL, flags);
#else
    flags = 1;
    ioctl(srv_socket, FIONBIO, &flags);
#endif

    return 0;
}


/*
 * print out a usage message.
 */

static void
usage(void)
{
#ifdef DEBUG
	fprintf(stderr, "Usage: %s [-d] [-s] [-n] [-k realm] [-f dumpfile]\n",
		programname);
#else
	fprintf(stderr, "Usage: %s [-d] [-n] [-k realm] [-f dumpfile]\n",
		programname);
#endif /* DEBUG */
	exit(2);
}

int
packets_waiting(void)
{
    fd_set readable, initial;
    struct timeval tv;

    if (msgs_queued())
	return 1;
    FD_ZERO(&initial);
    FD_SET(srv_socket, &initial);
    readable = initial;
    tv.tv_sec = tv.tv_usec = 0;
    return (select(srv_socket + 1, &readable, NULL, NULL, &tv) > 0);
}

static RETSIGTYPE
bye(int sig)
{
    server_shutdown();		/* tell other servers */
#ifdef REALM_MGMT
    realm_shutdown();		/* tell other realms */
#endif
    hostm_shutdown();		/* tell our hosts */
    kill_realm_pids();
#ifdef HAVE_KRB4
    dest_tkt();
#endif
    syslog(LOG_NOTICE, "goodbye (sig %d)", sig);
    exit(0);
}

static RETSIGTYPE
dbug_on(int sig)
{
    syslog(LOG_DEBUG, "debugging turned on");
    zdebug = 1;
}

static RETSIGTYPE
dbug_off(int sig)
{
    syslog(LOG_DEBUG, "debugging turned off");
    zdebug = 0;
}

int fork_for_dump = 0;

static void dump_strings(void)
{
    char filename[128];

    FILE *fp;
    int oerrno = errno;

    sprintf(filename, "%szephyr.strings", TEMP_DIRECTORY);
    fp = fopen (filename, "w");
    if (!fp) {
	syslog(LOG_ERR, "can't open strings dump file: %m");
	errno = oerrno;
	dump_strings_flag = 0;
	return;
    }
    syslog(LOG_INFO, "dumping strings to disk");
    print_string_table(fp);
    if (fclose(fp) == EOF)
	syslog(LOG_ERR, "error writing strings dump file");
    else
	syslog(LOG_INFO, "dump done");
    oerrno = errno;
    dump_strings_flag = 0;
    return;
}

static RETSIGTYPE
sig_dump_db(int sig)
{
    dump_db_flag = 1;
}

static void
dump_db(void)
{
    /* dump the in-core database to human-readable form on disk */
    FILE *fp;
    int oerrno = errno;
    int pid;
    char filename[128];

    pid = (fork_for_dump) ? fork() : -1;
    if (pid > 0) {
	dump_db_flag = 0;
	return;
    }
    sprintf(filename, "%szephyr.db", TEMP_DIRECTORY);
    fp = fopen(filename, "w");
    if (!fp) {
	syslog(LOG_ERR, "can't open dump database");
	errno = oerrno;
	dump_db_flag = 0;
	return;
    }
    syslog(LOG_INFO, "dumping to disk");
    server_dump_servers(fp);
    uloc_dump_locs(fp);
    client_dump_clients(fp);
    triplet_dump_subs(fp);
    realm_dump_realms(fp);
    syslog(LOG_INFO, "dump done");
    if (fclose(fp) == EOF)
	syslog(LOG_ERR, "can't close dump db");
    if (pid == 0)
	exit(0);
    errno = oerrno;
    dump_db_flag = 0;
}

static RETSIGTYPE
reset(int sig)
{
    zdbug((LOG_DEBUG,"reset()"));
    doreset = 1;
}

static RETSIGTYPE
reap(int sig)
{
    int pid, i = 0;
    int oerrno = errno;
    ZRealm *rlm;
#ifdef _POSIX_VERSION
    int waitb;
#else
    union wait waitb;
#endif

    zdbug((LOG_DEBUG,"reap()"));
#ifdef _POSIX_VERSION
    while ((pid = waitpid(-1, &waitb, WNOHANG)) == 0)
      { i++; if (i > 10) break; }
#else
    while ((pid = wait3 (&waitb, WNOHANG, (struct rusage*) 0)) == 0)
      { i++; if (i > 10) break; }
#endif

    errno = oerrno;

    if (pid) {
      if (WIFSIGNALED(waitb) == 0) {
	if (WIFEXITED(waitb) != 0) {
	  rlm = realm_get_realm_by_pid(pid);
	  if (rlm) {
	    rlm->child_pid = 0;
	    rlm->have_tkt = 1;
	  }
	}
      } else {
	rlm = realm_get_realm_by_pid(pid);
	if (rlm) {
	  rlm->child_pid = 0;
	}
      }
    }
}

static void
do_reset(void)
{
    int oerrno = errno;
#ifdef _POSIX_VERSION
    sigset_t mask, omask;
#else
    int omask;
#endif
#ifdef _POSIX_VERSION
    sigemptyset(&mask);
    sigaddset(&mask, SIGHUP);
    sigprocmask(SIG_BLOCK, &mask, &omask);
#else
    omask = sigblock(sigmask(SIGHUP));
#endif

    /* reset various things in the server's state */
    subscr_reset();
    server_reset();
    access_reinit();
    syslog(LOG_INFO, "restart completed");
    doreset = 0;
    errno = oerrno;
#ifdef _POSIX_VERSION
    sigprocmask(SIG_SETMASK, &omask, (sigset_t *)0);
#else
    sigsetmask(omask);
#endif
}

#ifndef DEBUG
/*
 * detach from the terminal
 */

static void
detach(void)
{
    /* detach from terminal and fork. */
    int i;
    long size;

#ifdef _POSIX_VERSION
    size = sysconf(_SC_OPEN_MAX);
#else
    size = getdtablesize();
#endif
    /* profiling seems to get confused by fork() */
    i = fork ();
    if (i) {
	if (i < 0)
	    perror("fork");
	exit(0);
    }

    for (i = 0; i < size; i++)
	close(i);

    i = open("/dev/tty", O_RDWR, 666);
#ifdef TIOCNOTTY /* Only necessary on old systems. */
    ioctl(i, TIOCNOTTY, NULL);
#endif
    close(i);
#ifdef _POSIX_VERSION
    setsid();
#endif
}
#endif /* not DEBUG */

static void
read_from_dump(char *dumpfile)
{
    /* Not yet implemented. */
    return;
}

