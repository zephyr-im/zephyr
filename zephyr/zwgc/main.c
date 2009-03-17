/* This file is part of the Project Athena Zephyr Notification System.
 * It is one of the source files comprising zwgc, the Zephyr WindowGram
 * client.
 *
 *      Created by:     Marc Horowitz <marc@athena.mit.edu>
 *
 *      $Id$
 *
 *      Copyright (c) 1989 by the Massachusetts Institute of Technology.
 *      For copying and distribution information, see the file
 *      "mit-copyright.h".
 */

#include <sysdep.h>
#ifdef HAVE_ARES
#include <ares.h>
#endif

#if (!defined(lint) && !defined(SABER))
static const char rcsid_main_c[] = "$Id$";
#endif

#include <netdb.h>
#include <sys/socket.h>
#include <sys/resource.h>
#include <zephyr/mit-copyright.h>
#include <zephyr/zephyr.h>

#include "new_memory.h"
#include "zwgc.h"
#include "parser.h"
#include "node.h"
#include "exec.h"
#include "zephyr.h"
#include "notice.h"
#include "subscriptions.h"
#include "file.h"
#include "mux.h"
#include "port.h"
#include "variables.h"
#include "main.h"
#ifdef CMU_ZCTL_PUNT
#include "int_dictionary.h"
#endif
#ifdef CMU_ZWGCPLUS
#include "plus.h"
int zwgcplus = 0;
#endif

void notice_handler(ZNotice_t *);
static void process_notice(ZNotice_t *, char *);
static void setup_signals(int);
static void detach(void);
static void signal_exit(int);
#ifdef HAVE_ARES
static void notice_callback(void *, int, int, struct hostent *);
#endif
#ifdef CMU_ZWGCPLUS
void reprocess_notice(ZNotice_t *notice, char *hostname);
#endif

/*
 * Global zwgc-wide variables:
 */

#ifdef DEBUG
int zwgc_debug = 0;
#endif

static char *zwgc_version_string = "1.0";

/*
 * description_filename_override - <<<>>>
 */

static char *description_filename_override = NULL;

/*
 * progname - <<<>>> export!
 */

char *progname = NULL;

/*
 * subscriptions_filename_override - <<<>>> export!
 */

char *subscriptions_filename_override = NULL;

/*
 * location_override - <<<>>> export!
 */

char *location_override = NULL;

#ifdef HAVE_ARES
/*
 * achannel - <<<>>> export!
 */

ares_channel achannel;
#endif

/****************************************************************************/
/*                                                                          */
/*             Code to deal with reading in the description file:           */
/*                                                                          */
/****************************************************************************/

/*
 * program - this holds a pointer to the node representation of the
 *           description file once it has been read in.
 */

static struct _Node *program = NULL;

/*
 * <<<>>>
 */

static void
fake_startup_packet(void)
{
    ZNotice_t *notice = (ZNotice_t *)malloc(sizeof(ZNotice_t));
    struct timezone tz;
    char msgbuf[BUFSIZ];
    extern void Z_gettimeofday(struct _ZTimeval *, struct timezone *);

    var_set_variable("version", zwgc_version_string);

    (void) memset(notice, 0, sizeof(ZNotice_t));

    notice->z_version = "";
    notice->z_class = "WG_CTL_CLASS";
    notice->z_class_inst = "WG_CTL_USER<<<>>>";
    notice->z_opcode = "WG_STARTUP";
    notice->z_default_format = "Zwgc mark II version $version now running...\n";
    notice->z_recipient = "";
    notice->z_sender = "ZWGC";
    Z_gettimeofday(&notice->z_time, &tz);
    notice->z_port = 0;
    notice->z_kind = ACKED;
    notice->z_auth = ZAUTH_YES;
    notice->z_charset = ZCHARSET_UNKNOWN;
    sprintf(msgbuf,"Zwgc mark II version %s now running...",
	    zwgc_version_string);
    notice->z_message = msgbuf;
    notice->z_message_len = strlen(notice->z_message)+1;
    
#ifdef CMU_ZWGCPLUS
    list_add_notice(notice);
    set_notice_fake(notice, 1);
#endif
    process_notice(notice, NULL);
#ifdef CMU_ZWGCPLUS
    list_del_notice(notice);
#else
    free(notice);
#endif
}

static void
read_in_description_file(void)
{
    FILE *input_file;
    char defdesc[128];

/*    var_clear_all_variables(); <<<>>> */

    sprintf(defdesc, "%s/zephyr/%s", DATADIR, DEFDESC);
    input_file = locate_file(description_filename_override, USRDESC, defdesc);
    if (input_file)
      program = parse_file(input_file);
    else
      program = NULL;
    
    fake_startup_packet();
}

/****************************************************************************/
/*                                                                          */
/*            Code to deal with argument parsing & overall control:         */
/*                                                                          */
/****************************************************************************/

/*
 *    void usage()
 *        Effects: Prints out an usage message on stderr then exits the
 *                 program with error code 1.
 */

void
usage(void)
{
#ifdef DEBUG
    fprintf(stderr, "\
zwgc: usage: zwgc [-debug] [-f <filename>] [-subfile <filename>]\n\
                  [-ttymode] [-nofork] [-reenter] [-loc text]\n\
                  [-default <driver>] {-disable <driver>}*\n\
                  [output driver options]\n");
#else
    fprintf(stderr, "\
zwgc: usage: zwgc [-f <filename>] [-subfile <filename>]\n\
                  [-ttymode] [-nofork] [-reenter] [-loc text]\n\
                  [-default <driver>] {-disable <driver>}*\n\
                  [output driver options]\n");
#endif
    exit(1);
}

/*
 * <<<>>>
 */

static void
run_initprogs(void)
{
    /*
     * This code stolen from old zwgc: yuck.  Clean up & fix.  <<<>>>
     * Should this fork instead of just systeming?
     */

    int status;
    char *progname = ZGetVariable("initprogs");
    
    if (!progname)
      return;
    
    status = system(progname);
    if (status == 127) {
	perror("zwgc initprog exec");
	fprintf(stderr,"zwgc initprog of <%s> failed: no shell.\n",
		progname);
    } else if (status!=-1 && status>>8) {
	perror("zwgc initprog exec");
	fprintf(stderr,"zwgc initprog of <%s> failed with status [%d].\n",
		progname, status>>8);
    }
}

/*
 * main -- the program entry point.  Does parsing & top level control.
 */

int
main(int argc,
     char **argv)
{
    char **new;
    register char **current;
    int dofork = 1;
#ifdef HAVE_ARES
    int status;
#endif

    progname = argv[0];

    /*
     * Process "-f <filename>", "-subfile <filename>", "-nofork",
     * "-reenter" (which is ignored) and (if DEBUG) "-debug"
     * arguments, removing then from argc, argv:
     */
    for (new=current=argv+1; *current; current++) {
	if (string_Eq(*current, "-debug")) {
	    argc--;
#ifdef DEBUG
	    zwgc_debug = 1;
#endif
	} else if (string_Eq(*current, "-f")) {
	    argc -= 2; current++;
	    if (!*current)
	      usage();
	    description_filename_override = *current;
	} else if (string_Eq(*current, "-subfile")) {
	    argc -= 2; current++;
	    if (!*current)
	      usage();
	    subscriptions_filename_override = *current;
	} else if (string_Eq(*current, "-nofork")) {
	    argc--;
	    dofork = 0;
	} else if (string_Eq(*current, "-reenter")) {
	    argc--;			/* just throw it away */
	} else if (string_Eq(*current, "-loc")) {
	    argc -= 2; current++;
	    if (!*current)
	      usage();
	    location_override = *current;
	} else
	  *(new)++ = *current;
    }
    *new = *current;

#ifdef HAVE_ARES
    /*
     * Initialize resolver library
     */
    status = ares_init(&achannel);
    if (status != ARES_SUCCESS) {
	fprintf(stderr, "Couldn't initialize resolver: %s\n",
		ares_strerror(status));
	return(1);
    }
#endif

    /*
     * Initialize various subsystems in proper order:
     */
    dprintf("Initializing subsystems...\n"); /*<<<>>>*/
#ifdef CMU_ZWGCPLUS
    init_noticelist();
#endif
    mux_init();
    var_clear_all_variables(); /* <<<>>> */
    init_ports();       /* <<<>>> */
    dprintf("Initializing standard ports...\n");
    init_standard_ports(&argc, argv);
    if (argc>1)
      usage();
    dprintf("Initializing zephyr...\n");
    setup_signals(dofork);
    zephyr_init(notice_handler);

    if (dofork)
	detach();
    /*
     * Run the initprogs program(s) now that we are all set to deal:
     */
    dprintf("Running initprogs program...\n");
    run_initprogs();

    dprintf("Test Zwgc parser.\n\n");
    read_in_description_file();

#ifdef CMU_ZWGCPLUS
    if (strcmp(progname, "zwgcplus") == 0)
      zwgcplus = 1;
#endif

    dprintf("Entering main loop\n");
    mux_loop();

    dprintf("Returning from main loop\n");
    finalize_zephyr();

    return(0);
}

/****************************************************************************/
/*                                                                          */
/*               :               */
/*                                                                          */
/****************************************************************************/

#define  USER_SUPPRESS     "SUPPRESS"
#define  USER_UNSUPPRESS   "UNSUPPRESS"

#ifdef CMU_ZCTL_PUNT
#define  USER_LIST_SUPPRESSED "LIST-SUPPRESSED"

#define PUNT_INC 1024
extern int_dictionary puntable_addresses_dict;
ZNotice_t punt_reply;

void
create_punt_reply(int_dictionary_binding *punt)
{
    string binding;
    int key_len = strlen(punt->key);
    char *tmp;
    
    if (!punt_reply.z_message) {
	punt_reply.z_message = (char *)malloc(PUNT_INC);
	punt_reply.z_message[0] = 0;
    }
    
    if ((punt_reply.z_message_len + key_len + 1) / PUNT_INC > 
	(punt_reply.z_message_len + PUNT_INC - 1) / PUNT_INC) {
	char *new_message = (char *)malloc((punt_reply.z_message_len
					    / PUNT_INC + 1) * PUNT_INC);
	
	strcpy(new_message, punt_reply.z_message);
	
	free(punt_reply.z_message);
	punt_reply.z_message = new_message;
    }
    tmp = punt_reply.z_message + strlen(punt_reply.z_message);
    strcat (punt_reply.z_message, punt->key);
    strcat (punt_reply.z_message, "\n");
    punt_reply.z_message_len += key_len + 1;
    
    while (*tmp != '\001') tmp++;
    *tmp = ',';
    while (*tmp != '\001') tmp++;
    *tmp = ',';
}
#endif /* CMU_ZCTL_PUNT */

void
notice_handler(ZNotice_t *notice)
{
    struct hostent *fromhost = NULL;

#if defined(CMU_ZWGCPLUS)
    list_add_notice(notice);
#endif

    if (notice->z_sender_addr.s_addr) {
#ifdef HAVE_ARES
	ares_gethostbyaddr(achannel, &(notice->z_sender_addr),
			   sizeof(notice->z_sender_addr), AF_INET,
			   notice_callback, notice);
	return;
#else
	fromhost = gethostbyaddr((char *) &(notice->z_sender_addr),
				 sizeof(struct in_addr), AF_INET);
#endif
    }
    process_notice(notice, fromhost ? fromhost->h_name : NULL);
#ifdef CMU_ZWGCPLUS
    /* Let list_del_notice clean up for us. */
#else
    ZFreeNotice(notice);
    free(notice);
#endif
}

#ifdef HAVE_ARES
static void
notice_callback(void *arg,
		int status,
		int timeouts,
		struct hostent *fromhost)
{
    ZNotice_t *notice = (ZNotice_t *) arg;

#ifdef CMU_ZWGCPLUS
    plus_set_hname(notice, fromhost ? fromhost->h_name : NULL);
#endif

    process_notice(notice, fromhost ? fromhost->h_name : NULL);
#ifdef CMU_ZWGCPLUS
    list_del_notice(notice);
#else
    ZFreeNotice(notice);
    free(notice);
#endif
}
#endif

static void
process_notice(ZNotice_t *notice,
	       char *hostname)
{
    char *control_opcode;

    dprintf("Got a message\n");

    control_opcode = decode_notice(notice, hostname);
    if (control_opcode) {
#ifdef DEBUG
	printf("got control opcode <%s>.\n", control_opcode);
#endif
	if (!strcasecmp(control_opcode, USER_REREAD)) {
	    read_in_description_file();
	} else if (!strcasecmp(control_opcode, USER_SHUTDOWN))
	  zwgc_shutdown();
	else if (!strcasecmp(control_opcode, USER_STARTUP)) {
#ifdef DEBUG_MEMORY
	    report_memory_usage(); /* <<<>>> */
#endif
	    zwgc_startup();
	} else if (!strcasecmp(control_opcode, USER_SUPPRESS)) {
	    string class = get_field(notice->z_message,
				     notice->z_message_len, 1);
	    string instance = get_field(notice->z_message,
					notice->z_message_len, 2);
	    string recipient = get_field(notice->z_message,
					 notice->z_message_len, 3);
	    punt(class, instance, recipient);
	    free(class);
	    free(instance);
	    free(recipient);
	} else if (!strcasecmp(control_opcode, USER_UNSUPPRESS)) {
	    string class = get_field(notice->z_message,
				     notice->z_message_len, 1);
	    string instance = get_field(notice->z_message,
					notice->z_message_len, 2);
	    string recipient = get_field(notice->z_message,
					 notice->z_message_len, 3);
	    unpunt(class, instance, recipient);
	    free(class);
	    free(instance);
	    free(recipient);
#ifdef CMU_ZCTL_PUNT
        } else if (!strcasecmp(control_opcode, USER_LIST_SUPPRESSED)) {
	    struct sockaddr_in old, to;
	    int retval;
	    
	    if (!notice->z_port) {
		printf("zwgc: can't reply to LIST-SUPPRESSED request\n");
		return;
	    }
	    memset((char *) &punt_reply, 0, sizeof(ZNotice_t));
	    punt_reply.z_kind = CLIENTACK;
	    punt_reply.z_class = WG_CTL_CLASS;
	    punt_reply.z_class_inst = "WG_REPLY";
	    punt_reply.z_recipient = "zctl?";
	    punt_reply.z_sender = "Zwgc";
	    punt_reply.z_default_format = "";
	    punt_reply.z_opcode = USER_LIST_SUPPRESSED;
	    punt_reply.z_port = notice->z_port;
	    punt_reply.z_message = NULL;
	    punt_reply.z_message_len = 0;
	    
	    if (puntable_addresses_dict) {
		int_dictionary_Enumerate(puntable_addresses_dict,
					 create_punt_reply);
	    }
	    
	    old = ZGetDestAddr();
	    to = old;
	    
	    to.sin_port = notice->z_port;
	    if ((retval = ZSetDestAddr(&to)) != ZERR_NONE) {
		com_err("zwgc",retval,"while setting destination address");
		exit(1);
	    }
	    
	    ZSendNotice(&punt_reply, ZNOAUTH);
	    
	    if ((retval = ZSetDestAddr(&old)) != ZERR_NONE) {
		com_err("zwgc",retval,"while resetting destination address");
		exit(1);
	    }
	    
	    if (punt_reply.z_message) {
		free(punt_reply.z_message);
		punt_reply.z_message = NULL;
	    }
#endif
	} else if (!strcasecmp(control_opcode, USER_EXIT)) {
	    signal_exit(0);
	} else
	  printf("zwgc: unknown control opcode %s.\n", control_opcode);

	goto cleanup;
    }

    if (!zwgc_active) {
#ifdef DEBUG
	if (zwgc_debug)
	  printf("NON-ACTIVE: PUNTED <%s>!!!!\n", notice->z_class_inst);
#endif
	goto cleanup;	
    }
    
    if (puntable_address_p(notice->z_class,
			   notice->z_class_inst,
			   notice->z_recipient)) {
#ifdef DEBUG
	if (zwgc_debug)
	  printf("PUNTED <%s>!!!!\n", notice->z_class_inst);
#endif
	goto cleanup;
    }

    exec_process_packet(program, notice);
  cleanup:
    return;
}

#ifdef CMU_ZWGCPLUS
void reprocess_notice(ZNotice_t *notice,
		      char *hostname)
{
  list_add_notice(notice);
  process_notice(notice, hostname);
  list_del_notice(notice);
}
#endif

/***************************************************************************/

/*
 *
 */

static void
signal_exit(int ignored)
{
    mux_end_loop_p = 1;
}

/* clean up ALL the waiting children, in case we get hit with
   multiple SIGCHLD's at once, and don't process in time. */
static RETSIGTYPE
signal_child(int ignored)
{
#ifdef HAVE_WAITPID
  int status;
#else
  union wait status;
#endif
  int pid, old_errno = errno;

  do {
#ifdef HAVE_WAITPID
      pid = waitpid(-1, &status, WNOHANG);
#else
      pid = wait3(&status, WNOHANG, (struct rusage *)0);
#endif
  } while (pid != 0 && pid != -1);
  errno = old_errno;
}

/* rewrite the wgfile in case it has gone away */
static RETSIGTYPE
signal_usr1(int ignored)
{
    write_wgfile();
}

static void
setup_signals(int dofork)
{
#ifdef _POSIX_VERSION
    struct sigaction sa;

    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    
    if (dofork) {
	sa.sa_handler = SIG_IGN;
	sigaction(SIGINT, &sa, (struct sigaction *)0);
	sigaction(SIGTSTP, &sa, (struct sigaction *)0);
	sigaction(SIGQUIT, &sa, (struct sigaction *)0);
	sigaction(SIGTTOU, &sa, (struct sigaction *)0);
    } else {
	/* clean up on SIGINT; exiting on logout is the user's problem, now. */
	sa.sa_handler = signal_exit;
	sigaction(SIGINT, &sa, (struct sigaction *)0);
    }

    /* behavior never changes */
    sa.sa_handler = signal_exit;
    sigaction(SIGTERM, &sa, (struct sigaction *)0);
    sigaction(SIGHUP, &sa, (struct sigaction *)0);

    sa.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &sa, (struct sigaction *)0);

    sa.sa_handler = signal_child;
    sigaction(SIGCHLD, &sa, (struct sigaction *)0);

    sa.sa_handler = signal_usr1;
    sigaction(SIGUSR1, &sa, (struct sigaction *)0);

#else /* !POSIX */
    if (dofork) {
	/* Ignore keyboard signals if forking.  Bad things will happen. */
	signal(SIGINT, SIG_IGN);
	signal(SIGTSTP, SIG_IGN);
	signal(SIGTTOU, SIG_IGN);
	signal(SIGQUIT, SIG_IGN);
    } else {
	/* clean up on SIGINT; exiting on logout is the user's problem, now. */
	signal(SIGINT, signal_exit);
    }
    
    /* behavior never changes */
    signal(SIGTERM, signal_exit);
    signal(SIGHUP, signal_exit);
    signal(SIGCHLD, signal_child);
    signal(SIGPIPE, SIG_IGN);		/* so that Xlib gets an error */
    signal(SIGUSR1, signal_usr1);
#endif
}

/* detach() taken from old zwgc, with lots of stuff ripped out */

static void
detach(void)
{
  /* detach from terminal and fork. */
  register int i;

  /* Attempt to join the process group of the session leader.  This
   * will get us a HUP if the session leader is in the foreground at
   * logout time (which is often the case) or if the shell is running
   * under telnetd or xterm (both of which HUP the process group of
   * their child process).  If we have getsid(), that's the best way
   * of finding the session leader; otherwise use the process group of
   * the parent process, which is a good guess. */
#if defined(HAVE_GETSID)

  setpgid(0, getsid(0));
#elif defined(HAVE_GETPGID)
  setpgid(0, getpgid(getppid()));
#elif !defined(GETPGRP_VOID)
  setpgid(0, getpgrp(getppid()));
#endif

  /* fork off and let parent exit... */
  i = fork();
  if (i) {
      if (i < 0) {
	  perror("zwgc: cannot fork, aborting:");
	  exit(1);
      }
      exit(0);
  }
}	
