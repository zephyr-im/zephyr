/* This file is part of the Project Athena Zephyr Notification System.
 * It contains code for the "zctl" command.
 *
 *	Created by:	Robert French
 *
 *	$Id$
 *
 *	Copyright (c) 1987,1988 by the Massachusetts Institute of Technology.
 *	For copying and distribution information, see the file
 *	"mit-copyright.h".
 */

#include <sysdep.h>
#include <zephyr/zephyr.h>
#ifdef HAVE_SS
#include <ss/ss.h>
#endif
#include <pwd.h>
#include <netdb.h>
#include <arpa/nameser.h>
#ifndef lint
static const char rcsid_zctl_c[] = "$Id$";
#endif

#define SUBSATONCE 7
#define SUB 0
#define UNSUB 1
#define LIST 2

#define USERS_SUBS "/.zephyr.subs"
#define OLD_SUBS "/.subscriptions"

#define	TOKEN_HOSTNAME	"%host%"
#define	TOKEN_CANONNAME	"%canon%"
#define	TOKEN_ME	"%me%"
#define	TOKEN_WILD	"*"

#define	ALL		0
#define	UNSUBONLY	1
#define	SUBONLY		2

#define	ERR		(-1)
#define	NOT_REMOVED	0
#define	REMOVED		1

#ifdef HAVE_SS
int sci_idx;
#endif
char subsname[BUFSIZ];
char ourhost[NS_MAXDNAME], ourhostcanon[NS_MAXDNAME];

#ifdef HAVE_SS
extern ss_request_table zctl_cmds;
#endif

int purge_subs(register ZSubscription_t *, int);
void add_file(short, ZSubscription_t *, int);
void del_file(short, ZSubscription_t *, int);
void fix_macros(ZSubscription_t *, ZSubscription_t *, int);
void fix_macros2(char *, char **);
int make_exist(char *);
char *whoami;

#ifndef HAVE_SS
static void run_command(int, char *[]);
static void show_commands(int, char *[]);
#endif

/* Prototype all of the commands.
 * These really should be in a header also visible to zctl_cmds.c,
 * but mk_cmds doesn't make that easy.
 */
void cancel_subs(int argc, char *argv[]);
void current(int argc, char *argv[]);
void do_hide(int argc, char *argv[]);
void do_punt(int argc, char *argv[]);
void flush_locations(int argc, char *argv[]);
void flush_subscr(int argc, char *argv[]);
void hm_control(int argc, char *argv[]);
void list_punts(int argc, char *argv[]);
void load_subs(int argc, char *argv[]);
void set_file(int argc, char *argv[]);
void set_var(int argc, char *argv[]);
void show_var(int argc, char *argv[]);
void sub_file(int argc, char *argv[]);
void subscribe(int argc, char *argv[]);
void unset_var(int argc, char *argv[]);
void wgc_control(int argc, char *argv[]);


int
main(int argc,
     char *argv[])
{
	struct passwd *pwd;
	struct hostent *hent;
	char ssline[BUFSIZ],oldsubsname[BUFSIZ],*envptr,*tty = NULL;
	int retval,code,i;
#ifdef HAVE_SYS_UTSNAME
	struct utsname name;
#endif

	whoami = argv[0];
	if ((retval = ZInitialize()) != ZERR_NONE) {
		com_err(argv[0],retval,"while initializing");
		exit (1);
	}

	/* Set hostname and tty for locations.  If we support X, use the
	 * DISPLAY environment variable for the tty name. */
#ifndef X_DISPLAY_MISSING
	tty = getenv("DISPLAY");
#endif
	if ((retval = ZInitLocationInfo(NULL, tty)) != ZERR_NONE)
	    com_err(argv[0], retval, "initializing location information");

	envptr = getenv("ZEPHYR_SUBS");
	if (envptr)
		strcpy(subsname,envptr);
	else {
		envptr = getenv("HOME");
		if (envptr)
			strcpy(subsname,envptr);
		else {
			if (!(pwd = getpwuid((int) getuid()))) {
				fprintf(stderr,"Who are you?\n");
				exit (1);
			}

			strcpy(subsname,pwd->pw_dir);
		}
		strcpy(oldsubsname,subsname);
		strcat(oldsubsname,OLD_SUBS);
		strcat(subsname,USERS_SUBS);
		if (!access(oldsubsname,F_OK) && access(subsname, F_OK)) {
			/* only if old one exists and new one does not exist */
			printf("The .subscriptions file in your home directory is now being used as\n.zephyr.subs . I will rename it to .zephyr.subs for you.\n");
			if (rename(oldsubsname,subsname))
				com_err(argv[0], errno, "renaming .subscriptions");
		}
	}

#ifdef HAVE_SYS_UTSNAME
	uname(&name);
	strcpy(ourhost, name.nodename);
#else
	if (gethostname(ourhost, sizeof(ourhost)) == -1) {
		com_err(argv[0],errno,"while getting host name");
		exit (1);
	}
#endif

	if (!(hent = gethostbyname(ourhost))) {
		fprintf(stderr,"%s: Can't resolve hostname %s; %s may be "
			"wrong in subscriptions\n",argv[0],ourhost,
			TOKEN_CANONNAME);
		strncpy(ourhostcanon,ourhost,sizeof(ourhostcanon)-1);
	} else
		strncpy(ourhostcanon,hent->h_name,sizeof(ourhostcanon)-1);

#ifdef HAVE_SS
	sci_idx = ss_create_invocation("zctl","",0,&zctl_cmds,&code);
	if (code) {
		ss_perror(sci_idx,code,"while creating invocation");
		exit(1);
#else
	if (argc <= 1) {
	    printf("ZCTL $Revision$ (Protocol %s%d.%d)\nType '%s help' for a list of subcommands.\n\n",
		   ZVERSIONHDR,
		   ZVERSIONMAJOR,ZVERSIONMINOR,
		   argv[0]);
	    exit(0);
#endif
	}

#ifdef HAVE_SS
	if (argc > 1) {
		*ssline = '\0';
		for (i=1;i<argc;i++)
			(void) sprintf(ssline+strlen(ssline),"%s ",argv[i]);
		ssline[strlen(ssline)-1] = '\0';
		code = ss_execute_line(sci_idx,ssline);
		if (code)
		    fprintf (stderr, "%s: %s: %s\n",
			     argv[0], error_message (code), ssline);
		ZClosePort();
		exit((code != 0));
	}

	printf("ZCTL $Revision$ (Protocol %s%d.%d) - Type '?' for a list of commands.\n\n",
	       ZVERSIONHDR,
	       ZVERSIONMAJOR,ZVERSIONMINOR);

	ss_listen(sci_idx);
#else
	run_command(argc-1, argv+1);
#endif
	ZClosePort();
	exit(0);
}

void
set_file(int argc,
	 char *argv[])
{
	if (argc > 2) {
		fprintf(stderr,"Usage: %s filename\n",argv[0]);
		return;
	}

	if (argc == 1)
		printf("Current file: %s\n",subsname);
	else
		(void) strcpy(subsname,argv[1]);
}

void
flush_locations(int argc,
		char *argv[])
{
	int retval;

	if (argc > 2) {
		fprintf(stderr,"Usage: %s [user]\n",argv[0]);
		return;
	}

	if (argc > 1)
		retval = ZFlushUserLocations(argv[1]);
	else
		retval = ZFlushMyLocations();

	if (retval != ZERR_NONE)
		com_err(whoami, retval, "while flushing locations");
}

void
flush_subscr(int argc,
	     char *argv[])
{
    int retval;

    if (argc > 2) {
	fprintf(stderr,"Usage: %s [recipient]\n",argv[0]);
	return;
    }

    retval = ZFlushUserSubscriptions((argc > 1) ? argv[1] : NULL);
    if (retval != ZERR_NONE)
	com_err(whoami, retval, "while flushing subscriptions");
}

void
wgc_control(int argc,
	    char *argv[])
{
	int retval;
	short newport;
	struct sockaddr_in newsin;
	ZNotice_t notice;

	newsin = ZGetDestAddr();

	if (argc > 1) {
		fprintf(stderr,"Usage: %s\n",argv[0]);
		return;
	}

	if ((newport = ZGetWGPort()) == -1) {
		com_err(whoami, errno, "while getting WindowGram port");
		return;
	}

	newsin.sin_port = (u_short) newport;
	if ((retval = ZSetDestAddr(&newsin)) != ZERR_NONE) {
		com_err(whoami, retval, "while setting destination address");
		return;
	}

	(void) memset((char *)&notice, 0, sizeof(notice));
	notice.z_kind = UNSAFE;
	notice.z_port = 0;
	notice.z_class = WG_CTL_CLASS;
	notice.z_class_inst = WG_CTL_USER;

	if (!strcmp(argv[0],"wg_read"))
		notice.z_opcode = USER_REREAD;
	if (!strcmp(argv[0],"wg_shutdown"))
		notice.z_opcode = USER_SHUTDOWN;
	if (!strcmp(argv[0],"wg_startup"))
		notice.z_opcode = USER_STARTUP;
	if (!strcmp(argv[0],"wg_exit"))
		notice.z_opcode = USER_EXIT;
	if (!notice.z_opcode) {
		fprintf(stderr,
			"unknown WindowGram client control command %s\n",
			argv[0]);
		return;
	}
	notice.z_sender = 0;
	notice.z_recipient = "";
	notice.z_default_format = "";
	notice.z_message_len = 0;

	if ((retval = ZSendNotice(&notice,ZNOAUTH)) != ZERR_NONE)
		com_err(whoami, retval, "while sending notice");

	if ((retval = ZInitialize()) != ZERR_NONE)
		com_err(whoami, retval,
			  "while reinitializing");
}

void
hm_control(int argc,
	   char *argv[])
{
	int retval;
	ZNotice_t notice;

	if (argc > 1) {
		fprintf(stderr,"Usage: %s\n",argv[0]);
		return;
	}

	(void) memset((char *)&notice, 0, sizeof(notice));
	notice.z_kind = HMCTL;
	notice.z_port = 0;
	notice.z_class = HM_CTL_CLASS;
	notice.z_class_inst = HM_CTL_CLIENT;

	if (!strcmp(argv[0],"hm_flush"))
		notice.z_opcode = CLIENT_FLUSH;
	if (!strcmp(argv[0],"new_server"))
		notice.z_opcode = CLIENT_NEW_SERVER;
	if (!notice.z_opcode) {
		fprintf(stderr, "unknown HostManager control command %s\n",
			argv[0]);
		return;
	}
	notice.z_sender = 0;
	notice.z_recipient = "";
	notice.z_default_format = "";
	notice.z_message_len = 0;

	if ((retval = ZSendNotice(&notice,ZNOAUTH)) != ZERR_NONE)
		com_err(whoami, retval, "while sending notice");
} 

void
show_var(int argc,
	 char *argv[])
{
	int i;
	char *value;

	if (argc < 2) {
		fprintf(stderr,"Usage: %s <varname> <varname> ...\n",argv[0]);
		return;
	}

	for (i=1;i<argc;i++) {
		value = ZGetVariable(argv[i]);
		if (value)
			printf("%s: %s\n",argv[i],value);
		else
			printf("%s: not defined\n",argv[i]);
	}
}

void
set_var(int argc, char *argv[])
{
	int retval,setting_exp,i;
	char *exp_level = NULL;
	char *newargv[1];
	char varcat[BUFSIZ];

	if (argc < 2) {
		fprintf(stderr,"Usage: %s <varname> [value]\n",
			argv[0]);
		return;
	}

	setting_exp = 0;

	if (!strcasecmp(argv[1],"exposure")) {
		setting_exp = 1;
		if (argc != 3) {
			fprintf(stderr,"An exposure setting must be specified.\n");
			return;
		}
		exp_level = (char *)0;
		if (!strcasecmp(argv[2],EXPOSE_NONE))
			exp_level = EXPOSE_NONE;
		if (!strcasecmp(argv[2],EXPOSE_OPSTAFF))
			exp_level = EXPOSE_OPSTAFF;
		if (!strcasecmp(argv[2],EXPOSE_REALMVIS))
			exp_level = EXPOSE_REALMVIS;
		if (!strcasecmp(argv[2],EXPOSE_REALMANN))
			exp_level = EXPOSE_REALMANN;
		if (!strcasecmp(argv[2],EXPOSE_NETVIS))
			exp_level = EXPOSE_NETVIS;
		if (!strcasecmp(argv[2],EXPOSE_NETANN))
			exp_level = EXPOSE_NETANN;
		if (!exp_level) {
			fprintf(stderr,"The exposure setting must be one of:\n");
			fprintf(stderr,"%s, %s, %s, %s, %s, %s.\n",
				EXPOSE_NONE,
				EXPOSE_OPSTAFF,
				EXPOSE_REALMVIS,
				EXPOSE_REALMANN,
				EXPOSE_NETVIS,
				EXPOSE_NETANN);
			return;
		}
	}
	if (argc == 2)
		retval = ZSetVariable(argv[1],"");
	else {
		(void) strcpy(varcat,argv[2]);
		for (i=3;i<argc;i++) {
			(void) strcat(varcat," ");
			(void) strcat(varcat,argv[i]);
		}
		retval = ZSetVariable(argv[1],varcat);
	}

	if (retval != ZERR_NONE) {
		com_err(whoami, retval, "while setting variable value");
		return;
	}

	/* Side-effects?  Naw, us? */

	if (setting_exp) {
		if ((retval = ZSetLocation(exp_level)) != ZERR_NONE)
			com_err(whoami, retval, "while changing exposure status");
		if (!strcmp(exp_level,EXPOSE_NONE)) {
			newargv[0] = "wg_shutdown";
			wgc_control(1,newargv);
		} else {
			newargv[0] = "wg_startup";
			wgc_control(1,newargv);
		}
		return;
	}
}

void
do_hide(int argc,
	char *argv[])
{
	char *exp_level = NULL;
	Code_t retval;

	if (argc != 1) {
		fprintf(stderr, "Usage: %s\n",argv[0]);
		return;
	}
	if (!strcmp(argv[0],"unhide"))
		exp_level = EXPOSE_REALMVIS;
	else
		exp_level = EXPOSE_OPSTAFF;
	if ((retval = ZSetLocation(exp_level)) != ZERR_NONE)
		com_err(whoami,retval,"while changing exposure status");
	return;
}

void
unset_var(int argc,
	  char *argv[])
{
	int retval,i;

	if (argc < 2) {
		fprintf(stderr,"Usage: %s <varname> [<varname> ... ]\n",
			argv[0]);
		return;
	}

	for (i=1;i<argc;i++)
		if ((retval = ZUnsetVariable(argv[i])) != ZERR_NONE)
			com_err(whoami, retval,
				  "while unsetting variable value");
}

void
cancel_subs(int argc,
	    char *argv[])
{
	int retval;
	short wgport;

	if (argc != 1) {
		fprintf(stderr,"Usage: %s\n",argv[0]);
		return;
	}

 	if ((wgport = ZGetWGPort()) == -1) {
		com_err(whoami, errno, "while finding WindowGram port");
		return;
	}
	if ((retval = ZCancelSubscriptions((u_short)wgport)) != ZERR_NONE)
		com_err(whoami, retval, "while cancelling subscriptions");
}

void
subscribe(int argc,
	  char *argv[])
{
	int retval;
	short wgport;
	ZSubscription_t sub,sub2;

	if (argc > 4 || argc < 3) {
		fprintf(stderr,"Usage: %s class instance [*]\n",argv[0]);
		return;
	}

	sub.zsub_class = argv[1];
	sub.zsub_classinst = argv[2];
	sub.zsub_recipient = (argc == 3)?ZGetSender():argv[3];

	fix_macros(&sub,&sub2,1);

 	if ((wgport = ZGetWGPort()) == -1) {
		com_err(whoami, errno, "while finding WindowGram port");
		return;
	}

	retval = (*argv[0] == 's') ?
		ZSubscribeToSansDefaults(&sub2,1,(u_short)wgport) :
		ZUnsubscribeTo(&sub2,1,(u_short)wgport);

	if (retval != ZERR_NONE)
		com_err(whoami, retval, "while subscribing");
} 

void
sub_file(int argc,
	 char *argv[])
{
	ZSubscription_t sub;
	short wgport;

	if (argc > 4 || argc < 3) {
		fprintf(stderr,"Usage: %s class instance [*]\n",argv[0]);
		return;
	}

	if (argv[1][0] == '!') {
		com_err(whoami, 0,
			  (!strcmp(argv[0],"add_unsubscription") ||
			   !strcmp(argv[0],"add_un") ||
			   !strcmp(argv[0],"delete_unsubscription") ||
			   !strcmp(argv[0],"del_un")) ?
			  "Do not use `!' as the first character of a class.\n\tIt is automatically added before modifying the subscription file." :
			  "Do not use `!' as the first character of a class.\n\tIt is reserved for internal use with un-subscriptions.");
		return;
	}
	sub.zsub_class = argv[1];
	sub.zsub_classinst = argv[2];
	sub.zsub_recipient = (argc == 3)?TOKEN_ME:argv[3];

	if (make_exist(subsname))
		return;
 	if ((wgport = ZGetWGPort()) == -1) {
		com_err(whoami, errno, "while finding WindowGram port");
		return;
	}

	if (!strcmp(argv[0],"add"))
		add_file(wgport,&sub,0);
	else if (!strcmp(argv[0],"add_unsubscription") ||
		 !strcmp(argv[0],"add_un"))
		add_file(wgport,&sub,1);
	else if (!strcmp(argv[0],"delete") ||
		 !strcmp(argv[0],"del") ||
		 !strcmp(argv[0],"dl"))
		del_file(wgport,&sub,0);
	else if (!strcmp(argv[0],"delete_unsubscription") ||
		 !strcmp(argv[0],"del_un")) {
		del_file(wgport,&sub,1);
	} else
		com_err(whoami, 0, "unknown command name");
	return;
}

void
add_file(short wgport,
	 ZSubscription_t *subs,
	 int unsub)
{
	FILE *fp;
	ZSubscription_t sub2;
	Code_t retval;

	(void) purge_subs(subs,ALL);	/* remove copies in the subs file */
	if (!(fp = fopen(subsname,"a"))) {
		com_err(whoami, errno, "while opening %s for append", subsname);
		return;
	}
	fprintf(fp,"%s%s,%s,%s\n",
		unsub ? "!" : "",
		subs->zsub_class, subs->zsub_classinst, subs->zsub_recipient);
	if (fclose(fp) == EOF) {
		com_err(whoami, errno, "while closing %s", subsname);
		return;
	}
	fix_macros(subs,&sub2,1);
	retval = (unsub
		  ? ZUnsubscribeTo(&sub2,1,(u_short)wgport)
		  : ZSubscribeToSansDefaults(&sub2,1,(u_short)wgport));
	if (retval)
		com_err(whoami, retval,
			  unsub ? "while unsubscribing" :
			  "while subscribing");
	return;
}

void
del_file(short wgport,
	 register ZSubscription_t *subs,
	 int unsub)
{
	ZSubscription_t sub2;
	int retval;

	retval = purge_subs(subs, unsub ? UNSUBONLY : SUBONLY);
	if (retval == ERR)
		return;
	if (retval == NOT_REMOVED)
		fprintf(stderr,
			"Couldn't find %sclass %s instance %s recipient %s in\n\tfile %s\n",
			unsub ? "un-subscription " : "",
			subs->zsub_class, subs->zsub_classinst,
			subs->zsub_recipient, subsname);
	fix_macros(subs,&sub2,1);
	if ((retval = ZUnsubscribeTo(&sub2,1,(u_short)wgport)) !=
	    ZERR_NONE)
		com_err(whoami, retval, "while unsubscribing");
	return;
}

int
purge_subs(register ZSubscription_t *subs,
	   int which)
{
	FILE *fp,*fpout;
	char subline[BUFSIZ];
	char backup[BUFSIZ],ourline[BUFSIZ];
	int delflag = NOT_REMOVED;
	int keep = 0;

	switch (which) {
	case SUBONLY:
	case UNSUBONLY:
	case ALL:
		break;
	default:
		com_err(whoami, 0, "internal error in purge_subs");
		return(ERR);
	}

	(void) sprintf(ourline,"%s,%s,%s",
		       subs->zsub_class,
		       subs->zsub_classinst,
		       subs->zsub_recipient);

	if (!(fp = fopen(subsname,"r"))) {
		com_err(whoami, errno, "while opening %s for read", subsname);
		return(ERR);
	}
	(void) strcpy(backup, subsname);
	(void) strcat(backup, ".temp");
	(void) unlink(backup);
	if (!(fpout = fopen(backup,"w"))) {
		com_err(whoami, errno, "while opening %s for writing", backup);
		(void) fclose(fp);
		return(ERR);
	}
	for (;;) {
		if (!fgets(subline,sizeof subline,fp))
			break;
		if (*subline)
			subline[strlen(subline)-1] = '\0'; /* nuke newline */
		switch (which) {
		case SUBONLY:
			keep = strcmp(subline,ourline);
			break;
		case UNSUBONLY:
			keep = (*subline != '!' || strcmp(subline+1,ourline));
			break;
		case ALL:
			keep = (strcmp(subline,ourline) &&
				(*subline != '!' || strcmp(subline+1,
							   ourline)));
			break;
		}
		if (keep) {
			fputs(subline, fpout);
			if (ferror(fpout) || (fputc('\n', fpout) == EOF)) {
				com_err(whoami, errno, "while writing to %s",
					backup);
			}
		} else
			delflag = REMOVED;
	}
	(void) fclose(fp);		/* open read-only, ignore errs */
	if (fclose(fpout) == EOF) {
		com_err(whoami, errno, "while closing %s", backup);
		return(ERR);
	}
	if (rename(backup,subsname) == -1) {
		com_err(whoami, errno, "while renaming %s to %s\n",
			backup, subsname);
		return(ERR);
	}
	return(delflag);
}

void
load_subs(int argc,
	  char *argv[])
{
	ZSubscription_t subs[SUBSATONCE],subs2[SUBSATONCE],unsubs[SUBSATONCE];
#ifdef CMU_ZCTL_PUNT
	ZSubscription_t punts[SUBSATONCE];
	int pind;
#endif
	FILE *fp;
	int ind,unind,lineno,i,retval,type;
	short wgport = 0;
	char *comma,*comma2,*file,subline[BUFSIZ];

	if (argc > 2) {
		fprintf(stderr,"Usage: %s [file]\n",argv[0]);
		return;
	}

	if (*argv[0] == 'u')
		type = UNSUB;
	else
		if (!strcmp(argv[0],"list") || !strcmp(argv[0],"ls"))
			type = LIST;
		else
			type = SUB;

	if (type != LIST)
		if ((wgport = ZGetWGPort()) == -1) {
			com_err(whoami, errno,
				  "while finding WindowGram port");
			return;
		}

	file = (argc == 1) ? subsname : argv[1];

	fp = fopen(file,"r");

	if (fp == NULL) {
		com_err(whoami, errno,
			  "while loading subscription file");
		return;
	}

#ifdef CMU_ZCTL_PUNT
	pind =
#endif
	  ind = unind = 0;
	lineno = 1;

	for (;;lineno++) {
		if (!fgets(subline,sizeof subline,fp))
			break;
		if (*subline == '#' || !*subline)
			continue;
		subline[strlen(subline)-1] = '\0'; /* nuke newline */
		comma = strchr(subline,',');
		if (comma)
			comma2 = strchr(comma+1,',');
		else
			comma2 = 0;
		if (!comma || !comma2) {
			fprintf(stderr,
				"Malformed subscription at line %d of %s:\n%s\n",
				lineno,file,subline);
			continue;
		}
		*comma = '\0';
		*comma2 = '\0';
		if (type == LIST) {
			if (*subline == '!')
				printf("(Un-subscription) Class %s instance %s recipient %s\n",
				       subline+1, comma+1, comma2+1);
#ifdef CMU_ZCTL_PUNT
			else if(*subline == '-')
				printf("(Punted) Class %s instance %s recipient %s\n",
				       subline+1, comma+1, comma2+1);
#endif
			else
				printf("Class %s instance %s recipient %s\n",
				       subline, comma+1, comma2+1);
			continue;
		}
		if (*subline == '!') {	/* an un-subscription */
			/* if we are explicitly un-subscribing to
			   the contents of a subscription file, ignore
			   any un-subscriptions in that file */
			if (type == UNSUB)
				continue;
			unsubs[unind].zsub_class =
			    (char *)malloc((unsigned)(strlen(subline)));
			/* XXX check malloc return */
			/* skip the leading '!' */
			(void) strcpy(unsubs[unind].zsub_class,subline+1);
			unsubs[unind].zsub_classinst =
			    (char *)malloc((unsigned)(strlen(comma+1)+1));
			/* XXX check malloc return */
			(void) strcpy(unsubs[unind].zsub_classinst,comma+1);
			unsubs[unind].zsub_recipient =
			    (char *)malloc((unsigned)(strlen(comma2+1)+1));
			/* XXX check malloc return */
			(void) strcpy(unsubs[unind].zsub_recipient,comma2+1);
			unind++;
		} else
#ifdef CMU_ZCTL_PUNT
		if (*subline == '-') {  /* a punt */
			if (type == UNSUB)
				continue;
			punts[pind].zsub_class =
			    (char *)malloc((unsigned)(strlen(subline)+1));
			/* XXX check malloc return */
			(void) strcpy(punts[pind].zsub_class,subline+1);
			punts[pind].zsub_classinst =
			    (char *)malloc((unsigned)(strlen(comma+1)+1));
			/* XXX check malloc return */
			(void) strcpy(punts[pind].zsub_classinst,comma+1);
			punts[pind].zsub_recipient =
			    (char *)malloc((unsigned)(strlen(comma2+1)+1));
			/* XXX check malloc return */
			(void) strcpy(punts[pind].zsub_recipient,comma2+1);
			pind++;
		} else
#endif
		{
			subs[ind].zsub_class =
			    (char *)malloc((unsigned)(strlen(subline)+1));
			/* XXX check malloc return */
			(void) strcpy(subs[ind].zsub_class,subline);
			subs[ind].zsub_classinst =
			    (char *)malloc((unsigned)(strlen(comma+1)+1));
			/* XXX check malloc return */
			(void) strcpy(subs[ind].zsub_classinst,comma+1);
			subs[ind].zsub_recipient =
			    (char *)malloc((unsigned)(strlen(comma2+1)+1));
			/* XXX check malloc return */
			(void) strcpy(subs[ind].zsub_recipient,comma2+1);
			ind++;
		}
#ifdef CMU_ZCTL_PUNT
		if (pind == SUBSATONCE) {
			 fix_macros(punts,subs2,pind);
			 if ((retval = ZPunt(subs2,pind,(u_short)wgport) !=
			     ZERR_NONE))
			   {
			     com_err(whoami, retval,
				       "while punting");
			     goto cleanup;
			   }
			 for (i=0;i<pind;i++) {
				 free(punts[i].zsub_class);
				 free(punts[i].zsub_classinst);
				 free(punts[i].zsub_recipient);
			 }
			 pind = 0;
		}
#endif
		if (ind == SUBSATONCE) {
			fix_macros(subs,subs2,ind);
			if ((retval = (type == SUB)?
			     ZSubscribeTo(subs2,ind,(u_short)wgport):
			     ZUnsubscribeTo(subs2,ind,(u_short)wgport)) !=
			    ZERR_NONE) {
				com_err(whoami, retval, (type == SUB) ?
					  "while subscribing":
					  "while unsubscribing");
				goto cleanup;
			}
			for (i=0;i<ind;i++) {
				free(subs[i].zsub_class);
				free(subs[i].zsub_classinst);
				free(subs[i].zsub_recipient);
			}
			ind = 0;
		}
		if (unind == SUBSATONCE) {
			fix_macros(unsubs,subs2,unind);
			if ((retval = ZUnsubscribeTo(subs2,unind,(u_short)wgport)) != ZERR_NONE) {
				com_err(whoami, retval,
					  "while unsubscribing to un-subscriptions");
				goto cleanup;
			}
			for (i=0;i<unind;i++) {
				free(unsubs[i].zsub_class);
				free(unsubs[i].zsub_classinst);
				free(unsubs[i].zsub_recipient);
			}
			unind = 0;
		}
	}

	if (type != LIST) {
		/* even if we have no subscriptions, be sure to send
		   an empty packet to trigger the default subscriptions */
		fix_macros(subs,subs2,ind);
		if ((retval = (type == SUB)?ZSubscribeTo(subs2,ind,(u_short)wgport):
		     ZUnsubscribeTo(subs2,ind,(u_short)wgport)) != ZERR_NONE) {
			com_err(whoami, retval, (type == SUB) ?
				  "while subscribing":
				  "while unsubscribing");
			goto cleanup;
		}
		if (unind) {
			fix_macros(unsubs,subs2,unind);
			if ((retval =
			     ZUnsubscribeTo(subs2,unind,(u_short)wgport)) != ZERR_NONE) {
				com_err(whoami, retval,
					  "while unsubscribing to un-subscriptions");
				goto cleanup;
			}
		}
#ifdef CMU_ZCTL_PUNT
		if (pind) {
			fix_macros(punts,subs2,pind);
			if ((retval = ZPunt(subs2,pind,(u_short)wgport) !=
			    ZERR_NONE))
			{
			  com_err(whoami,retval,
				    "while punting");
			  goto cleanup;
			}
		}
#endif
	}
cleanup:
	for (i=0;i<ind;i++) {
	  free(subs[i].zsub_class);
	  free(subs[i].zsub_classinst);
	  free(subs[i].zsub_recipient);
	}
	for (i=0;i<unind;i++) {
	  free(unsubs[i].zsub_class);
	  free(unsubs[i].zsub_classinst);
	  free(unsubs[i].zsub_recipient);
	}
#ifdef CMU_ZCTL_PUNT
	for (i=0;i<pind;i++) {
	  free(punts[i].zsub_class);
	  free(punts[i].zsub_classinst);
	  free(punts[i].zsub_recipient);
	}
#endif

	(void) fclose(fp);	/* ignore errs--file is read-only */
	return;
}

void
current(int argc,
	char *argv[])
{
	FILE *fp = NULL;
	ZSubscription_t subs;
	int i,nsubs,retval,save,one,defs;
	short wgport;
	char backup[BUFSIZ];
	char *file = NULL;

	save = 0;
	defs = 0;

	if (!strcmp(argv[0],"save"))
		save = 1;
	else if (!strcmp(argv[0], "defaults") || !strcmp(argv[0], "defs"))
		defs = 1;

	if (argc != 1 && !(save && argc == 2)) {
		fprintf(stderr,"Usage: %s%s\n",argv[0],save?" [filename]":"");
		return;
	}

	if (!defs)
		if ((wgport = ZGetWGPort()) == -1) {
			com_err(whoami, errno,
				  "while finding WindowGram port");
			return;
		}

	if (defs)
		retval = ZRetrieveDefaultSubscriptions(&nsubs);
	else
		retval = ZRetrieveSubscriptions((u_short)wgport,&nsubs);

	if (retval == ZERR_TOOMANYSUBS) {
		fprintf(stderr,"Too many subscriptions -- some have not been returned.\n");
		if (save) {
			fprintf(stderr,"Save aborted.\n");
			return;
		}
	}
	else
		if (retval != ZERR_NONE) {
			com_err(whoami, retval, "retrieving subscriptions");
			return;
		}

	if (save) {
		file = (argc == 1)?subsname:argv[1];
		(void) strcpy(backup,file);
		(void) strcat(backup,".temp");
		if (!(fp = fopen(backup,"w"))) {
			com_err(whoami, errno, "while opening %s for write",
				backup);
			return;
		}
	}

	for (i=0;i<nsubs;i++) {
		one = 1;
		if ((retval = ZGetSubscriptions(&subs,&one)) != ZERR_NONE) {
			com_err(whoami, retval, "while getting subscription");
			if (save) {
				fprintf(stderr,"Subscriptions file not modified\n");
				(void) fclose(fp);
				(void) unlink(backup);
			}
			return;
		}
		if (save)
			fprintf(fp,"%s,%s,%s\n",subs.zsub_class,
				subs.zsub_classinst, subs.zsub_recipient);
		else
			printf("Class %s Instance %s Recipient %s\n",
			       subs.zsub_class, subs.zsub_classinst,
			       subs.zsub_recipient);
	}

	if (save) {
		if (fclose(fp) == EOF) {
			com_err(whoami, errno, "while closing %s", backup);
			return;
		}
		if (rename(backup,file) == -1) {
			com_err(whoami, retval, "while renaming %s to %s",
				backup, file);
			(void) unlink(backup);
		}
	}
}

int
make_exist(char *filename)
{
	FILE *fpout;

	if (!access(filename,F_OK))
		return (0);

	if (!(fpout = fopen(filename,"w"))) {
		com_err(whoami, errno,"while opening %s for write", filename);
		return (1);
	}

	if (fclose(fpout) == EOF) {
		com_err(whoami, errno, "while closing %s", filename);
		return(1);
	}
	return (0);
}

void
fix_macros(ZSubscription_t *subs,
	   ZSubscription_t *subs2,
	   int num)
{
	int i;

	for (i=0;i<num;i++) {
		subs2[i] = subs[i];
		fix_macros2(subs[i].zsub_class,&subs2[i].zsub_class);
		fix_macros2(subs[i].zsub_classinst,&subs2[i].zsub_classinst);
		fix_macros2(subs[i].zsub_recipient,&subs2[i].zsub_recipient);
	}
}

void
fix_macros2(char *src, char **dest)
{
	if (!strcmp(src,TOKEN_HOSTNAME)) {
		*dest = ourhost;
		return;
	}
	if (!strcmp(src,TOKEN_CANONNAME)) {
		*dest = ourhostcanon;
		return;
	}
	if (!strcmp(src,TOKEN_ME))
		*dest = ZGetSender();
}

void
do_punt(int argc, char *argv[])
{
#ifdef CMU_ZCTL_PUNT
  char *class, *inst, *recip, *msg, *cmd = argv[0];
  int retval, punt;
  short newport;
  struct sockaddr_in newsin;
  ZNotice_t notice;

  if (! strcmp(cmd, "punt")) punt = 1;
  else punt = 0;

  switch (argc) {
  case 2:
    class = "message";
    inst = argv[1];
    recip = "";
    break;
  case 3:
    class = argv[1];
    inst = argv[2];
    recip = "";
    break;
  case 4:
    class = argv[1];
    inst = argv[2];
    recip = argv[3];
    if (*argv[3] == '*') /* fixed so realm punts would work (vs0r) */
      if (*(argv[3]+1) == '@')
      if (!strcmp((char *)ZGetRealm(), (char *)ZExpandRealm(argv[3]+2)))
        /*check local*/
        recip = "";
    break;
  default:
    fprintf(stderr, "Usages:\n");
    fprintf(stderr, "\t%s instance\n", cmd);
    fprintf(stderr, "\t%s class instance\n", cmd);
    fprintf(stderr, "\t%s class instance recipient\n", cmd);
    return;
  }

  retval = ZOpenPort((u_short *) 0);
  if(retval != ZERR_NONE) {
    com_err(whoami, retval, "while opening Zephyr port.");
    return;
  }

  newsin = ZGetDestAddr();
  if ((newport = ZGetWGPort()) == -1) {
    fprintf(stderr, "%s: Can't find windowgram port\n", whoami);
    return;
  }

  newsin.sin_port = (unsigned short) newport;
  if ((retval = ZSetDestAddr(&newsin)) != ZERR_NONE) {
    com_err(whoami,retval,"while setting destination address");
    return;
  }

  msg = (char *) malloc(strlen(class) + strlen(inst) + strlen(recip) + 4);
  sprintf(msg, "%s%c%s%c%s", class, '\0', inst, '\0', recip);

  if (*recip == '*')
    if (*(recip+1) == '@')
      if (strcmp(recip+2, (char *)ZExpandRealm(recip+2)))
        sprintf(msg, "%s%c%s%c%s", class, '\0', inst, '\0',
                (char *)ZExpandRealm(recip+2));
  printf("%s <%s,%s,%s>\n", punt ? "Punting" : "Unpunting",
       class, inst, *recip ? recip : "*");

  memset((char *) &notice, 0, sizeof(ZNotice_t));
  notice.z_kind = UNSAFE;
  notice.z_class = WG_CTL_CLASS;
  notice.z_class_inst = WG_CTL_USER;
  notice.z_recipient = "";
  notice.z_default_format = "";
  notice.z_opcode = (punt) ? "SUPPRESS" : "UNSUPPRESS";
  notice.z_port = 0;
  notice.z_message = msg;
  notice.z_message_len = strlen(class)+strlen(inst)+strlen(recip)+3;

  if ((retval = ZSendNotice(&notice,ZNOAUTH)) != ZERR_NONE)
    fprintf(stderr,"%s: while sending notice\n",whoami);

  free(msg);

  ZClosePort();
#endif
  return;
}

void
list_punts(int argc, char *argv[])
{
#ifdef CMU_ZCTL_PUNT
  ZNotice_t notice;
  int retval;
  struct sockaddr_in old, to, from;
  u_short ourport, zwgcport;
  char *msg;

  ourport=0;
  retval = ZOpenPort(&ourport);
  if(retval != ZERR_NONE) {
    com_err("zctl", retval, "while opening Zephyr port.");
    return;
  }

  old = ZGetDestAddr();
  to = old;
  if ((zwgcport = ZGetWGPort()) == (u_short)-1) {
    fprintf(stderr, "zctl: Can't find windowgram port\n");
    return;
  }

  to.sin_port = (u_short) zwgcport;
  if ((retval = ZSetDestAddr(&to)) != ZERR_NONE) {
    com_err("zctl",retval,"while setting destination address");
    return;
  }

  memset((char *) &notice, 0, sizeof(ZNotice_t));
  notice.z_kind = UNSAFE;
  notice.z_class = WG_CTL_CLASS;
  notice.z_class_inst = WG_CTL_USER;
  notice.z_recipient = "";
  notice.z_default_format = "";
  notice.z_opcode = "LIST-SUPPRESSED" /*USER_LIST_SUPPRESSED*/;
  notice.z_port = ourport;
  notice.z_message = NULL;
  notice.z_message_len = 0;

  if ((retval = ZSendNotice(&notice,ZNOAUTH)) != ZERR_NONE)
    com_err("zctl",retval,"while sending notice");

  if ((retval = ZReceiveNotice(&notice,&from)) != ZERR_NONE)
    com_err("zctl",retval,"while receiving ack");

  (void) ZFreeNotice(&notice);

  if ((retval = ZReceiveNotice(&notice,&from)) != ZERR_NONE)
    com_err("zctl",retval,"while receiving notice");

  notice.z_auth = ZCheckAuthentication(&notice, &from);

  if ((retval = ZSetDestAddr(&old)) != ZERR_NONE) {
    com_err("zctl",retval,"while resetting destination address");
    return;
  }

  msg = (char *) malloc((notice.z_message_len+1) * sizeof(char));
  (void) strncpy(msg,notice.z_message, notice.z_message_len);
  msg[notice.z_message_len]=(char)0;
  printf("%s", msg);
  (void) free(msg);
  (void) ZFreeNotice(&notice);
  (void) ZClosePort();

#endif /* CMU_ZCTL_PUNT */
  return;
}

#ifndef HAVE_SS
#define MAXNAMES 3
static const struct {
	void (*fptr)(int, char *[]);
	const char *doc;
	const char *names[MAXNAMES];
} commands[] = {
/* { set_file, "Set default subscriptions file.", "file" }, */
  { cancel_subs, "Cancel all subscriptions.",
    { "cancel" } },
  { load_subs, "Subscribe to a subscriptions file.",
    { "load", "ld" } },
  { load_subs, "Unsubscribe to a subscriptions file.",
    { "unload", "unld" } },
  { load_subs, "List a subscriptions file.",
    { "list", "ls" } },
  { subscribe, "Subscribe to a class/class instance.",
    { "subscribe", "sub" } },
  { subscribe, "Unsubscribe to a class/class instance.",
    { "unsubscribe", "unsub" } },
  { sub_file, "Subscribe and add to subscriptions file.",
    { "add" } },
  { sub_file, "Unsubscribe and add to subscriptions file\nas un-subscription.",
    { "add_unsubscription", "add_un" } },
  { sub_file, "Unsubscribe and delete subscription from\nsubscriptions file.",
    { "delete", "del", "dl" } },
  { sub_file, "Delete un-subscription from subscriptions file.",
    { "delete_unsubscription", "del_un" } },
  { current, "Retrieve current subscriptions.",
    { "retrieve", "ret" } },
  { current, "Retrieve system-wide default subscriptions.",
    { "defaults", "defs" } },
  { current, "Save current subscriptions (replacing existing file).",
    { "save" } },
  { show_var, "Show a variable's value.",
    { "show" } },
  { set_var, "Set a variable's value.",
    { "set" } },
  { unset_var, "Delete a variable's value.",
    { "unset" } },
  { wgc_control, "Get the WindowGram to reread its description file.",
    { "wg_read" } },
  { wgc_control, "Tell the WindowGram not to react to incoming notices.",
    { "wg_shutdown" } },
  { wgc_control, "Tell the WindowGram to react to incoming notices.",
    { "wg_startup" } },
  { wgc_control, "Tell the WindowGram to exit completely.",
    { "wg_exit" } },
  { hm_control, "Tell the server to flush information about this host.",
    { "hm_flush" } },
  { hm_control, "Tell the HostManager to find a new server.",
    { "new_server" } },
  { flush_locations, "Flush all location information.",
    { "flush_locs" } },
  { flush_subscr, "Flush all subscription information.",
    { "flush_subs" } },
  { do_hide, "Hide your location.",
    { "hide" } },
  { do_hide, "Show (un-hide) your location.",
    { "unhide" } },
  { show_commands, "List available commands.",
    { "help", "?" } },
#ifdef CMU_ZCTL_PUNT
  { do_punt, "Ignore specified messages.",
    { "punt" } },
  { do_punt, "Stop ignoring specified messages.",
    { "unpunt" } },
  { list_punts, "List current messages to ignore.",
    { "list_punts", "lp" } },
#endif
};
#define MAXCOMMAND (sizeof(commands)/sizeof(commands[0]))

#define DOCCOL 25

static void
show_commands(int argc, char *argv[])
{
	int i, j, col, len;
	const char *str, *s;
	printf("Available zctl requests:\n\n");
	for (i = 0; i < MAXCOMMAND; i++) {
		col = 0;
		printf("%s", commands[i].names[0]);
		col += strlen(commands[i].names[0]);
		for (j = 1; j < MAXNAMES && commands[i].names[j]; j++) {
			printf(", %s", commands[i].names[j]);
			col += 2 + strlen(commands[i].names[j]);
		}
		if (col > DOCCOL - 2) {
			printf("\n");
			col = 0;
		}
		printf("%*s", DOCCOL - col, "");
		str = commands[i].doc;
		while ((s = strchr(str, '\n')) != NULL) {
			printf("%.*s\n%*s", (int)(s-str), str, DOCCOL, "");
			str = s+1;
		}
		printf("%s\n", str);
	}
}

static void
run_command(int argc, char *argv[])
{
	int i, j;
	for (i = 0; i < MAXCOMMAND; i++)
		for (j = 0; j < MAXNAMES; j++)
			if (commands[i].names[j] != NULL &&
			    !strcmp(commands[i].names[j], argv[0])) {
				commands[i].fptr(argc, argv);
				return;
			}
	com_err(whoami, 0,
		"Unknown command '%s'; use '%s help' for a list of commands.",
		argv[0], whoami);
	exit(1);
}
#endif
