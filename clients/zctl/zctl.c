/* This file is part of the Project Athena Zephyr Notification System.
 * It contains code for the "zctl" command.
 *
 *	Created by:	Robert French
 *
 *	$Source$
 *	$Author$
 *
 *	Copyright (c) 1987,1988 by the Massachusetts Institute of Technology.
 *	For copying and distribution information, see the file
 *	"mit-copyright.h". 
 */

#include <zephyr/mit-copyright.h>

#include <zephyr/zephyr.h>
#include <ss/ss.h>
#include <com_err.h>
#include <pwd.h>
#include <netdb.h>
#include <string.h>
#include <sys/file.h>
#include <sys/param.h>
#ifndef lint
static char *rcsid_zctl_c = "$Header$";
#endif lint

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
int purge_subs();

int sci_idx;
char subsname[BUFSIZ];
char ourhost[MAXHOSTNAMELEN],ourhostcanon[MAXHOSTNAMELEN];

extern ss_request_table zctl_cmds;
extern char *getenv(), *malloc();
extern uid_t getuid();

main(argc,argv)
	int argc;
	char *argv[];
{
	struct passwd *pwd;
	struct hostent *hent;
	char ssline[BUFSIZ],oldsubsname[BUFSIZ],*envptr;
	int retval,code,i;

	if ((retval = ZInitialize()) != ZERR_NONE) {
		com_err(argv[0],retval,"while initializing");
		exit (1);
	}

	envptr = getenv("HOME");
	if (envptr)
		(void) strcpy(subsname,envptr);
	else {
		if (!(pwd = getpwuid((int) getuid()))) {
			fprintf(stderr,"Who are you?\n");
			exit (1);
		}

		(void) strcpy(subsname,pwd->pw_dir);
	}
	(void) strcpy(oldsubsname,subsname);
	(void) strcat(oldsubsname,OLD_SUBS);
	(void) strcat(subsname,USERS_SUBS);
	if (!access(oldsubsname,F_OK) && access(subsname, F_OK)) {
		/* only if old one exists and new one does not exist */
		printf("The .subscriptions file in your home directory is now being used as\n.zephyr.subs . I will rename it to .zephyr.subs for you.\n");
		if (rename(oldsubsname,subsname))
			com_err(argv[0], errno, "renaming .subscriptions");
	}
	
	if (gethostname(ourhost,BUFSIZ) == -1) {
		com_err(argv[0],errno,"while getting host name");
		exit (1);
	}

	if (!(hent = gethostbyname(ourhost))) {
		fprintf(stderr,"%s: Can't get canonical name for host %s",
			argv[0], ourhost);
		exit (1);
	}

	(void) strcpy(ourhostcanon,hent->h_name);
	
	sci_idx = ss_create_invocation("zctl","",0,&zctl_cmds,&code);
	if (code) {
		ss_perror(sci_idx,code,"while creating invocation");
		exit(1);
	}

	if (argc > 1) {
		*ssline = '\0';
		for (i=1;i<argc;i++)
			(void) sprintf(ssline+strlen(ssline),"%s ",argv[i]);
		ssline[strlen(ssline)-1] = '\0';
		code = ss_execute_line(sci_idx,ssline);
		if (code)
			ss_perror(sci_idx,code,ssline);
		exit((code != 0));
	} 

	printf("ZCTL $Revision$ (Protocol %s%d.%d) - Type '?' for a list of commands.\n\n",
	       ZVERSIONHDR,
	       ZVERSIONMAJOR,ZVERSIONMINOR);
	
	ss_listen(sci_idx,&code);
	exit(0);
}

set_file(argc,argv)
	int argc;
	char *argv[];
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

flush_locations(argc,argv)
	int argc;
	char *argv[];
{
	int retval;
	
	if (argc > 1) {
		fprintf(stderr,"Usage: %s\n",argv[0]);
		return;
	}

	if ((retval = ZFlushMyLocations()) != ZERR_NONE)
		ss_perror(sci_idx,retval,"while flushing locations");
}

wgc_control(argc,argv)
	int argc;
	char *argv[];
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
		ss_perror(sci_idx,errno,"while getting WindowGram port");
		return;
	}

	newsin.sin_port = (u_short) newport;
	if ((retval = ZSetDestAddr(&newsin)) != ZERR_NONE) {
		ss_perror(sci_idx,retval,"while setting destination address");
		return;
	}

	(void) bzero((char *)&notice, sizeof(notice));
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
		ss_perror(sci_idx,retval,"while sending notice");

	if ((retval = ZInitialize()) != ZERR_NONE)
		ss_perror(sci_idx,retval,
			  "while reinitializing");
} 

hm_control(argc,argv)
	int argc;
	char *argv[];
{
	int retval;
	ZNotice_t notice;

	if (argc > 1) {
		fprintf(stderr,"Usage: %s\n",argv[0]);
		return;
	}
	
	(void) bzero((char *)&notice, sizeof(notice));
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
		ss_perror(sci_idx,retval,"while sending notice");
} 

show_var(argc,argv)
	int argc;
	char *argv[];
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

set_var(argc,argv)
	int argc;
	char *argv[];
{
	int retval,setting_exp,i;
	char *exp_level,*newargv[1];
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
		ss_perror(sci_idx,retval,"while setting variable value");
		return;
	}

	/* Side-effects?  Naw, us? */
	
	if (setting_exp) {
		if ((retval = ZSetLocation(exp_level)) != ZERR_NONE)
			ss_perror(sci_idx,retval,"while changing exposure status");
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

do_hide(argc,argv)
	int argc;
	char *argv[];
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
		ss_perror(sci_idx,retval,"while changing exposure status");
	return;
}

unset_var(argc,argv)
	int argc;
	char *argv[];
{
	int retval,i;
	
	if (argc < 2) {
		fprintf(stderr,"Usage: %s <varname> [<varname> ... ]\n",
			argv[0]);
		return;
	}

	for (i=1;i<argc;i++)
		if ((retval = ZUnsetVariable(argv[i])) != ZERR_NONE)
			ss_perror(sci_idx,retval,
				  "while unsetting variable value");
}
	
cancel_subs(argc,argv)
	int argc;
	char *argv[];
{
	int retval;
	short wgport;

	if (argc != 1) {
		fprintf(stderr,"Usage: %s\n",argv[0]);
		return;
	} 

 	if ((wgport = ZGetWGPort()) == -1) {
		ss_perror(sci_idx,errno,"while finding WindowGram port");
		return;
	} 
	if ((retval = ZCancelSubscriptions((u_short)wgport)) != ZERR_NONE)
		ss_perror(sci_idx,retval,"while cancelling subscriptions");
}

subscribe(argc,argv)
	int argc;
	char *argv[];
{
	int retval;
	short wgport;
	ZSubscription_t sub,sub2;
	
	if (argc > 4 || argc < 3) {
		fprintf(stderr,"Usage: %s class instance [*]\n",argv[0]);
		return;
	}
	
	sub.class = argv[1];
	sub.classinst = argv[2];
	sub.recipient = (argc == 3)?ZGetSender():argv[3];

	fix_macros(&sub,&sub2,1);
	
 	if ((wgport = ZGetWGPort()) == -1) {
		ss_perror(sci_idx,errno,"while finding WindowGram port");
		return;
	} 

	retval = (*argv[0] == 's') ? ZSubscribeTo(&sub2,1,(u_short)wgport) :
		ZUnsubscribeTo(&sub2,1,(u_short)wgport);
	
	if (retval != ZERR_NONE)
		ss_perror(sci_idx,retval,"while subscribing");
} 

sub_file(argc,argv)
	int argc;
	char *argv[];
{
	ZSubscription_t sub;
	short wgport;

	if (argc > 4 || argc < 3) {
		fprintf(stderr,"Usage: %s class instance [*]\n",argv[0]);
		return;
	}

	if (argv[1][0] == '!') {
		ss_perror(sci_idx,0,
			  (!strcmp(argv[0],"add_unsubscription") ||
			   !strcmp(argv[0],"add_un") ||
			   !strcmp(argv[0],"delete_unsubscription") ||
			   !strcmp(argv[0],"del_un")) ?
			  "Do not use `!' as the first character of a class.\n\tIt is automatically added before modifying the subscription file." :
			  "Do not use `!' as the first character of a class.\n\tIt is reserved for internal use with un-subscriptions.");
		return;
	}
	sub.class = argv[1];
	sub.classinst = argv[2];
	sub.recipient = (argc == 3)?TOKEN_ME:TOKEN_WILD;


	if (make_exist(subsname))
		return;
 	if ((wgport = ZGetWGPort()) == -1) {
		ss_perror(sci_idx,errno,"while finding WindowGram port");
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
		ss_perror(sci_idx,0,"unknown command name");
	return;
}

add_file(wgport,subs,unsub)
short wgport;
ZSubscription_t *subs;
int unsub;
{
	FILE *fp;
	char errbuf[BUFSIZ];
	ZSubscription_t sub2;
	Code_t retval;

	(void) purge_subs(subs,ALL);	/* remove copies in the subs file */
	if (!(fp = fopen(subsname,"a"))) {
		(void) sprintf(errbuf,"while opening %s for append",subsname);
		ss_perror(sci_idx,errno,errbuf);
		return;
	} 
	fprintf(fp,"%s%s,%s,%s\n",
		unsub ? "!" : "",
		subs->class, subs->classinst, subs->recipient);
	if (fclose(fp) == EOF) {
		(void) sprintf(errbuf, "while closing %s", subsname);
		ss_perror(sci_idx, errno, errbuf);
		return;
	}
	fix_macros(subs,&sub2,1);
	if (retval = (unsub ? ZUnsubscribeTo(&sub2,1,(u_short)wgport) :
		       ZSubscribeTo(&sub2,1,(u_short)wgport)))
		ss_perror(sci_idx,retval,
			  unsub ? "while unsubscribing" :
			  "while subscribing");
	return;
}

del_file(wgport,subs,unsub)
short wgport;
register ZSubscription_t *subs;
int unsub;
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
			subs->class,subs->classinst,subs->recipient,subsname);
	fix_macros(subs,&sub2,1);
	if ((retval = ZUnsubscribeTo(&sub2,1,(u_short)wgport)) !=
	    ZERR_NONE)
		ss_perror(sci_idx,retval,"while unsubscribing");
	return;
}

int
purge_subs(subs,which)
register ZSubscription_t *subs;
int which;
{
	FILE *fp,*fpout;
	char errbuf[BUFSIZ],subline[BUFSIZ];
	char backup[BUFSIZ],ourline[BUFSIZ];
	int delflag = NOT_REMOVED;
	int keep;

	switch (which) {
	case SUBONLY:
	case UNSUBONLY:
	case ALL:
		break;
	default:
		ss_perror(sci_idx,0,"internal error in purge_subs");
		return(ERR);
	}

	(void) sprintf(ourline,"%s,%s,%s",
		       subs->class,
		       subs->classinst,
		       subs->recipient);

	if (!(fp = fopen(subsname,"r"))) {
		(void) sprintf(errbuf,"while opening %s for read",subsname);
		ss_perror(sci_idx,errno,errbuf);
		return(ERR);
	} 
	(void) strcpy(backup, subsname);
	(void) strcat(backup, ".temp");
	(void) unlink(backup);
	if (!(fpout = fopen(backup,"w"))) {
		(void) sprintf(errbuf,"while opening %s for writing",backup);
		ss_perror(sci_idx,errno,errbuf);
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
				(void) sprintf(errbuf, "while writing to %s",
					       backup);
				ss_perror(sci_idx, errno, errbuf);
			}
		} else
			delflag = REMOVED;
	}
	(void) fclose(fp);		/* open read-only, ignore errs */
	if (fclose(fpout) == EOF) {
		(void) sprintf(errbuf, "while closing %s",backup);
		ss_perror(sci_idx, errno, errbuf);
		return(ERR);
	}
	if (rename(backup,subsname) == -1) {
		(void) sprintf(errbuf,"while renaming %s to %s\n",
			       backup,subsname);
		ss_perror(sci_idx,errno,errbuf);
		return(ERR);
	}
	return(delflag);
}

load_subs(argc,argv)
	int argc;
	char *argv[];
{
	ZSubscription_t subs[SUBSATONCE],subs2[SUBSATONCE],unsubs[SUBSATONCE];
	FILE *fp;
	int ind,unind,lineno,i,retval,type;
	short wgport;
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
			ss_perror(sci_idx,errno,
				  "while finding WindowGram port");
			return;
		} 

	file = (argc == 1) ? subsname : argv[1];
	
	fp = fopen(file,"r");

	
	ind = unind = 0;
	lineno = 1;
	
	if (fp)	for (;;lineno++) {
		if (!fgets(subline,sizeof subline,fp))
			break;
		if (*subline == '#' || !*subline)
			continue;
		subline[strlen(subline)-1] = '\0'; /* nuke newline */
		comma = index(subline,',');
		if (comma)
			comma2 = index(comma+1,',');
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
			unsubs[unind].class =
				malloc((unsigned)(strlen(subline)));
			/* skip the leading '!' */
			(void) strcpy(unsubs[unind].class,subline+1);
			unsubs[unind].classinst =
				malloc((unsigned)(strlen(comma+1)+1));
			(void) strcpy(unsubs[unind].classinst,comma+1);
			unsubs[unind].recipient =
				malloc((unsigned)(strlen(comma2+1)+1));
			(void) strcpy(unsubs[unind].recipient,comma2+1);
			unind++;
		} else {
			subs[ind].class =
				malloc((unsigned)(strlen(subline)+1));
			(void) strcpy(subs[ind].class,subline);
			subs[ind].classinst =
				malloc((unsigned)(strlen(comma+1)+1));
			(void) strcpy(subs[ind].classinst,comma+1);
			subs[ind].recipient =
				malloc((unsigned)(strlen(comma2+1)+1));
			(void) strcpy(subs[ind].recipient,comma2+1);
			ind++;
		}
		if (ind == SUBSATONCE) {
			fix_macros(subs,subs2,ind);
			if ((retval = (type == SUB)?
			     ZSubscribeTo(subs2,ind,(u_short)wgport):
			     ZUnsubscribeTo(subs2,ind,(u_short)wgport)) !=
			    ZERR_NONE) {
				ss_perror(sci_idx,retval,(type == SUB)?
					  "while subscribing":
					  "while unsubscribing");
				goto cleanup;
			}
			for (i=0;i<ind;i++) {
				free(subs[i].class);
				free(subs[i].classinst);
				free(subs[i].recipient);
			} 
			ind = 0;
		}
		if (unind == SUBSATONCE) {
			fix_macros(unsubs,subs2,unind);
			if ((retval = ZUnsubscribeTo(subs2,unind,(u_short)wgport)) != ZERR_NONE) {
				ss_perror(sci_idx,retval,
					  "while unsubscribing to un-subscriptions");
				goto cleanup;
			}
			for (i=0;i<unind;i++) {
				free(unsubs[i].class);
				free(unsubs[i].classinst);
				free(unsubs[i].recipient);
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
			ss_perror(sci_idx,retval,(type == SUB)?
				  "while subscribing":
				  "while unsubscribing");
			goto cleanup;
		}
		if (unind) {
			fix_macros(unsubs,subs2,unind);
			if ((retval =
			     ZUnsubscribeTo(subs2,unind,(u_short)wgport)) != ZERR_NONE) {
				ss_perror(sci_idx,retval,
					  "while unsubscribing to un-subscriptions");
				goto cleanup;
			}
		}
	}
cleanup:
	if (fp)
		(void) fclose(fp);	/* ignore errs--file is read-only */
	return;
}

current(argc,argv)
	int argc;
	char *argv[];
{
	FILE *fp;
	char errbuf[BUFSIZ];
	ZSubscription_t subs;
	int i,nsubs,retval,save,one,defs;
	short wgport;
	char *file,backup[BUFSIZ];
	
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
			ss_perror(sci_idx,errno,
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
			ss_perror(sci_idx,retval,"retrieving subscriptions");
			return;
		}

	if (save) {
		file = (argc == 1)?subsname:argv[1];
		(void) strcpy(backup,file);
		(void) strcat(backup,".temp");
		if (!(fp = fopen(backup,"w"))) {
			(void) sprintf(errbuf,"while opening %s for write",
				       backup);
			ss_perror(sci_idx,errno,errbuf);
			return;
		}
	}
	
	for (i=0;i<nsubs;i++) {
		one = 1;
		if ((retval = ZGetSubscriptions(&subs,&one)) != ZERR_NONE) {
			ss_perror(sci_idx,retval,"while getting subscription");
			if (save) {
				fprintf(stderr,"Subscriptions file not modified\n");
				(void) fclose(fp);
				(void) unlink(backup);
			}
			return;
		} 
		if (save)
			fprintf(fp,"%s,%s,%s\n",subs.class,subs.classinst,
				subs.recipient);
		else
			printf("Class %s Instance %s Recipient %s\n",
			       subs.class,subs.classinst,subs.recipient);
	}

	if (save) {
		if (fclose(fp) == EOF) {
			(void) sprintf(errbuf, "while closing %s", backup);
			ss_perror(sci_idx, errno, errbuf);
			return;
		}
		if (rename(backup,file) == -1) {
			(void) sprintf(errbuf,"while renaming %s to %s",
				       backup,file);
			ss_perror(sci_idx,retval,errbuf);
			(void) unlink(backup);
		}
	}
}

make_exist(filename)
	char *filename;
{
	char errbuf[BUFSIZ];
	FILE *fpout;
	
	if (!access(filename,F_OK))
		return (0);

	if (!(fpout = fopen(filename,"w"))) {
		(void) sprintf(errbuf,"while opening %s for write",filename);
		ss_perror(sci_idx,errno,errbuf);
		return (1);
	}

	if (fclose(fpout) == EOF) {
		(void) sprintf(errbuf, "while closing %s", filename);
		ss_perror(sci_idx, errno, errbuf);
		return(1);
	}
	return (0);
}

fix_macros(subs,subs2,num)
	ZSubscription_t *subs,*subs2;
	int num;
{
	int i;

	for (i=0;i<num;i++) {
		subs2[i] = subs[i];
		fix_macros2(subs[i].class,&subs2[i].class);
		fix_macros2(subs[i].classinst,&subs2[i].classinst);
		fix_macros2(subs[i].recipient,&subs2[i].recipient);
	}
}

fix_macros2(src,dest)
	char *src,**dest;
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
