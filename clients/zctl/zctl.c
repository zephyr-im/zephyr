/* This file is part of the Project Athena Zephyr Notification System.
 * It contains code for the "zctl" command.
 *
 *	Created by:	Robert French
 *
 *	$Source$
 *	$Author$
 *
 *	Copyright (c) 1987 by the Massachusetts Institute of Technology.
 *	For copying and distribution information, see the file
 *	"mit-copyright.h". 
 */

#include <zephyr/mit-copyright.h>

#include <zephyr/zephyr.h>
#include <ctype.h>
#include <ss.h>
#include <pwd.h>
#include <netdb.h>
#include <string.h>
#include <sys/file.h>

#ifndef lint
static char rcsid_zctl_c[] = "$Header$";
#endif lint

#define SUBSATONCE 7
#define SUB 0
#define UNSUB 1
#define LIST 2

#define DEFAULT_SUBS "/etc/athena/zephyr.subs"
#define USERS_SUBS "/.zephyr.subs"
#define OLD_SUBS "/.subscriptions"

#define TOKEN_HOSTNAME "%host%"
#define TOKEN_CANONNAME "%canon%"
#define TOKEN_ME "%me%"

#define _toupper(c) (islower(c)?toupper(c):c)

char *index(),*malloc();

int sci_idx;
char subsname[BUFSIZ];
char ourhost[BUFSIZ],ourhostcanon[BUFSIZ];

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
			com_err(argv[0], retval, "renaming .subscriptions");
	}
	
	if (gethostname(ourhost,BUFSIZ) == -1) {
		com_err(argv[0],errno,"while getting host name");
		exit (1);
	}

	if (!(hent = gethostbyname(ourhost))) {
		com_err(argv[0],errno,"while canonicalizing host name");
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
		ss_execute_line(sci_idx,ssline,&code);
		if (code)
			ss_perror(sci_idx,code,ssline);
		exit((code != 0));
	} 

	printf("ZCTL version %d.%d - Type '?' for a list of commands.\n\n",
	       ZVERSIONMAJOR,ZVERSIONMINOR);
	
	ss_listen(sci_idx,&code);
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
	
	notice.z_kind = HMCTL;
	notice.z_port = 0;
	notice.z_class = HM_CTL_CLASS;
	notice.z_class_inst = HM_CTL_CLIENT;

	if (!strcmp(argv[0],"hm_flush"))
		notice.z_opcode = CLIENT_FLUSH;
	if (!strcmp(argv[0],"new_server"))
		notice.z_opcode = CLIENT_NEW_SERVER;

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

	if (!cistrcmp(argv[1],"exposure")) {
		setting_exp = 1;
		if (argc != 3) {
			fprintf(stderr,"An exposure setting must be specified.\n");
			return;
		}
		exp_level = (char *)0;
		if (!cistrcmp(argv[2],EXPOSE_NONE))
			exp_level = EXPOSE_NONE;
		if (!cistrcmp(argv[2],EXPOSE_OPSTAFF))
			exp_level = EXPOSE_OPSTAFF;
		if (!cistrcmp(argv[2],EXPOSE_REALMVIS))
			exp_level = EXPOSE_REALMVIS;
		if (!cistrcmp(argv[2],EXPOSE_REALMANN))
			exp_level = EXPOSE_REALMANN;
		if (!cistrcmp(argv[2],EXPOSE_NETVIS))
			exp_level = EXPOSE_NETVIS;
		if (!cistrcmp(argv[2],EXPOSE_NETANN))
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
		varcat[0] = '\0';
		for (i=2;i<argc;i++) {
			if (i != 2)
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
		} 
		return;
	} 
}

cistrcmp(s1,s2)
	char *s1,*s2;
{
	while (*s1 && *s2) {
		if (_toupper(*s1) != _toupper(*s2))
			return 1;
		s1++;
		s2++;
	}
	return (*s1 || *s2);
} 

unset_var(argc,argv)
	int argc;
	char *argv[];
{
	int retval,i;
	
	if (argc < 2) {
		fprintf(stderr,"Usage: %s <varname> <varname> ...\n",
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
	ZSubscription_t sub,sub2;
	FILE *fp,*fpout;
	char errbuf[BUFSIZ],subline[BUFSIZ],ourline[BUFSIZ];
	char backup[BUFSIZ];
	int delflag,retval;
	short wgport;
	
	if (argc > 4 || argc < 3) {
		fprintf(stderr,"Usage: %s class instance [*]\n",argv[0]);
		return;
	}

	sub.class = argv[1];
	sub.classinst = argv[2];
	sub.recipient = (argc == 3)?TOKEN_ME:argv[3];

 	if ((wgport = ZGetWGPort()) == -1) {
		ss_perror(sci_idx,errno,"while finding WindowGram port");
		return;
	} 

	if (!strcmp(argv[0],"add")) {
		if (make_exist(subsname))
			return;
		if (!(fp = fopen(subsname,"a"))) {
			(void) sprintf(errbuf,"while opening %s for append",subsname);
			ss_perror(sci_idx,errno,errbuf);
			return;
		} 
		fprintf(fp,"%s,%s,%s\n",sub.class,sub.classinst,
			sub.recipient);
		if (fclose(fp) == EOF) {
			(void) sprintf(errbuf, "while closing %s", subsname);
			ss_perror(sci_idx, errno, errbuf);
			return;
		}
		fix_macros(&sub,&sub2,1);
		if ((retval = ZSubscribeTo(&sub2,1,(u_short)wgport)) !=
		    ZERR_NONE)
			ss_perror(sci_idx,retval,"while subscribing");
		return;
	}

	delflag = 0;
	(void) sprintf(ourline,"%s,%s,%s",
		       sub.class,
		       sub.classinst,
		       sub.recipient);
	if (make_exist(subsname))
		return;
	if (!(fp = fopen(subsname,"r"))) {
		(void) sprintf(errbuf,"while opening %s for read",subsname);
		ss_perror(sci_idx,errno,errbuf);
		return;
	} 
	(void) sprintf(backup,"%s.temp",subsname);
	(void) unlink(backup);
	if (!(fpout = fopen(backup,"w"))) {
		(void) sprintf(errbuf,"while opening %s for writing",backup);
		ss_perror(sci_idx,errno,errbuf);
		return;
	} 
	for (;;) {
		if (!fgets(subline,sizeof subline,fp))
			break;
		if (*subline)
			subline[strlen(subline)-1] = '\0';
		if (strcmp(subline,ourline))
			fprintf(fpout,"%s\n",subline);
		else
			delflag = 1;
	}
	if (!delflag)
		fprintf(stderr,
			"Couldn't find class %s instance %s recipient %s\n",
			sub.class,sub.classinst,subsname);
	(void) fclose(fp);		/* open read-only, ignore errs */
	if (fclose(fpout) == EOF) {
		(void) sprintf(errbuf, "while closing %s",backup);
		ss_perror(sci_idx, errno, errbuf);
		return;
	}
	if (rename(backup,subsname) == -1) {
		(void) sprintf(errbuf,"while renaming %s to %s\n",
			       backup,subsname);
		ss_perror(sci_idx,errno,errbuf);
		return;
	}
	fix_macros(&sub,&sub2,1);
	if ((retval = ZUnsubscribeTo(&sub2,1,(u_short)wgport)) !=
	    ZERR_NONE)
		ss_perror(sci_idx,retval,"while subscribing");
}

load_subs(argc,argv)
	int argc;
	char *argv[];
{
	ZSubscription_t subs[SUBSATONCE],subs2[SUBSATONCE];
	FILE *fp;
	int ind,lineno,i,retval,type;
	short wgport;
	char *comma,*comma2,*file,subline[BUFSIZ],errbuf[BUFSIZ];

	if (argc > 2) {
		fprintf(stderr,"Usage: %s [file]\n",argv[0]);
		return;
	}

 	if ((wgport = ZGetWGPort()) == -1) {
		ss_perror(sci_idx,errno,"while finding WindowGram port");
		return;
	} 

	file = (argc == 1) ? subsname : argv[1];
	
	if (!(fp = fopen(file,"r")))
		if (!(fp = fopen(DEFAULT_SUBS,"r"))) {
			(void) sprintf(errbuf,
				       "while opening %s for read",file);
			ss_perror(sci_idx,errno,errbuf);
			return;
		} 

	if (*argv[0] == 'u')
		type = UNSUB;
	else
		if (!strcmp(argv[0],"list") || !strcmp(argv[0],"ls"))
			type = LIST;
		else
			type = SUB;
	
	ind = 0;
	lineno = 1;
	
	for (;;lineno++) {
		if (!fgets(subline,sizeof subline,fp))
			break;
		if (*subline == '#' || !*subline)
			continue;
		subline[strlen(subline)-1] = '\0';
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
		subs[ind].class = malloc((unsigned)(strlen(subline)+1));
		(void) strcpy(subs[ind].class,subline);
		subs[ind].classinst = malloc((unsigned)(strlen(comma+1)+1));
		(void) strcpy(subs[ind].classinst,comma+1);
		subs[ind].recipient = malloc((unsigned)(strlen(comma2+1)+1));
		(void) strcpy(subs[ind].recipient,comma2+1);
		ind++;
		if (type == LIST)
			printf("Class %s instance %s recipient %s\n",
			       subs[0].class,subs[0].classinst,
			       subs[0].recipient);
		else {
			if (ind == SUBSATONCE) {
				fix_macros(subs,subs2,ind);
				if ((retval = (type == SUB)?
				     ZSubscribeTo(subs2,ind,(u_short)wgport):
				     ZUnsubscribeTo(subs2,ind,(u_short)wgport)) !=
				    ZERR_NONE) {
					ss_perror(sci_idx,retval,(type == SUB)?
						"while subscribing":
						"while unsubscribing");
					return;
				}
			}
		} 
		if (type == LIST || ind == SUBSATONCE) {
			for (i=0;i<ind;i++) {
				free(subs[i].class);
				free(subs[i].classinst);
				free(subs[i].recipient);
			} 
			ind = 0;
		} 
	}
	
	if (ind) {
		fix_macros(subs,subs2,ind);
		if ((retval = (type == SUB)?ZSubscribeTo(subs2,ind,(u_short)wgport):
		     ZUnsubscribeTo(subs2,ind,(u_short)wgport)) != ZERR_NONE) {
			ss_perror(sci_idx,retval,(type == SUB)?
				"while subscribing":
				"while unsubscribing");
			return;
		}
	} 

	(void) fclose(fp);		/* ignore errs--file is read-only */
}

current(argc,argv)
	int argc;
	char *argv[];
{
	FILE *fp;
	char errbuf[BUFSIZ];
	ZSubscription_t subs;
	int i,nsubs,retval,save,one;
	short wgport;
	char *file,backup[BUFSIZ];
	
	save = 0;
	
	if (!strcmp(argv[0],"save"))
		save = 1;

	if (argc != 1 && !(save && argc == 2)) {
		fprintf(stderr,"Usage: %s%s\n",argv[0],save?" [filename]":"");
		return;
	}

 	if ((wgport = ZGetWGPort()) == -1) {
		ss_perror(sci_idx,errno,"while finding WindowGram port");
		return;
	} 

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
				       file);
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
	char bfr[BUFSIZ],errbuf[BUFSIZ];
	FILE *fp,*fpout;
	
	if (!access(filename,F_OK))
		return (0);

	fprintf(stderr,"Copying %s to %s\n",DEFAULT_SUBS,filename);

	if (!(fp = fopen(DEFAULT_SUBS,"r"))) {
		(void) sprintf(errbuf,"while opening %s for read",
			       DEFAULT_SUBS);
		ss_perror(sci_idx,errno,errbuf);
		return (1);
	}

	if (!(fpout = fopen(filename,"w"))) {
		(void) sprintf(errbuf,"while opening %s for write",filename);
		ss_perror(sci_idx,errno,errbuf);
		(void) fclose(fp);
		return (1);
	}

	while (fgets(bfr,sizeof bfr,fp))
		fprintf(fpout,"%s",bfr);

	(void) fclose(fp);
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
