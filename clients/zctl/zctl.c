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
#include "ss.h"
#include <pwd.h>
#include <netdb.h>

#ifndef lint
static char rcsid_zctl_c[] = "$Header$";
#endif lint

#define SUBSATONCE 7
#define SUB 0
#define UNSUB 1
#define LIST 2

#define DEFAULT_SUBS "/etc/athena/windowgram.subs"

#define TOKEN_HOSTNAME "%host%"
#define TOKEN_CANONNAME "%canon%"
#define TOKEN_ME "%me%"

char *index(),*malloc();

int wgport,sci_idx;
char subsname[BUFSIZ];
char ourhost[BUFSIZ],ourhostcanon[BUFSIZ];

extern ss_request_table zctl_cmds;

main(argc,argv)
	int argc;
	char *argv[];
{
	struct passwd *pwd;
	struct hostent *hent;
	FILE *fp;
	char ssline[BUFSIZ],buf[BUFSIZ],*envptr;
	int retval,code,i;

	if ((retval = ZInitialize()) != ZERR_NONE) {
		com_err(argv[0],retval,"while initializing");
		exit (1);
	}

	envptr = (char *)getenv("WGFILE");
	if (!envptr) {
		sprintf(buf,"/tmp/wg.%d",getuid());
		envptr = buf;
	} 
	if (!(fp = fopen(envptr,"r"))) {
		fprintf(stderr,"Can't find WindowGram subscription port\n");
		exit (1);
	}
	fscanf(fp,"%d",&wgport);
	fclose(fp);
       
	envptr = (char *)getenv("HOME");
	if (envptr)
		strcpy(subsname,envptr);
	else {
		if (!(pwd = getpwuid(getuid()))) {
			fprintf(stderr,"Who are you?\n");
			exit (1);
		}

		strcpy(subsname,pwd->pw_dir);
	} 
	strcat(subsname,"/.subscriptions");

	if (gethostname(ourhost,BUFSIZ) == -1) {
		com_err(argv[0],errno,"while getting host name");
		exit (1);
	}

	if (!(hent = gethostbyname(ourhost))) {
		com_err(argv[0],errno,"while canonicalizing host name");
		exit (1);
	}

	strcpy(ourhostcanon,hent->h_name);
	
	sci_idx = ss_create_invocation("zctl","",0,&zctl_cmds,&code);
	if (code) {
		ss_perror(sci_idx,code,"while creating invocation");
		exit(1);
	}

	if (argc > 1) {
		*ssline = '\0';
		for (i=1;i<argc;i++)
			sprintf(ssline+strlen(ssline),"%s ",argv[i]);
		ssline[strlen(ssline)-1] = '\0';
		ss_execute_line(sci_idx,ssline,&code);
		if (code)
			ss_perror(sci_idx,code,ssline);
		exit((code != 0));
	} 

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
		strcpy(subsname,argv[1]);
}

cancel_subs(argc,argv)
	int argc;
	char *argv[];
{
	int retval;

	if (argc != 1) {
		fprintf(stderr,"Usage: %s\n",argv[0]);
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
	ZSubscription_t sub,sub2;
	
	if (argc > 4 || argc < 3) {
		fprintf(stderr,"Usage: %s class instance [*]\n",argv[0]);
		return;
	}
	
	sub.class = argv[1];
	sub.classinst = argv[2];
	sub.recipient = (argc == 3)?ZGetSender():argv[3];

	fix_macros(&sub,&sub2,1);
	
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
	
	if (argc > 4 || argc < 3) {
		fprintf(stderr,"Usage: %s class instance [*]\n",argv[0]);
		return;
	}

	sub.class = argv[1];
	sub.classinst = argv[2];
	sub.recipient = (argc == 3)?ZGetSender():argv[3];

	if (!strcmp(argv[0],"add")) {
		if (make_exist(subsname))
			return;
		if (!(fp = fopen(subsname,"a"))) {
			sprintf(errbuf,"while opening %s for append",subsname);
			ss_perror(sci_idx,errno,errbuf);
			return;
		} 
		fprintf(fp,"%s,%s,%s\n",sub.class,sub.classinst,
			sub.recipient);
		fclose(fp);
		fix_macros(&sub,&sub2,1);
		if ((retval = ZSubscribeTo(&sub2,1,(u_short)wgport)) !=
		    ZERR_NONE)
			ss_perror(sci_idx,retval,"while subscribing");
		return;
	}

	delflag = 0;
	sprintf(ourline,"%s,%s,%s",sub.class,sub.classinst,sub.recipient);
	if (make_exist(subsname))
		return;
	if (!(fp = fopen(subsname,"r"))) {
		sprintf(errbuf,"while opening %s for read",subsname);
		ss_perror(sci_idx,errno,errbuf);
		return;
	} 
	sprintf(backup,"%s.temp",subsname);
	unlink(backup);
	if (!(fpout = fopen(backup,"w"))) {
		sprintf(errbuf,"while opening %s for writing",backup);
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
		fprintf(stderr,"Couldn't find class %s instance %s recipient %s\n",
			sub.class,sub.classinst,subsname);
	fclose(fp);
	fclose(fpout);
	if (rename(backup,subsname) == -1) {
		sprintf(errbuf,"while renaming %s to %s\n",backup,subsname);
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
	char *comma,*comma2,*file,subline[BUFSIZ],errbuf[BUFSIZ];

	if (argc > 2) {
		fprintf(stderr,"Usage: %s [file]\n",argv[0]);
		return;
	}

	file = (argc == 1) ? subsname : argv[1];
	
	if (!(fp = fopen(file,"r")))
		if (!(fp = fopen(DEFAULT_SUBS,"r"))) {
			sprintf(errbuf,"while opening %s for read",file);
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
		subs[ind].class = malloc(strlen(subline)+1);
		strcpy(subs[ind].class,subline);
		subs[ind].classinst = malloc(strlen(comma+1)+1);
		strcpy(subs[ind].classinst,comma+1);
		subs[ind].recipient = malloc(strlen(comma2+1)+1);
		strcpy(subs[ind].recipient,comma2+1);
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
					exit(1);
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
			exit(1);
		}
	} 

	fclose(fp);
}

current(argc,argv)
	int argc;
	char *argv[];
{
	FILE *fp;
	char errbuf[BUFSIZ];
	ZSubscription_t subs;
	int i,nsubs,retval,save,one;
	char *file,backup[BUFSIZ];
	
	save = 0;
	
	if (!strcmp(argv[0],"save"))
		save = 1;

	if (argc != 1 && !(save && argc == 2)) {
		fprintf(stderr,"Usage: %s%s\n",argv[0],save?" [filename]":"");
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
		strcpy(backup,file);
		strcat(backup,".temp");
		if (!(fp = fopen(backup,"w"))) {
			sprintf(errbuf,"while opening %s for write",file);
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
				fclose(fp);
				unlink(backup);
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
		fclose(fp);
		if (rename(backup,file) == -1) {
			sprintf(errbuf,"while renaming %s to %s",backup,file);
			ss_perror(sci_idx,retval,errbuf);
			unlink(backup);
		}
	}
}

make_exist(filename)
	char *filename;
{
	char bfr[BUFSIZ],errbuf[BUFSIZ];
	FILE *fp,*fpout;
	
	if (!access(filename,0))
		return (0);

	fprintf(stderr,"Copying %s to %s\n",DEFAULT_SUBS,filename);

	if (!(fp = fopen(DEFAULT_SUBS,"r"))) {
		sprintf(errbuf,"while opening %s for read",DEFAULT_SUBS);
		ss_perror(sci_idx,errno,errbuf);
		return (1);
	}

	if (!(fpout = fopen(filename,"w"))) {
		sprintf(errbuf,"while opening %s for write",filename);
		ss_perror(sci_idx,errno,errbuf);
		fclose(fp);
		return (1);
	}

	while (fgets(bfr,sizeof bfr,fp))
		fprintf(fpout,"%s",bfr);

	fclose(fp);
	fclose(fpout);

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
