/* This file is part of the Project Athena Zephyr Notification System.
 * It contains code for the "znol" command.
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

#include <pwd.h>

#ifndef lint
static char rcsid_znol_c[] = "$Header$";
#endif lint

#define SUBSATONCE 7
#define ON 1
#define OFF 0

main(argc,argv)
	int argc;
	char *argv[];
{
	ZSubscription_t subs[SUBSATONCE];
	ZLocations_t locations;
	FILE *fp;
	struct passwd *pwd;
	char anyonename[BUFSIZ],name[BUFSIZ],cleanname[BUFSIZ],*envptr;
	int onoff = ON,quiet = 0,justlist = 0;
	int retval,arg,ind,wgport,one,numlocs,i;

	if ((retval = ZInitialize()) != ZERR_NONE) {
		com_err(argv[0],retval,"initializing");
		exit (1);
	}

	envptr = (char *)getenv("WGFILE");
	if (!envptr) {
		sprintf(name,"/tmp/wg.%d",getuid());
		envptr = name;
	} 
	if (!(fp = fopen(envptr,"r"))) {
		fprintf(stderr,"Can't find WindowGram subscription port\n");
		exit (1);
	}
	fscanf(fp,"%d",&wgport);
	fclose(fp);
	
	envptr = (char *)getenv("HOME");
	if (envptr)
		strcpy(anyonename,envptr);
	else {
		if (!(pwd = getpwuid(getuid()))) {
			fprintf(stderr,"Who are you?\n");
			exit (1);
		}

		strcpy(anyonename,pwd->pw_dir);
	} 
	strcat(anyonename,"/.anyone");

	for (arg=1;arg<argc;arg++) {
		if (!strcmp(argv[arg],"on")) {
			onoff = ON;
			continue;
		}
		if (!strcmp(argv[arg],"off")) {
			onoff = OFF;
			continue;
		} 
		if (!strcmp(argv[arg],"-q")) {
			quiet = 1;
			continue;
		} 
		if (!strcmp(argv[arg],"-l")) {
			justlist = 1;
			continue;
		} 
		if (!strcmp(argv[arg],"-f")) {
			if (arg == argc-1) {
				fprintf(stderr,"No file name specified\n");
				exit (1);
			}
			strcpy(anyonename,argv[++arg]);
			continue;
		}
		printf("Usage: %s [on|off] [-f file]\n",argv[0]);
		exit (1);
	}

	if (quiet && justlist) {
		fprintf(stderr,"-q and -l cannot both be used\n");
		exit (1);
	} 

	if (!(fp = fopen(anyonename,"r"))) {
		fprintf(stderr,"Can't open %s for input\n",anyonename);
		exit (1);
	}

	ind = 0;
	
	for (;;) {
		if (!fgets(cleanname,sizeof cleanname,fp))
			break;
		/* Get rid of old-style nol entries, just in case */
		cleanname[strlen(cleanname)-1] = '\0';
		while (cleanname[strlen(cleanname)-1] == ' ')
			cleanname[strlen(cleanname)-1] = '\0';
		if (*cleanname == '@' || !*cleanname)
			continue;
		subs[ind].class = LOGIN_CLASS;
		strcpy(name,cleanname);
		if (!index(name,'@')) {
			strcat(name,"@");
			strcat(name,ZGetRealm());
		}
		subs[ind].classinst = (char *)malloc(strlen(name)+1);
		strcpy(subs[ind].classinst,name);
		subs[ind++].recipient = "";

		if (!quiet && onoff == ON) {
			if ((retval = ZLocateUser(name,&numlocs))
			    != ZERR_NONE) {
				com_err(argv[0],retval,"locating user");
				exit(1);
			}
			one = 1;
			if (numlocs) {
				for (i=0;i<numlocs;i++) {
					if ((retval =
					     ZGetLocations(&locations,&one))
					    != ZERR_NONE) {
						com_err(argv[0],retval,
							"getting location");
						continue;
					}
					if (one != 1) {
						printf("%s: internal failure while getting location\n",argv[0]);
						exit(1);
					}
					printf("%s: %s\t%s\t%s\n",cleanname,
					       locations.host,
					       locations.tty,
					       locations.time);
				}
			}
		}
		
		if (ind == SUBSATONCE) {
			if (!justlist)
				if ((retval = (onoff==ON)?
				     ZSubscribeTo(subs,ind,(u_short)wgport):
				     ZUnsubscribeTo(subs,ind,(u_short)wgport)) !=
				    ZERR_NONE) {
					com_err(argv[0],retval,(onoff==ON)?
						"subscribing":
						"unsubscribing");
					exit(1);
				} 
			for (ind=0;ind<SUBSATONCE;ind++)
				free(subs[ind].classinst);
			ind = 0;
		}
	}

	if (ind && !justlist)
		if ((retval = (onoff==ON)?
		     ZSubscribeTo(subs,ind,(u_short)wgport):
		     ZUnsubscribeTo(subs,ind,(u_short)wgport)) !=
		    ZERR_NONE) {
			com_err(argv[0],retval,(onoff==ON)?
				"subscribing":
				"unsubscribing");
			exit(1);
		} 

	fclose(fp);
}
