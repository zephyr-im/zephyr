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

#include <zephyr/zephyr.h>

#include <pwd.h>
#include <string.h>

#ifndef lint
static char rcsid_znol_c[] = "$Id$";
#endif 

#define SUBSATONCE 7
#define ON 1
#define OFF 0

main(argc,argv)
	int argc;
	register char *argv[];
{
	register char *cp;
	ZSubscription_t subs[SUBSATONCE];
	ZLocations_t locations;
	FILE *fp;
	struct passwd *pwd;
	char anyonename[BUFSIZ],name[BUFSIZ],cleanname[BUFSIZ],*envptr;
	char *comment_ptr;
	int onoff = ON,quiet = 0,justlist = 0,useronly = 0, filenamed = 0;
	int retval,arg,ind,one,numlocs,i;
	short wgport;

	if ((retval = ZInitialize()) != ZERR_NONE) {
		com_err(argv[0],retval,"initializing");
		exit (1);
	}

	for (arg=1;arg<argc;arg++) {
		if (!strcmp(argv[arg],"on")) {
			onoff = ON;
			continue;
		}
		if (!strcmp(argv[arg],"off")) {
			onoff = OFF;
			continue;
		} 
		if (argv[arg][0] == '-') {
			char opt = argv[arg][1];
			if (opt == 0 || argv[arg][2] != 0)
				goto usage;
			switch (argv[arg][1]) {
			case 'q':
				quiet = 1;
				break;
			case 'l':
				justlist = 1;
				break;
			case 'f':
				if (arg == argc-1) {
					fprintf(stderr,"No file name specified\n");
					goto usage;
				}
				(void) strcpy(anyonename,argv[++arg]);
				filenamed = 1;
				break;
			case 'u':
				if (arg == argc-1) {
					fprintf(stderr,"No username specified\n");
					goto usage;
				}
				(void) strcpy(cleanname,argv[++arg]);
				useronly = 1;
				break;
			default:
				goto usage;
			}
			continue;
		}
	    usage:
		fprintf(stderr,"Usage: %s [on|off] [-q | -l] [-f file | -u username]\n", argv[0]);
		exit (1);
	}

	if (quiet && justlist) {
		fprintf(stderr,"-q and -l cannot both be used\n");
		goto usage;
	} 
	if (useronly && filenamed) {
		fprintf(stderr,"-u and -f cannot both be used\n");
		goto usage;
	} 
	if (!justlist)
		if ((wgport = ZGetWGPort()) == -1) {
			com_err(argv[0],errno,"while getting WindowGram port");
			exit(1);
		}
	
	if (!useronly) {
		/* If no filename specified, get the default */
		if (!filenamed) {
			envptr = getenv("HOME");
			if (envptr)
			    (void) strcpy(anyonename,envptr);
			else {
				if (!(pwd = getpwuid((int) getuid()))) {
					fprintf(stderr,"You are not listed in the password file.\n");
					exit (1);
				}
				(void) strcpy(anyonename,pwd->pw_dir);
			}
			(void) strcat(anyonename,"/.anyone");
		}

		/* if the filename is "-", read stdin */
		if (strcmp(anyonename,"-") == 0) {
			fp = stdin;
		} else if (!(fp = fopen(anyonename,"r"))) {
			fprintf(stderr,"Can't open %s for input\n",anyonename);
			exit (1);
		}
	}

	ind = 0;
	
	for (;;) {
		if (!useronly) {
		    if (!fgets(cleanname,sizeof cleanname,fp))
			break;
		    if (cleanname[0] == '#' || cleanname[0] == '\0' ||
			cleanname[0] == '\n')
			continue;	/* ignore comment and empty lines */
		    if (comment_ptr = strchr(cleanname, '#'))
			*comment_ptr = '\0'; /* Ignore from # onwards */
		    /* Get rid of old-style nol entries, just in case */
		    cp = cleanname + strlen(cleanname) - 1;
		    *cp = '\0';
		    while(*--cp == ' ')
			*cp = '\0';
		    if (*cleanname == '@' || !*cleanname)
			continue;
		} else if (ind)
		    break;		/* only do the one name */

		subs[ind].zsub_class = LOGIN_CLASS;
		(void) strcpy(name,cleanname);
		if (!strchr(name,'@')) {
			cp = name + strlen(name);
			*cp++ = '@';
			(void) strcpy(cp,ZGetRealm());
		}
		if ((subs[ind].zsub_classinst = malloc((unsigned)(strlen(name)+1))) == NULL) {
			fprintf (stderr, "znol: out of memory");
			exit (1);
		}
		(void) strcpy(subs[ind].zsub_classinst, name);
		subs[ind++].zsub_recipient = "";

		if (!quiet && onoff == ON) {
			if ((retval = ZLocateUser(name,&numlocs,ZAUTH))
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
				free(subs[ind].zsub_classinst);
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

	if (!useronly)
	    (void) fclose(fp);		/* file is open read-only,
					   ignore errs */
	exit(0);
}
