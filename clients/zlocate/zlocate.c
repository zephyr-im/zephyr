/* This file is part of the Project Athena Zephyr Notification System.
 * It contains code for the "zlocate" command.
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
#include <string.h>

#ifndef lint
static char rcsid_zlocate_c[] = "$Header$";
#endif lint

char *whoami;

void usage()
{
   printf("Usage: %s [ -a | -d ] user ... \n",whoami);
   exit(1);
}

main(argc,argv)
	int argc;
	char *argv[];
{
	int retval,numlocs,i,one,ourargc,found,auth;
	char bfr[BUFSIZ],user[BUFSIZ];
	ZLocations_t locations;
	
	whoami = argv[0];
	auth = -1;

	if (argc < 2) usage();

	if ((retval = ZInitialize()) != ZERR_NONE) {
		com_err(whoami,retval,"while initializing");
		exit(1);
	} 

	argv++;
	argc--;

	for (i=0; argv[i]; i++)
	  if (argv[i][0] == '-')
	    switch (argv[i][1]) {
		  case 'a':
		    if (auth != -1) usage();
		    auth = 1;
		    break;
		  case 'd':
		    if (auth != -1) usage();
		    auth = 0;
		    break;
		  default:
		    usage();
		    break;
	    }

	one = 1;
	found = 0;
	ourargc = argc - ((auth == -1)?0:1);
	
	if (auth == -1) auth = 1;

	for (;argc--;argv++) {
		if ((*argv)[0] == '-') continue;
		(void) strcpy(user,*argv);
		if (!index(user,'@')) {
			(void) strcat(user,"@");
			(void) strcat(user,ZGetRealm());
		} 
		if ((retval = ZNewLocateUser(user,&numlocs,
					     (auth?ZAUTH:ZNOAUTH)))
		    != ZERR_NONE) {
			(void) sprintf(bfr,"while locating user %s",user);
			com_err(whoami,retval,bfr);
			continue;
		}
		if (ourargc > 1)
			printf("\t%s:\n",user);
		if (!numlocs) {
			printf("Hidden or not logged-in\n");
			if (argc)
				printf("\n");
			continue;
		}
		for (i=0;i<numlocs;i++) {
			if ((retval = ZGetLocations(&locations,&one))
			    != ZERR_NONE) {
				com_err(whoami,retval,
					"while getting location");
				continue;
			}
			if (one != 1) {
				printf("%s: internal failure while getting location\n",whoami);
				exit(1);
			}
			/* just use printf; make the field widths one
			 * smaller to deal with the extra separation space.
			 */
			printf("%-*s %-*s %s\n",
			       42, locations.host,
			       7, locations.tty,
			       locations.time);
			found++;
		}
		if (argc)
			printf("\n");
		(void) ZFlushLocations();
	}
	if (!found)
	    exit(1);
	exit(0);
}
