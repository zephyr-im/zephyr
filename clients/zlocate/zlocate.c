/* This file is part of the Project Athena Zephyr Notification System.
 * It contains code for the "locate" command.
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

#ifndef lint
static char rcsid_locate_c[] = "$Header$";
#endif lint

main(argc,argv)
	int argc;
	char *argv[];
{
	int retval,numlocs,i,one,ourargc;
	char *whoami,bfr[BUFSIZ],user[BUFSIZ];
	ZLocations_t locations[1];
	
	if ((retval = ZInitialize()) != ZERR_NONE) {
		com_err(whoami,retval,"while initializing");
		exit(1);
	} 

	whoami = argv[0];

	if (argc < 2) {
		printf("Usage: %s user ... \n",whoami);
		exit(1);
	}
	
	argv++;
	argc--;

	one = 1;
	
	ourargc = argc;
	
	for (;argc--;argv++) {
		strcpy(user,*argv);
		if (!index(user,'@')) {
			strcat(user,"@");
			strcat(user,ZGetRealm());
		} 
		if ((retval = ZLocateUser(user,&numlocs)) != ZERR_NONE) {
			sprintf(bfr,"while locating user %s",user);
			com_err(whoami,retval,bfr);
			continue;
		}
		if (ourargc > 1)
			printf("\t%s:\n",user);
		if (!numlocs) {
			printf("Not logged-in\n");
			if (argc)
				printf("\n");
			continue;
		}
		for (i=0;i<numlocs;i++) {
			if ((retval = ZGetLocations(locations,&one))
			    != ZERR_NONE) {
				com_err(whoami,retval,
					"while getting location");
				continue;
			}
			if (one != 1) {
				printf("%s: internal failure while getting location\n",whoami);
				exit(1);
			} 
			printf("%s\t  %s\n",locations[0].host,
			       locations[0].time);
		}
		if (argc)
			printf("\n");
		ZFlushLocations();
	}
}
