/* This file is part of the Project Athena Zephyr Notification System.
 * It contains source for the ZGetWGPort function.
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
/* $Header$ */

#ifndef lint
static char rcsid_ZGetWGPort_c[] = "$Header$";
#endif lint

#include <zephyr/mit-copyright.h>

#include <zephyr/zephyr_internal.h>

int ZGetWGPort()
{
	char *envptr,name[128];
	FILE *fp;
	int wgport;
	
	envptr = (char *)getenv("WGFILE");
	if (!envptr) {
		sprintf(name,"/tmp/wg.%d",getuid());
		envptr = name;
	} 
	if (!(fp = fopen(envptr,"r")))
		return (-1);
	fscanf(fp,"%d",&wgport);
	fclose(fp);

	return (wgport);
}
