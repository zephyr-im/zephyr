/*
 *	$Source$
 *	$Header$
 */

#ifndef lint
static char *rcsid_common_c = "$Header$";
#endif lint

/* common routines */

#include <zephyr/mit-copyright.h>
#include <stdio.h>

char *
strsave(sp) char *sp;
{
    register char *ret;

    if((ret = (char *) malloc(strlen(sp)+1)) == NULL) {
	error("out of memory in strsave()\n");
	return(NULL);
    }
    strcpy(ret,sp);
    return(ret);
}

