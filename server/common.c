/* This file is part of the Project Athena Zephyr Notification System.
 * It contains functions for general use within the Zephyr server.
 *
 *	Created by:	John T. Kohl
 *
 *	$Source$
 *	$Author$
 *
 *	Copyright (c) 1987 by the Massachusetts Institute of Technology.
 *	For copying and distribution information, see the file
 *	"mit-copyright.h". 
 */

#include <zephyr/mit-copyright.h>

#ifndef lint
static char rcsid_common_c[] = "$Header$";
#endif lint

#include <stdio.h>

/* common routines for the server */

char *
strsave(sp) char *sp;
{
    register char *ret;

    if((ret = (char *) malloc(strlen(sp)+1)) == NULL)
      return(NULL);
    strcpy(ret,sp);
    return(ret);
}

