/* This file is part of the Project Athena Zephyr Notification System.
 * It is one of the source files comprising zwgc, the Zephyr WindowGram
 * client.
 *
 *      Created by:     Marc Horowitz <marc@athena.mit.edu>
 *
 *      $Source$
 *      $Author$
 *
 *      Copyright (c) 1989 by the Massachusetts Institute of Technology.
 *      For copying and distribution information, see the file
 *      "mit-copyright.h".
 */

#if (!defined(lint) && !defined(SABER))
static char rcsid_regexp_c[] = "$Id$";
#endif

#include <stdio.h>
#include "regexp.h"

#ifdef SOLARIS
#include <libgen.h>
#endif

extern char *re_comp();
extern int re_exec();

int ed_regexp_match_p(test_string, pattern)
     string test_string;
     string pattern;
{
    char *comp_retval;
    int exec_retval;

    if (comp_retval = re_comp(pattern)) {
	fprintf(stderr,"%s in regex %s\n",comp_retval,pattern);
	return(0);
    }
    if ((exec_retval=re_exec(test_string)) == -1) {
	fprintf(stderr,"Internal error in re_exec()");
	return(0);
    }

    return(exec_retval);
}


/*
 * This is for AUX.
 * It is a wrapper around the C library regexp functions.
 */

#if defined(_AUX_SOURCE) || defined(SOLARIS)

static char *re;

char *re_comp(s)
    char *s;
{
    if(!s)
	return 0;
    if(re)
	free(re);

    if(!(re = regcmp(s, (char *)0)))
	return "Bad argument to re_comp";

    return 0;
}

int re_exec(s)
    char *s;
{
    return regex(re, s) != 0;
}

#endif
