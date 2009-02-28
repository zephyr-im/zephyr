/* This file is part of the Project Athena Zephyr Notification System.
 * It is one of the source files comprising zwgc, the Zephyr WindowGram
 * client.
 *
 *      Created by:     Marc Horowitz <marc@athena.mit.edu>
 *
 *      $Id$
 *
 *      Copyright (c) 1989 by the Massachusetts Institute of Technology.
 *      For copying and distribution information, see the file
 *      "mit-copyright.h".
 */

#include <sysdep.h>
#include <regex.h>

#if (!defined(lint) && !defined(SABER))
static const char rcsid_regexp_c[] = "$Id$";
#endif

#include "regexp.h"

int ed_regexp_match_p(test_string, pattern)
     string test_string;
     string pattern;
{
    regex_t RE;
    int retval;
    char errbuf[512];

    retval = regcomp(&RE, pattern, REG_NOSUB);
    if (retval != 0) {
	regerror(retval, &RE, errbuf, sizeof(errbuf));
	fprintf(stderr,"%s in regcomp %s\n",errbuf,pattern);
	return(0);
    }
    retval = regexec(&RE, test_string, 0, NULL, 0);
    if (retval != 0 && retval != REG_NOMATCH) {
	regerror(retval, &RE, errbuf, sizeof(errbuf));
	fprintf(stderr,"%s in regexec %s\n",errbuf,pattern);
	regfree(&RE);
	return(0);
    }
    regfree(&RE);
    return(retval == 0 ? 1 : 0);
}
