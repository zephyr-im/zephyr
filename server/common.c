/* This file is part of the Project Athena Zephyr Notification System.
 * It contains functions for general use within the Zephyr server.
 *
 *	Created by:	John T. Kohl
 *
 *	$Id$
 *
 *	Copyright (c) 1987 by the Massachusetts Institute of Technology.
 *	For copying and distribution information, see the file
 *	"mit-copyright.h". 
 */

#include <zephyr/mit-copyright.h>
#include "zserver.h"

#ifndef lint
#ifndef SABER
static const char rcsid_common_c[] =
    "$Id$";
#endif /* SABER */
#endif /* lint */

/* common routines for the server */

/* copy a string into a newly allocated area */

char *
strsave (sp)
    const char *sp;
{
    char *ret;

    ret = (char *) malloc(strlen(sp) + 1);
    if (!ret) {
	syslog(LOG_CRIT, "no mem strdup'ing");
	abort();
    }
    strcpy(ret, sp);
    return ret;
}

/* The "& 0x5f" provides case-insensitivity for ASCII. */

unsigned long
hash(string)
    const char *string;
{
    unsigned long hval = 0;
    char cp;

    while (1) {
	cp = *string++;
	if (!cp)
	    break;
	hval += cp & 0x5f;

	cp = *string++;
	if (!cp)
	    break;
	hval += (cp & 0x5f) * (3 + (1 << 16));

	cp = *string++;
	if (!cp)
	    break;
	hval += (cp & 0x5f) * (1 + (1 << 8));

	cp = *string++;
	if (!cp)
	    break;
	hval += (cp & 0x5f) * (1 + (1 << 12));

	cp = *string++;
	if (!cp)
	    break;
	hval += (cp & 0x5f) * (1 + (1 << 4));

	hval += ((long) hval) >> 18;
    }

    hval &= 0x7fffffff;
    return hval;
}

/* Output a name, replacing newlines with \n and single quotes with \q. */
void dump_quote(p, fp)
    char *p;
    FILE *fp;
{
    for (; *p; p++) {
	if (*p == '\'') {
	    putc('\\', fp);
	    putc('q', fp);
	} else if (*p == '\n') {
	    putc('\\', fp);
	    putc('n', fp);
	} else {
	    putc(*p, fp);
	}
    }
}

