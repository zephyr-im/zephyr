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
strsave (const char *sp)
{
    char *ret;

    ret = strdup(sp);
    if (!ret) {
	syslog(LOG_CRIT, "no mem strdup'ing");
	abort();
    }
    return ret;
}

/* The "& 0x5f" provides case-insensitivity for ASCII. */

unsigned long
hash(const char *string)
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
void
dump_quote(char *p, FILE *fp)
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

/* Pull the address out of the packet for dispatching.  Doesn't do anything
 *  special, and will need to change signatures when ipv6 support happens.  But
 *  it'll be in one place....
 */
void
notice_extract_address(ZNotice_t *notice, struct sockaddr_in *addr)
{
    /*
     * We get the address out of the uid rather than the 
     * Hopefully by the time a server will actually be speaking ipv6, it won't have
     * to worry about talking to other <3.0 realms
     */
    memset(addr, 0, sizeof(*addr));
    addr->sin_addr.s_addr = notice->z_uid.zuid_addr.s_addr;
    addr->sin_port = notice->z_port;
    addr->sin_family = AF_INET;
}
