/*
 * $Source$
 * $Author$
 *
 * Copyright 1985, 1986, 1987, 1988 by the Massachusetts Institute
 * of Technology.
 *
 * For copying and distribution information, please see the file
 * <mit-copyright.h>.
 *
 * This routine computes the DES key schedule given a key.  The
 * permutations and shifts have been done at compile time, resulting
 * in a direct one-step mapping from the input key to the key
 * schedule.
 *
 * Also checks parity and weak keys.
 *
 * Watch out for the subscripts -- most effectively start at 1 instead
 * of at zero.  Maybe some bugs in that area.
 *
 * DON'T change the data types for arrays and such, or it will either
 * break or run slower.  This was optimized for Uvax2.
 *
 * In case the user wants to cache the computed key schedule, it is
 * passed as an arg.  Also implies that caller has explicit control
 * over zeroing both the key schedule and the key.
 *
 * All registers labeled imply Vax using the Ultrix or 4.2bsd compiler.
 *
 * Originally written 6/85 by Steve Miller, MIT Project Athena.
 */

#ifndef	lint
static char rcsid_key_sched_c[] =
    "$Id$";
#endif

#include <mit-copyright.h>
#include <stdio.h>
#include "des.h"

int
des_key_sched(k,schedule)
    register des_cblock k;
    des_key_schedule schedule;
{
    if (!des_check_key_parity(k))	/* bad parity --> return -1 */
	return(-1);

    /* check against weak keys */
    if (des_is_weak_key(k))
	return(-2);

    make_key_sched(k,schedule);

    /* if key was good, return 0 */
    return 0;
}
