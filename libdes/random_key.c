/*
 * $Source$
 * $Author$
 *
 * Copyright 1988 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <mit-copyright.h>.
 *
 * These routines perform encryption and decryption using the DES
 * private key algorithm, or else a subset of it-- fewer inner loops.
 * ( AUTH_DES_ITER defaults to 16, may be less)
 *
 * Under U.S. law, this software may not be exported outside the US
 * without license from the U.S. Commerce department.
 *
 * The key schedule is passed as an arg, as well as the cleartext or
 * ciphertext.	 The cleartext and ciphertext should be in host order.
 *
 * These routines form the library interface to the des facilities.
 *
 * spm	8/85	MIT project athena
 */

#ifndef	lint
static char rcsid_random_key_c[] =
    "$Id$";
#endif

#include <mit-copyright.h>
#include <stdio.h>
#include <time.h>
#include <sys/time.h>

#include <des.h>

#ifdef USE_RAND48
#define random	lrand48
#define srandom	srand48
#endif

/* random_key */
int
des_random_key(key)
    des_cblock *key;
{
    /*
     * create a random des key; should force odd parity per byte;
     * parity is bits 8,16,...64 in des order, implies 0, 8, 16, ...
     * vax order
     */

    register unsigned int temp;
    register int odd;
    register unsigned char *c = (unsigned char *) key;
    unsigned long *k = (unsigned long *) key;
    static long p = 0;
    static long n = 0;

    int i,j;

    static struct timeval time;

    if (!p) {
	p = getpid();
#ifndef SOLARIS
	p ^= gethostid();
#endif
    }

    (void) gettimeofday(&time,(struct timezone *)0);
    /* randomize start */
    srandom(time.tv_usec ^ time.tv_sec ^ p ^ n++);

    *k++ = random();
    *k = random();

    /* make each byte parity odd */
    for (i = 0; i <= 7; i++) {
	odd = 0;
	temp = (unsigned int) *c;
	/* ignore bit 0, lsb,  it will be parity (on vax) */
	/* should do this with a table lookup */
	for (j = 0; j <= 6; j++) {
	    temp = temp >> 1;
	    odd ^= temp & 01;
	}
	/* set odd parity in lsb */
	if (!odd)
	    *c |= 1;
	else
	    *c &= ~1;
	c++;
    }

    return 0;
}
