/*
 * $Source$
 * $Author$
 *
 * Copyright 1988 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <mit-copyright.h>.
 */

#ifndef	lint
static char rcsid_destest_c[] =
    "$Id$";
#endif

#include "mit-copyright.h"
#include "des.h"
#include <stdio.h>

char clear[] = "eight bytes";
char cipher[8];
char key[8];
des_key_schedule schedule;

int main()
{
    int i;
    des_string_to_key("good morning!", key);
    i = des_key_sched(key, schedule);
    if (i) {
	printf("bad schedule (%d)\n", i);
	exit(1);
    }
    for (i = 1; i <= 10000; i++)
	des_ecb_encrypt(clear, cipher, schedule, i&1);
    return 0;
}
