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

#include <mit-copyright.h>
#include <stdio.h>
#include <des.h>

char clear[] = "eight bytes";
char cipher[8];
char key[8];
Key_schedule schedule;

main()
{
    int i;
    string_to_key("good morning!", key);
    i = key_sched(key, schedule);
    if (i) {
	printf("bad schedule (%d)\n", i);
	exit(1);
    }
    for (i = 1; i <= 10000; i++)
	des_ecb_encrypt(clear, cipher, schedule, i&1);
    return 0;
}
