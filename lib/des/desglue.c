/*
 *	$Source$
 *	$Author$
 *	$Header$
 *
 *	Copyright (C) 1988 by the Massachusetts Institute of Technology
 *
 * For copying and distribution information, please see the file
 * <mit-copyright.h>.
 *
 * Backwards compatibility module.
 */

#ifndef lint
static char *rcsid_desglue_c = "$Header$";
#endif /* lint */

#include "des.h"

void
string_to_key(str, key)
    char *str;
    register des_cblock key;
{
    des_string_to_key(str, key);
}


int
read_pw_string(s, max, prompt, verify)
    char *s;
    int max;
    char *prompt;
    int verify;
{
    return des_read_pw_string (s, max, prompt, verify);
}

int
random_key(key)
    des_cblock key;
{
    return des_random_key(key);
}

int
pcbc_encrypt(in, out, length, key, iv, encrypt)
    des_cblock in, out;
    register long length;
    des_key_schedule key;
    des_cblock iv;
    int encrypt;
{
    return des_pcbc_encrypt (in, out, length, key, iv, encrypt);
}

int
key_sched(k, s)
    unsigned char *k;
    des_key_schedule s;
{	
    return des_key_sched (k, s);
}

int
cbc_encrypt(in, out, length, key, iv, encrypt)
    des_cblock in, out;
    register long length;
    des_key_schedule key;
    des_cblock iv;
    int encrypt;
{
    return des_cbc_encrypt (in, out, length, key, iv, encrypt);
}

int
cbc_cksum(in, out, length, key, iv)
    des_cblock in;		/* >= length bytes of inputtext */
    des_cblock out;		/* >= length bytes of outputtext */
    register long length;	/* in bytes */
    des_key_schedule key;		/* precomputed key schedule */
    des_cblock iv;		/* 8 bytes of ivec */
{
    return des_cbc_cksum(in, out, length, key, iv);
}

void
C_Block_print(x)
    des_cblock x;
{	
    des_cblock_print (x);
}

unsigned long
quad_cksum(in,out,length,out_count,c_seed)
    des_cblock c_seed;		/* secret seed, 8 bytes */
    unsigned char *in;		/* input block */
    u_int32 *out;		/* optional longer output */
    int out_count;		/* number of iterations */
    long length;		/* original length in bytes */
{
    return des_quad_cksum(in,out,length,out_count,c_seed);
}

