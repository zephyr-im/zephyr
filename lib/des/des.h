/*
 * $Source$
 * $Author$
 * $Header$ 
 *
 * Copyright 1987, 1988 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <mit-copyright.h>.
 *
 * Include file for the Data Encryption Standard library.
 */

/* only do the whole thing once	 */
#ifndef DES_DEFS
#define DES_DEFS

/* This header file has been modified for the Zephyr source tree, and is not
 * suitable for use outside the Zephyr source tree because it relies on
 * <sysdep.h> to determine what a 32-bit type is. */

#include "mit-copyright.h"
#include <sysdep.h>

#define KRB_INT32 ZEPHYR_INT32
#define KRB_UINT32 unsigned ZEPHYR_INT32
#define int32 ZEPHYR_INT32
#define u_int32 unsigned ZEPHYR_INT32

typedef unsigned char des_cblock[8];	/* crypto-block size */
/* Key schedule */
typedef struct des_ks_struct { union { long pad; des_cblock _;} __; } des_key_schedule[16];

#define DES_KEY_SZ 	(sizeof(des_cblock))
#define DES_ENCRYPT	1
#define DES_DECRYPT	0

#define C_Block des_cblock

int des_cbc_encrypt __P((des_cblock, des_cblock, long, des_key_schedule,
			 des_cblock, int));
int des_ecb_encrypt __P((des_cblock, des_cblock, des_key_schedule, int));
int des_pcbc_encrypt __P((des_cblock, des_cblock, long, des_key_schedule,
			  des_cblock, int));
unsigned long des_cbc_cksum __P((des_cblock, des_cblock, long,
				 des_key_schedule, des_cblock));
unsigned long des_quad_cksum __P((unsigned char *, u_int32 *, long, int,
				  des_cblock));
int make_key_sched __P((des_cblock, des_key_schedule));
int des_read_password __P((des_cblock, char *, int));
int des_read_pw_string __P((char *, int, char *, int));
void des_string_to_key __P((char *, register des_cblock));
int des_is_weak_key __P((des_cblock));
void des_set_random_generator_seed __P((des_cblock));
void des_set_sequence_number __P((des_cblock));
void des_generate_random_block __P((des_cblock));
int des_random_key __P((des_cblock));
void des_cblock_print_file __P((des_cblock, FILE *));
void des_fixup_key_parity __P((des_cblock));
int des_check_key_parity __P((des_cblock));
int des_key_sched __P((register des_cblock, des_key_schedule));

#define des_cblock_print(x) des_cblock_print_file(x, stdout)

#endif	/* DES_DEFS */
