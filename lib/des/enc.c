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
static char rcsid_enc_c[] =
    "$Id$";
#endif

#include <mit-copyright.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/file.h>
#include <fcntl.h>

#include <des.h>

des_key_schedule KEYSCHED;
des_cblock key = {0,1,2,3,4,5,6,7};
des_cblock sum;
char inbuf[512+8];		/* leave room for cksum and len */
char oubuf[512+8];
int ind;
int oud;
long orig_size;

main(argc,argv)
    int argc;
    char *argv[];
{
    register int encrypt;
    register long length;
    register int *p;
    u_int32 ivec[2];
    if (argc != 4) {
	fprintf (stderr, "%s: Usage: %s infile outfile mode.\n",
		 argv[0], argv[0]);
	exit (1);
    }
    if (!strcmp(argv[3], "e"))
	encrypt = 1;
    else if (!strcmp(argv[3], "d"))
	encrypt = 0;
    else {
	fprintf (stderr, "%s: Mode must be e (encrypt) or d (decrypt).\n",
		 argv[0]);
	exit (1);
    }
    if ((ind = open(argv[1], O_RDONLY, 0666)) < 0) {
	fprintf (stderr, "%s: Cannot open %s for input.\n",
		 argv[0], argv[1]);
	exit (1);
    }
    if (!strcmp(argv[2], "-"))
	oud = dup(1);
    else if ((oud = open(argv[2], O_CREAT|O_WRONLY, 0666)) < 0) {
	fprintf (stderr, "%s: Cannot open %s for output.\n",
		 argv[0], argv[2]);
	exit (1);
    }
#ifdef notdef
    (void) freopen ("/dev/tty", "r", stdin);
    (void) freopen ("/dev/tty", "w", stdout);
#endif
    des_read_password (key, "\n\07\07Enter Key> ", 1);
    if (des_key_sched (key, KEYSCHED) < 0) {
	fprintf (stderr, "%s: Key parity error\n", argv[0]);
	exit (1);
    }
    ivec[0] = 0;
    ivec[1] = 0;
    memcpy(sum, key, sizeof(des_cblock));
    for (;;) {
	if ((length = read (ind, inbuf, 512)) < 0) {
	    fprintf (stderr, "%s: Error reading from input.\n",
		     argv[0]);
	    exit (1);
	} else if (length == 0) {
	    fprintf (stderr, "\n");
	    break;
	}
	if (encrypt) {
#ifdef notdef
	    sum = des_quad_cksum(inbuf,NULL,length,1,sum);
#endif
	    des_quad_cksum(inbuf,sum,length,1,sum);
	    orig_size += length;
	    fprintf(stderr,
		    "\nlength = %d tot length = %d quad_sum = %X %X",
		    length, orig_size, *(unsigned long *) sum,
		    *((unsigned long *) sum+1));
	    fflush(stderr);
	}
	des_pcbc_encrypt (inbuf, oubuf, (long) length, KEYSCHED, ivec,
		      encrypt);
	if (!encrypt) {
#ifdef notdef
	    sum = des_quad_cksum(oubuf,NULL,length,1,sum);
#endif
	    des_quad_cksum(oubuf,sum,length,1,sum);
	    orig_size += length;
	    fprintf(stderr,
		    "\nlength = %d tot length = %d quad_sum = %X ",
		    length, orig_size, *(unsigned long *) sum,
		    *((unsigned long *) sum+1));
	}
	length = (length+7)& ~07;
	write (oud, oubuf, length);
	if (!encrypt)
	    p = (int *)&oubuf[length-8];
	else
	    p = (int *)&inbuf[length-8];
	ivec[0] = *p++;
	ivec[1] = *p;
    }

    fprintf(stderr,"\ntot length = %d quad_sum = %X\n",
	    orig_size,sum);
    /* if encrypting, now put the original length and checksum in */
    return 0;
}
