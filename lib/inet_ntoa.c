/* This file is part of the Project Athena Zephyr Notification System.
 * It contains a version of the standard inet_ntoa function, for use
 * on a Sun 4 with gcc version 1.
 *
 *	Created by:	Ken Raeburn
 *
 *	$Source$
 *	$Author$
 *
 *	Copyright (c) 1991 by the Massachusetts Institute of Technology.
 *	For copying and distribution information, see the file
 *	"mit-copyright.h". 
 */

#include <zephyr/mit-copyright.h>

#ifndef lint
static char rcsid_inet_ntoa_c[] = "$Zephyr$";
#endif

#if defined (sparc) && __GNUC__ == 1
/* GCC version 1 passes structures incorrectly on the Sparc.
   This addition will cause things to work correctly if everything
   using inet_ntoa is compiled with gcc.  If not, you lose anyways.  */
char *inet_ntoa (addr)
     struct in_addr addr;
{
  static char buf[16];
  sprintf (buf, "%d.%d.%d.%d",
	   addr.S_un.S_un_b.s_b1,
	   addr.S_un.S_un_b.s_b2,
	   addr.S_un.S_un_b.s_b3,
	   addr.S_un.S_un_b.s_b4);
  return buf;
}
#endif
