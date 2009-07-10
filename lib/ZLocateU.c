/* This file is part of the Project Athena Zephyr Notification System.
 * It contains source for the ZLocateUser function.
 *
 *	Created by:	Robert French
 *
 *	$Id$
 *
 *	Copyright (c) 1987,1988 by the Massachusetts Institute of Technology.
 *	For copying and distribution information, see the file
 *	"mit-copyright.h". 
 */

#ifndef lint
static char rcsid_ZLocateUser_c[] = "$Id$";
#endif

#include <internal.h>

Code_t ZLocateUser(user, nlocs)
    char *user;
    int *nlocs;
{
   return(ZNewLocateUser(user,nlocs,ZAUTH));
}
