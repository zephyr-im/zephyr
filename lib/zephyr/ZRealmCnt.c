/* This file is part of the Project Athena Zephyr Notification System.
 * It contains source for the ZGetRealmCount and ZGetRealmName functions.
 *
 *	Created by:	Marc Horowitz
 *
 *	$Source$
 *	$Author$
 *
 *	Copyright (c) 1987, 1991 by the Massachusetts Institute of Technology.
 *	For copying and distribution information, see the file
 *	"mit-copyright.h". 
 */
/* $Header$ */

#include <internal.h>

#ifndef lint
static const char rcsid_ZRealmCnt_c[] =
    "$Id$";
#endif

Code_t ZGetRealmCount(pcnt)
     int *pcnt;
{
   *pcnt = __nrealms;

   return(ZERR_NONE);
}

Code_t ZGetRealmName(idx, name)
     int idx;
     char **name;
{
   if ((idx < 0) || (idx >= __nrealms))
      return(EINVAL);

   /* return the default realm first.  when the default realm would have
      been return in the order, return the first realm. */

   if (idx == 0)
      *name = __realm_list[__default_realm].realm_config.realm;
   else if (idx == __default_realm)
      *name = __realm_list[0].realm_config.realm;
   else
      *name = __realm_list[idx].realm_config.realm;


   return(ZERR_NONE);
}
