/* This file is part of the Project Athena Zephyr Notification System.
 * It contains source for the ZGetGalaxyCount and ZGetGalaxyName functions.
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
static const char rcsid_ZGxyCnt_c[] =
    "$Id$";
#endif

Code_t ZGetGalaxyCount(pcnt)
     int *pcnt;
{
   *pcnt = __ngalaxies;

   return(ZERR_NONE);
}

Code_t ZGetGalaxyName(idx, name)
     int idx;
     char **name;
{
   if ((idx < 0) || (idx >= __ngalaxies))
      return(EINVAL);

   /* return the default galaxy first.  when the default galaxy would have
      been returned in the order, return the first galaxy. */

   if (idx == 0)
      *name = __galaxy_list[__default_galaxy].galaxy_config.galaxy;
   else if (idx == __default_galaxy)
      *name = __galaxy_list[0].galaxy_config.galaxy;
   else
      *name = __galaxy_list[idx].galaxy_config.galaxy;


   return(ZERR_NONE);
}
