/* This file is part of the Project Athena Zephyr Notification System.
 * It contains source for the ZGetRhs function.
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
static const char rcsid_ZGetRhs_c[] =
    "$Id$";
#endif

/* Get the thing after the @ (kerberos realm if kerberos, otherwise
   just the zephyr galaxy), given the zephyr destination realm */

char *ZGetRhs(zgalaxy)
     char *zgalaxy;
{
   Z_GalaxyList *rl;
   int i;

   /* this should only happen on a server */
   if (__ngalaxies == 0)
      return("local-galaxy");

   if (zgalaxy && zgalaxy[0]) {
      rl = NULL;

      for (i=0; i<__ngalaxies; i++)
	 if (strcasecmp(__galaxy_list[i].galaxy_config.galaxy, zgalaxy) == 0) {
	    rl = &__galaxy_list[i];
	    break;
	 }

      if (rl == NULL)
	 return(NULL);
   } else {
      rl = &__galaxy_list[__default_galaxy];
   }

   return(
#ifdef HAVE_KRB4
	  rl->krealm
#else
	  rl->galaxy_config.galaxy
#endif
	  );
}
