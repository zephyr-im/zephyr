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
   just the zephyr realm), given the zephyr destination realm */

char *ZGetRhs(zrealm)
     char *zrealm;
{
   Z_RealmList *rl;
   int i;

   /* this should only happen on a server */
   if (__nrealms == 0)
      return("local-realm");

   if (zrealm && zrealm[0]) {
      rl = NULL;

      for (i=0; i<__nrealms; i++)
	 if (strcasecmp(__realm_list[i].realm_config.realm, zrealm) == 0) {
	    rl = &__realm_list[i];
	    break;
	 }

      if (rl == NULL)
	 return(NULL);
   } else {
      rl = &__realm_list[__default_realm];
   }

   return(
#ifdef ZEPHYR_USES_KERBEROS		   
	  rl->krealm
#else
	  rl->realm_config.realm
#endif
	  );
}
