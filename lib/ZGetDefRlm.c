/* This file is part of the Project Athena Zephyr Notification System.
 * It contains source for the ZGetDefRlm function.
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
static const char rcsid_ZGetDefGxy_c[] =
    "$Id$";
#endif

char *ZGetDefaultGalaxy()
{
   return(__galaxy_list[__default_galaxy].galaxy_config.galaxy);
}
