/* This file is part of the Project Athena Zephyr Notification System.
 * It contains the version identification of the Zephyr server
 *
 *	Created by:	John T. Kohl
 *
 *	$Id$
 *
 *	Copyright (c) 1989 by the Massachusetts Institute of Technology.
 *	For copying and distribution information, see the file
 *	"mit-copyright.h". 
 */

#include <zephyr/mit-copyright.h>

#include "zserver.h"
#include "version.h"

const char zephyr_version[] = "Zephyr system version 2.0";

static char version[] = {
    "Zephyr Server "
#ifdef DEBUG
    "(DEBUG) "
#endif
    "$Revision$"
    ": " ZSERVER_VERSION_STRING "/" MACHINE_TYPE
};

#if !defined (lint) && !defined (SABER)
static const char rcsid_version_c[] =
    "$Id$";
static const char copyright[] =
    "Copyright (c) 1987,1988,1989,1990 Massachusetts Institute of Technology.\n";
#endif

char *
get_version()
{
    return version;
}
