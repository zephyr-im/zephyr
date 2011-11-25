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

#include <sys/utsname.h>

#include "zserver.h"
#include <zephyr_version.h>

const char zephyr_version[] = "Zephyr system version" ZEPHYR_VERSION_STRING;

#ifdef DEBUG
const char version[] = "Zephyr Server (DEBUG) " ZEPHYR_VERSION_STRING;
#else
const char version[] = "Zephyr Server " ZEPHYR_VERSION_STRING;
#endif

#if !defined (lint) && !defined (SABER)
static const char copyright[] =
    "Copyright (c) 1987,1988,1989,1990 Massachusetts Institute of Technology.\n";
#endif

char *
get_version(void)
{
  static char vers_buf[256];
  struct utsname un;

  if (vers_buf[0] == '\0') {
      strcpy(vers_buf, version);

      (void) strcat(vers_buf, "/");

      uname(&un);
      (void) strcat(vers_buf, un.machine);
      (void) strcat(vers_buf, "-");
      (void) strcat(vers_buf, un.sysname);
  }

  return(vers_buf);
}
