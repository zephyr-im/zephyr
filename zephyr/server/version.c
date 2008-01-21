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
#include "version.h"

const char zephyr_version[] = "Zephyr system version 2.0";

#ifdef DEBUG
const char version[] = "Zephyr server (DEBUG) $Revision$";
#else
const char version[] = "Zephyr server $Revision$";
#endif

#if !defined (lint) && !defined (SABER)
static const char rcsid_version_c[] =
    "$Id$";
static const char copyright[] =
    "Copyright (c) 1987,1988,1989,1990 Massachusetts Institute of Technology.\n";
#endif

char *
get_version(void)
{
  static char vers_buf[256];
  struct utsname un;

  if (vers_buf[0] == '\0') {
#ifdef DEBUG
    sprintf(vers_buf,"Zephyr Server (DEBUG) $Revision$: %s",
	    ZSERVER_VERSION_STRING);
#else
    sprintf(vers_buf,"Zephyr Server $Revision$: %s",
	    ZSERVER_VERSION_STRING);
#endif /* DEBUG */

    (void) strcat(vers_buf, "/");
#ifdef vax
    (void) strcat(vers_buf, "VAX");
#endif /* vax */
#ifdef ibm032
    (void) strcat(vers_buf, "IBM RT");
#endif /* ibm032 */
#ifdef _IBMR2
    (void) strcat(vers_buf, "IBM RS/6000");
#endif /* _IBMR2 */
#ifdef sun
    (void) strcat(vers_buf, "SUN");
#ifdef sparc
    (void) strcat (vers_buf, "-4");
#endif /* sparc */
#ifdef sun386
    (void) strcat (vers_buf, "-386I");
#endif /* sun386 */
#endif /* sun */

#ifdef mips
#ifdef ultrix			/* DECstation */
    (void) strcat (vers_buf, "DEC-");
#endif /* ultrix */
    (void) strcat(vers_buf, "MIPS");
#endif /* mips */
#ifdef NeXT
    (void) strcat(vers_buf, "NeXT");
#endif /* NeXT */

    if (vers_buf[strlen(vers_buf) - 1] == '/') {
	uname(&un);
	(void) strcat(vers_buf, un.machine);
	(void) strcat(vers_buf, "-");
	(void) strcat(vers_buf, un.sysname);
    }
  }
  return(vers_buf);
}
