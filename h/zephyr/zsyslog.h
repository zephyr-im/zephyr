/* This file is part of the Project Athena Zephyr Notification System.
 * It contains definitions to deal with old 4.2-style syslog functions.
 *
 *	Created by:	John T. Kohl
 *
 *	$Source$
 *	$Author$
 *
 *	Copyright (c) 1987,1988 by the Massachusetts Institute of Technology.
 *	For copying and distribution information, see the file
 *	"mit-copyright.h". 
 */
/* $Header$ */

#include <syslog.h>
#ifndef LOG_AUTH
/* Probably a 4.2-type syslog */
#define	OPENLOG(str, opts, facility)	openlog(str, opts)
#else
/* A decent syslog */
#define OPENLOG(str, opts, facility) openlog(str, opts, facility)
#endif
