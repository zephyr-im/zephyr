/* This file is part of the Project Athena Zephyr Notification System.
 * It is one of the source files comprising zwgc, the Zephyr WindowGram
 * client.
 *
 *      Created by:     Marc Horowitz <marc@athena.mit.edu>
 *
 *      $Source$
 *      $Author$
 *	$Id$
 *
 *      Copyright (c) 1989 by the Massachusetts Institute of Technology.
 *      For copying and distribution information, see the file
 *      "mit-copyright.h".
 */


#include <zephyr/mit-copyright.h>

#ifndef main_MODULE
#define main_MODULE

extern char *subscriptions_filename_override;

/*
 *    void usage()
 *        Effects: Prints out a usage message on stderr then exits the
 *                 program with error code 1.
 */

extern void usage();

/* USRDESC points to a file (relative to user's homedir) which has a user's
   description file */

#define USRDESC ".zwgc.desc"

/* DEFDESC points to where the system default description is stored */

#ifndef DEFDESC
#define DEFDESC "/etc/athena/zwgc.desc"
#endif

#endif
