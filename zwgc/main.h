/* This file is part of the Project Athena Zephyr Notification System.
 * It is one of the source files comprising zwgc, the Zephyr WindowGram
 * client.
 *
 *      Created by:     Marc Horowitz <marc@athena.mit.edu>
 *
 *      $Id$
 *
 *      Copyright (c) 1989 by the Massachusetts Institute of Technology.
 *      For copying and distribution information, see the file
 *      "mit-copyright.h".
 */


#include <zephyr/mit-copyright.h>

#ifndef main_MODULE
#define main_MODULE

#ifdef HAVE_ARES
#include <ares.h>

extern ares_channel achannel;
#endif

extern char *progname;
extern char *subscriptions_filename_override;
extern char *location_override;

/*
 *    void usage()
 *        Effects: Prints out a usage message on stderr then exits the
 *                 program with error code 1.
 */

extern void usage();

/* USRDESC points to a file (relative to user's homedir) which has a user's
   description file */

#define USRDESC ".zwgc.desc"

/* DEFDESC points to a file (relative to the data directory) which has the
 * system default description file */

#ifndef DEFDESC
#define DEFDESC "zwgc.desc"
#endif

#endif
