/* This file is part of the Project Athena Zephyr Notification System.
 * It is one of the source files comprising zwgc, the Zephyr WindowGram
 * client.
 *
 *      Created by:     Marc Horowitz <marc@athena.mit.edu>
 *
 *      $Source$
 *      $Author$
 *
 *      Copyright (c) 1989 by the Massachusetts Institute of Technology.
 *      For copying and distribution information, see the file
 *      "mit-copyright.h".
 */

#if (!defined(lint) && !defined(SABER))
static char rcsid_zephyr_h[] = "$Header$";
#endif

#include <zephyr/mit-copyright.h>

#ifndef zephyr_MODULE
#define zephyr_MODULE

extern void zephyr_init();
extern void finalize_zephyr();

#endif
