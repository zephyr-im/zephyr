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
static char rcsid_buffer_h[] = "$Header$";
#endif

#include <zephyr/mit-copyright.h>

#ifndef buffer_MODULE
#define buffer_MODULE

#include "new_string.h"

extern string buffer_to_string();
extern void clear_buffer();
extern void append_buffer();

#endif
