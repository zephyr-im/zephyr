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

#ifndef text_operations_MODULE
#define text_operations_MODULE

#include "character_class.h"

extern string lany(string *, string);
extern string lbreak(string *, const character_class);
extern string lspan(string *, character_class);
extern string rany(string *, string);
extern string rbreak(string *, character_class);
extern string rspan(string *, character_class);

#endif
