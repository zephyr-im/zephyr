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
static char rcsid_character_class_h[] = "$Header$";
#endif

#include <zephyr/mit-copyright.h>

#ifndef character_class_TYPE
#define character_class_TYPE

#include "new_string.h"

#define  NUMBER_OF_CHARACTERS   256

typedef char character_class[NUMBER_OF_CHARACTERS];

extern character_class *string_to_character_class();

#endif
