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

#include <sysdep.h>

#if (!defined(lint) && !defined(SABER))
static const char rcsid_buffer_c[] = "$Id$";
#endif

#include <zephyr/mit-copyright.h>

#include "new_memory.h"
#include "buffer.h"

static char *buffer = 0;

string
buffer_to_string(void)
{
    return(buffer);
}

void
clear_buffer(void)
{
    if (buffer)
      free(buffer);

    buffer = string_Copy("");
}

void
append_buffer(char *str)
{
    buffer = string_Concat2(buffer, str);
}
