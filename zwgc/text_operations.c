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
static char rcsid_text_operations_c[] = "$Header$";
#endif

#include <zephyr/mit-copyright.h>

#include "new_memory.h"
#include "text_operations.h"
#include "char_stack.h"

string lany(text_ptr, str)
     string *text_ptr;
     string str;
{
    string result, whats_left;
    char *p = *text_ptr;

    while (*p && *str) p++, str++;

    result = string_CreateFromData(*text_ptr, p - *text_ptr);
    whats_left = string_Copy(p);
    free(*text_ptr);
    *text_ptr = whats_left;

    return(result);
}

string lbreak(text_ptr, set)
     string *text_ptr;
     character_class *set;
{
    string result, whats_left;
    char *p = *text_ptr;

    while (*p && !(*set)[*p]) p++;

    result = string_CreateFromData(*text_ptr, p - *text_ptr);
    whats_left = string_Copy(p);
    free(*text_ptr);
    *text_ptr = whats_left;

    return(result);
}

string lspan(text_ptr, set)
     string *text_ptr;
     character_class *set;
{
    string result, whats_left;
    char *p = *text_ptr;

    while (*p && (*set)[*p]) p++;

    result = string_CreateFromData(*text_ptr, p - *text_ptr);
    whats_left = string_Copy(p);
    free(*text_ptr);
    *text_ptr = whats_left;

    return(result);
}

string rany(text_ptr, str)
     string *text_ptr;
     string str;
{
    string result, whats_left;
    string text = *text_ptr;
    char *p = text + strlen(text);

    while (text<p && *str) p--, str++;

    result = string_Copy(p);
    whats_left = string_CreateFromData(text, p - text);
    free(text);
    *text_ptr = whats_left;

    return(result);
}

string rbreak(text_ptr, set)
     string *text_ptr;
     character_class *set;
{
    string result, whats_left;
    string text = *text_ptr;
    char *p = text + strlen(text);

    while (text<p && !(*set)[p[-1]]) p--;

    result = string_Copy(p);
    whats_left = string_CreateFromData(text, p - text);
    free(text);
    *text_ptr = whats_left;

    return(result);
}

string rspan(text_ptr, set)
     string *text_ptr;
     character_class *set;
{
    string result, whats_left;
    string text = *text_ptr;
    char *p = text + strlen(text);

    while (text<p && (*set)[p[-1]]) p--;

    result = string_Copy(p);
    whats_left = string_CreateFromData(text, p - text);
    free(text);
    *text_ptr = whats_left;

    return(result);
}
