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
static char rcsid_string_dictionary_aux_c[] = "$Id$";
#endif

/*
 * string_dictionary_aux - a module implementing convenience routines for use
 *                         with string_dictionarys
 *
 * Overview:
 *
 *       This module implements Fetch and Set operations on
 *    string_dictionaries which take the place of Define and Lookup for
 *    most uses.  The importance difference between them and Define and
 *    Lookup is that they maintain the invariant that all the value strings
 *    in a string_dictionary are on the heap.  In particular, they do
 *    free's and string_Copy's whenever needed.  Also implemented is
 *    SafeDestroy which does a Destroy after freeing all the value strings
 *    in a string_dictionary.
 */

#include "new_memory.h"
#include "string_dictionary.h"

/*
 *    void string_dictionary_Set(string_dictionary d, string key,string value):
 *        Modifies: d
 *        Effects: Binds key to value in d.  Automatically free's the
 *                 previous value of key, if any.  Value is copied on the
 *                 heap.
 */

void string__dictionary_Set(d, key, value)
     string_dictionary d;
     string key;
     string value;
{
    string_dictionary_binding *binding;
    int already_exists;

    binding = string_dictionary_Define(d, key, &already_exists);
    if (already_exists)
      free(binding->value);

    binding->value = string_Copy(value);
}

/*
 *    char *string_dictionary_Fetch(string_dictionary d, string key)
 *        Effects: If key is not bound in d, returns 0.  Otherwise,
 *                 returns the value that key is bound to.  
 *                 Note that the returned string if any should not be
 *                 freed or modified in any way.  Note also that it may
 *                 disappear later if key is rebound.
 */

char *string_dictionary_Fetch(d, key)
     string_dictionary d;
     string key;
{
    string_dictionary_binding *binding;

    binding = string_dictionary_Lookup(d, key);
    if (!binding)
      return(0);

    return(binding->value);
}

/*
 *    void string_dictionary_SafeDestroy(string_dictionary d)
 *        Modifies: d
 *        Effects: Like string_dictionary_Destroy except first frees
 *                 all value's in the dictionary.
 */

static void free_value_of_binding(b)
     string_dictionary_binding *b;
{
    free(b->value);
}

void string_dictionary_SafeDestroy(d)
     string_dictionary d;
{
    string_dictionary_Enumerate(d, free_value_of_binding);
    string_dictionary_Destroy(d);
}
