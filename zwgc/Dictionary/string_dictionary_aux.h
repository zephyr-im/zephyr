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

#ifndef string_dictionary_aux_MODULE
#define string_dictionary_aux_MODULE

#include "new_memory.h"
#include "string_dictionary.h"

/*
 *    void string_dictionary_Set(string_dictionary d, string key,string value):
 *        Modifies: d
 *        Effects: Binds key to value in d.  Automatically free's the
 *                 previous value of key, if any.  Value is copied on the
 *                 heap.
 */

extern void string__dictionary_Set();
#ifdef DEBUG_MEMORY
#define string_dictionary_Set(a,b,c)         (set_module(__FILE__,__LINE__),\
					      string__dictionary_Set(a,b,c))
#else
#define string_dictionary_Set(a,b,c)         string__dictionary_Set(a,b,c)
#endif

/*
 *    char *string_dictionary_Fetch(string_dictionary d, string key)
 *        Effects: If key is not bound in d, returns 0.  Otherwise,
 *                 returns the value that key is bound to.  
 *                 Note that the returned string if any should not be
 *                 freed or modified in any way.  Note also that it may
 *                 disappear later if key is rebound.
 */

extern char *string_dictionary_Fetch();

/*
 *    void string_dictionary_SafeDestroy(string_dictionary d)
 *        Modifies: d
 *        Effects: Like string_dictionary_Destroy except first frees
 *                 all value's in the dictionary.
 */

extern void string_dictionary_SafeDestroy();

#endif
