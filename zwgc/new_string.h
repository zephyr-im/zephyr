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

#ifndef string_TYPE
#define string_TYPE

#include <string.h>
#include "new_memory.h"

typedef char *string;

/*
 *    int string_Length(string s):
 *        Effects: Returns the number of non-null characters in s.
 */

#define string_Length(s) strlen(s)

/*
 *    int string_Eq(string a, b):
 *        Effects: Returns true iff strings a & b are equal.  I.e., have the
 *                 same character contents.
 */

#define string_Eq(a,b) (!strcmp(a,b))

/*
 *    int string_Neq(string a, b):
 *        Effects: Returns true iff strings a & b are not equal.
 */

#define string_Neq(a,b) (strcmp(a,b))

/*
 *    string string_CreateFromData(char *data, int length):
 *        Requires: data[0], data[1], ..., data[length-1] != 0
 *        Effects: Takes the first length characters at data and
 *                 creates a string containing them.  The returned string
 *                 is on the heap & must be freed eventually.
 *                 I.e., if passed "foobar" and 3, it would return
 *                 string_Copy("foo").
 */

extern string string__CreateFromData();
#ifdef DEBUG_MEMORY
#define string_CreateFromData(data,length) (set_module(__FILE__,__LINE__),\
				    string__CreateFromData(data,length))
#else
#define string_CreateFromData(data,length)  string__CreateFromData(data,length)
#endif

/*
 *    string string_Copy(string s):
 *        Effects: Returns a copy of s on the heap.  The copy must be
 *                 freed eventually.
 */

extern string string__Copy(/* string s */);
#ifdef DEBUG_MEMORY
#define string_Copy(data)  (set_module(__FILE__,__LINE__),\
			    string__Copy(data))
#else
#define string_Copy(data)  string__Copy(data)
#endif

/*
 *    string string_Concat(string a, b):
 *        Effects: Returns a string equal to a concatenated to b.
 *                 The returned string is on the heap and must be
 *                 freed eventually.  I.e., given "abc" and "def",
 *                 returns string_Copy("abcdef").
 */

extern string string__Concat(/* string a, b */);
#ifdef DEBUG_MEMORY
#define string_Concat(a,b)  (set_module(__FILE__,__LINE__),\
			     string__Concat(a,b))
#else
#define string_Concat(a,b)  string__Concat(a,b)
#endif
    
/*
 *    string string_Concat2(string a, b):
 *        Modifies: a
 *        Requires: a is on the heap, b does not point into a.
 *        Effects: Equivalent to:
 *                     string temp;
 *                     temp = string_Concat(a,b);
 *                     free(a);
 *                     return(temp);
 *                 only faster.  I.e., uses realloc instead of malloc+bcopy.
 */

extern string string__Concat2(/* string a, b */);
#ifdef DEBUG_MEMORY
#define string_Concat2(a,b)  (set_module(__FILE__,__LINE__),\
			      string__Concat2(a,b))
#else
#define string_Concat2(a,b)  string__Concat2(a,b)
#endif

/*
 *    string string_Downcase(string s):
 *        Modifies: s
 *        Effects: Modifies s by changing every uppercase character in s
 *                 to the corresponding lowercase character.  Nothing else
 *                 is changed.  I.e., "FoObAr19." is changed to "foobar19.".
 *                 S is returned as a convenience.
 */

extern string string_Downcase();

/*
 *    string string_Upcase(string s):
 *        Modifies: s
 *        Effects: Modifies s by changing every lowercase character in s
 *                 to the corresponding uppercase character.  Nothing else
 *                 is changed.  I.e., "FoObAr19." is changed to "FOOBAR19.".
 *                 S is returned as a convenience.
 */

extern string string_Upcase();

#endif
