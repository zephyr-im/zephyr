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
static char rcsid_new_string_c[] = "$Id$";
#endif

/*
 * string - a module providing operations on C strings.  (i.e., char *'s)
 *
 * Overview:
 *
 *        A string is a standard C string.  I.e., a char pointer to a
 *    null-terminated sequence of characters.  0 is NOT considered a valid
 *    string!  Various operations are available.  See the string_spec file
 *    for details.
 *
 *    Note: This module assumes that malloc NEVER returns 0 for reasonable
 *          requests.  It is the users responsibility to either ensure that
 *          this happens or supply a version of malloc with error
 *          handling.
 *
 *    Some strings are mutable.
 */

#ifdef DEBUG
#define  assert(x)          if (!(x)) abort()
#else
#define  assert(x)          
#endif

#include <ctype.h>
#include "new_memory.h"

#include <strings.h>

#define string_Length(s) strlen(s)
typedef char *string;

/*
 *    string string_CreateFromData(char *data, int length):
 *        Requires: data[0], data[1], ..., data[length-1] != 0
 *        Effects: Takes the first length characters at data and
 *                 creates a string containing them.  The returned string
 *                 is on the heap & must be freed eventually.
 *                 I.e., if passed "foobar" and 3, it would return
 *                 string_Copy("foo").
 */

string string__CreateFromData(data, length)
     char *data;
     int length;
{
    string result;

    assert(length>=0);

    result = (string)malloc(length+1);
    assert(result);

    bcopy(data, result, length);
    result[length] = 0;

    return(result);
}

/*
 *    string string_Copy(string s):
 *        Effects: Returns a copy of s on the heap.  The copy must be
 *                 freed eventually.
 */

string string__Copy(s)
     string s;
{
    int length;
    string result;

    assert(s);

    length = string_Length(s)+1;
    result = (string)malloc(length);
    assert(result);

    bcopy(s, result, length);
    return(result);
}

/*
 *    string string_Concat(string a, b):
 *        Effects: Returns a string equal to a concatenated to b.
 *                 The returned string is on the heap and must be
 *                 freed eventually.  I.e., given "abc" and "def",
 *                 returns string_Copy("abcdef").
 */

string string__Concat(a, b)
     string a, b;
{
    string result;
    int a_length, b_size, result_size;

    a_length = string_Length(a);
    b_size = string_Length(b)+1;
    result_size = a_length+b_size;
    result = (string)malloc(result_size);
    assert(result);

    bcopy(a, result, a_length);
    bcopy(b, result+a_length, b_size);

    return(result);
}

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

string string__Concat2(a, b)
     string a, b;
{
    int a_length = string_Length(a);
    int b_size = string_Length(b)+1;

#ifdef DEBUG_MEMORY
    assert(memory__on_heap_p(a));
#endif

    a = (string)realloc(a, a_length+b_size);
    assert(a);
    bcopy(b, a+a_length, b_size);

    return(a);
}

/*
 *    string string_Downcase(string s):
 *        Modifies: s
 *        Effects: Modifies s by changing every uppercase character in s
 *                 to the corresponding lowercase character.  Nothing else
 *                 is changed.  I.e., "FoObAr19." is changed to "foobar19.".
 *                 S is returned as a convenience.
 */

string string_Downcase(s)
     string s;
{
    char *ptr;

    for (ptr=s; *ptr; ptr++) {
	if (isupper(*ptr))
	  *ptr = tolower(*ptr);
    }

    return(s);
}

/*
 *    string string_Upcase(string s):
 *        Modifies: s
 *        Effects: Modifies s by changing every lowercase character in s
 *                 to the corresponding uppercase character.  Nothing else
 *                 is changed.  I.e., "FoObAr19." is changed to "FOOBAR19.".
 *                 S is returned as a convenience.
 */

string string_Upcase(s)
     string s;
{
    char *ptr;

    for (ptr=s; *ptr; ptr++) {
	if (islower(*ptr))
	  *ptr = toupper(*ptr);
    }

    return(s);
}
