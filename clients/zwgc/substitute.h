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
static char rcsid_substitute_h[] = "$Header$";
#endif

#include <zephyr/mit-copyright.h>

#ifndef substitute_MODULE
#define substitute_MODULE

#include "new_string.h"

/*
 *    string substitute(string (*lookup)(string); string text)
 *        Effects: returns the result of expanding all variable
 *                 references in text using lookup.  Example:
 *                 "test $foo.$bar baz" would be translated to
 *                 "text <foo>.<bar> baz" where "<foo>" is the value of
 *                 lookup("foo") and "<bar>" is the value of lookup("bar").
 *                 Variables are case sensitive and have the form
 *                 {identifier_char}+ where identifier_char is defined
 *                 in lexer.h by is_identifier_char.  $(foo) and
 *                 ${foo} are alternate forms for $foo.  In particular,
 *                 ${foo}bar is a reference to foo followed by "bar" while
 *                 $foobar is a reference to foobar.  Incomplete variable
 *                 references like $(foo bar are displayed as if they
 *                 were not variable references.  To allow quoting, "$$"
 *                 is translated to "$".  Only the first
 *                 MAX_IDENTIFIER_LENGTH characters of an identifier are
 *                 significant.  The strings returned by lookup are not
 *                 modified in any way or freed.
 */

extern string substitute();

#endif
