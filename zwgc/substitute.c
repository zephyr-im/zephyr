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
static char rcsid_substitute_c[] = "$Id$";
#endif

#include <zephyr/mit-copyright.h>

#include "new_memory.h"
#include "lexer.h"
#include "substitute.h"

/*
 *  Internal Routine:
 *
 *    string eat_dollar_sign_stuff(string (*lookup)(string); string *text_ptr)
 *        Modifies: *text_ptr
 *        Effects: This routine deals with handling the stuff after a '$'
 *                 for substitute.  If *text_ptr starts with a valid
 *                 variable reference (minus the leading '$'), we look up
 *                 the variable using lookup and return its value.
 *                 *text_ptr is also advanced past the variable reference.
 *                 If a '$' starts *text_ptr, *text_ptr is advanced past it &
 *                 "$" returned.  (This handles "$$" -> "$")  Otherwise,
 *                 "$" is returned and *text_ptr is not advanced.
 *                 The returned string must not be freed.
 */

static string eat_dollar_sign_stuff(lookup, text_ptr)
     string (*lookup)();
     string *text_ptr;                 /* Input/Output parameter */
{
    char c;
    char closing_brace = 0;
    char *p = *text_ptr;
    char *variable_name_start;
    int variable_name_length;

    /*
     * Handle "$$" -> "$" translation:
     */
    c = *p;
    if (c=='$') {
	*text_ptr = p+1;
	return("$");
    }

    /*
     * If opening brace present (i.e., '(' or '{'), skip it and save away
     * what closing brace we must see at the end of the variable reference:
     */
    if (c=='{') {
	closing_brace = '}';
	c = *++p;
    } else if (c=='(') {
	closing_brace = ')';
	c = *++p;
    }

    /*
     * Eat {identifier_char}* keeping track of what we ate:
     */
    variable_name_start = p;
    variable_name_length = 0;
    while (c = *p, is_identifier_char(c)) {
	p++;
	variable_name_length++;
    }

    /*
     * If there was an opening brace, there had better be a comparable
     * closing brace.  If so, skip it.  If not, we have an invalid variable
     * reference so return '$' without advancing *text_ptr.
     */
    if (closing_brace) {
	if (c==closing_brace)
	  c = *++p;
	else
	  return("$");
    }

    /*
     * Zero length variable names are not valid:
     */
    if (!variable_name_length)
      return("$");

    /*
     * We have a valid variable reference.  Advance past it then lookup
     * its value and return it:
     */
    *text_ptr = p;
    if (variable_name_length > MAX_IDENTIFIER_LENGTH)
      variable_name_length = MAX_IDENTIFIER_LENGTH;
    variable_name_start = string_CreateFromData(variable_name_start,
						variable_name_length);
    p = lookup(variable_name_start);
    free(variable_name_start);
    return(p);
}

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

string substitute(lookup, text)
     string (*lookup)();
     string text;
{
    string result_so_far = string_Copy("");
    char *p, *temp;

    for (;;) {
	/*
	 * Move [^$]* from start of text to end of result_so_far:
	 */
	for (p=text; *p && (*p)!='$'; p++) ;
	if (text != p) {
	    temp = string_CreateFromData(text, p-text);
	    text = p;
	    result_so_far = string_Concat2(result_so_far, temp);
	    free(temp);
	}

	/*
	 * If text now empty, exit -- the result is in result_so_far:
	 */
	if (!*text)
	  return(result_so_far);

	/*
	 * Otherwise, text begins with a '$'.  Eat it then call
	 * eat_dollar_sign_stuff to process stuff after it.
	 * Append result to result_so_far, update text, & continue.
	 */
	text++;
	p = eat_dollar_sign_stuff(lookup, &text);
	result_so_far = string_Concat2(result_so_far, p);
    }
}
