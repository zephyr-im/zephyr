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
static char rcsid_variables_c[] = "$Id$";
#endif

#include <zephyr/mit-copyright.h>

/****************************************************************************/
/*                                                                          */
/*   Module containing code to deal with description langauge variables:    */
/*                                                                          */
/****************************************************************************/

#include <stdio.h>
#include <ctype.h>
#include "new_memory.h"
#include "notice.h"
#include "string_dictionary_aux.h"
#include "variables.h"

/*
 * fields_data[_length] - these point to the field data that the number
 *                        variables were last set to using 
 *                        var_set_number_variables_to_fields.
 */

static char *fields_data;
static int fields_data_length = 0;

/*
 * [non_]number_variable_dict - contains the values of all the [non-]number
 *                              variables that have been set since the last
 *                              var_clear_all_variables call or (for numbers
 *                              only) var_set_number_variables_to_fields call.
 */

static string_dictionary non_number_variable_dict = NULL;
static string_dictionary number_variable_dict = NULL;

/*
 *  Internal Routine:
 *
 *    int is_digits(string text)
 *        Effects: Returns true iff text matches [0-9]*.  ("" matches...)
 */

static int is_digits(text)
     string text;
{
    for (; *text; text++)
      if (!isdigit(*text))
	return(0);

    return(1);
}

/*
 *  Internal Routine:
 *
 *    int is_number_variable(string text)
 *        Effects: Returns true iff text matches [0-9]+.
 */

#define  is_number_variable(x)      (isdigit(*(x)) && is_digits((x)))

/*
 *    void var_clear_all_variables()
 *        Requires: This routine must be called before any other
 *                  var module routine is called.
 *        Modifies: All description language variables
 *        Effects: Sets all description langauge variables to "".
 */

void var_clear_all_variables()
{
    if (non_number_variable_dict) {
	string_dictionary_SafeDestroy(non_number_variable_dict);
	string_dictionary_SafeDestroy(number_variable_dict);
    }

    non_number_variable_dict = string_dictionary_Create(101);
    number_variable_dict = string_dictionary_Create(11);
    fields_data_length = 0;
}

/*
 *    string var_get_variable(string name)
 *        Requires: var_clear_all_variables has been called
 *        Effects: Returns the value of the description langauge variable
 *                 named name.  The returned string is read-only and is
 *                 guarenteed to last only until the next var module
 *                 call.  DO NOT FREE THIS STRING.
 */

string var_get_variable(name)
     string name;
{
    char *result;
    int field_to_get;
    static string last_get_field_call_result = NULL;

    if (is_number_variable(name)) {
	if (result = string_dictionary_Fetch(number_variable_dict, name))
	  return(result);

	/*
	 * Convert name to an integer avoiding overflow:
	 */
	while (*name=='0')
	  name++;
	if (strlen(name)>12)
	  field_to_get = 0; /* no way we'll have > 1 trillian fields... */
	else
	  field_to_get = atoi(name);

	if (!field_to_get)
	  return("");
	if (last_get_field_call_result)
	  free(last_get_field_call_result);
	last_get_field_call_result = get_field(fields_data,
					       fields_data_length,
					       field_to_get);
	return(last_get_field_call_result);
    }

    if (!(result = string_dictionary_Fetch(non_number_variable_dict, name)))
      result = "";

    return(result);
}

/*
 *    void var_set_variable(string name, value)
 *        Requires: var_clear_all_variables has been called
 *        Modifies: The value of description langauge variable
 *                  named name.
 *        Effects: Sets the description langauge variable named name
 *                 to have the value value.
 */

void var_set_variable(name, value)
     string name;
     string value;
{
    string_dictionary_Set(is_number_variable(name) ? number_variable_dict
			  : non_number_variable_dict, name, value);
}

/*
 *    void var_set_variable_to_number(string name; int number)
 *        Requires: var_clear_all_variables has been called
 *        Modifies: The value of description langauge variable
 *                  named name.
 *        Effects: Sets the description langauge variable named name
 *                 to have as its value number's ascii representation.
 */

void var_set_variable_to_number(name, number)
     string name;
     int number;
{
    char buffer[20];

    sprintf(buffer, "%d", number);
    var_set_variable(name, buffer);
}

/*
 *    void var_set_variable_then_free_value(string name, value)
 *        Requires: var_clear_all_variables has been called, value is
 *                  on the heap.
 *        Modifies: The value of description langauge variable
 *                  named name, value
 *        Effects: Sets the description langauge variable named name
 *                 to have the value value then frees value.  This
 *                 routine is slightly faster than calling var_set_variable
 *                 then freeing value.  It is provided mainly for
 *                 convenience reasons.
 */

void var_set_variable_then_free_value(name, value)
     string name;
     string value;
{
    string_dictionary_binding *binding;
    int exists;

#ifdef DEBUG_MEMORY
    if (!memory__on_heap_p(value))
      abort(); /* <<<>>> */
#endif

    if (is_number_variable(name)) {
	var_set_variable(name, value);
	free(value);
	return;
    }

    binding = string_dictionary_Define(non_number_variable_dict, name,
				       &exists);
    if (exists)
      free(binding->value);
    binding->value = value;
}

/*
 *    void var_set_number_variables_to_fields(char *data, int length)
 *        Requires: var_clear_all_variables has been called
 *        Modifies: All numeric description language variables
 *        Effects: Treats data[0]..data[length-1] as a series of
 *                 null-seperated fields.  Sets $<number> (<number>
 *                 here means [0-9]+ to field # <number> in data.
 *                 Field 0 is defined to be "" as are all field #'s
 *                 greater than the number of fields in data.
 *                 Data[0]..data[length-1] must not be changed (or freed)
 *                 until either this call is made again with different
 *                 data or var_clear_all_variables is called.
 */

void var_set_number_variables_to_fields(data, length)
     char *data;
     int length;
{
    fields_data = data;
    fields_data_length = length;

    string_dictionary_SafeDestroy(number_variable_dict);
    number_variable_dict = string_dictionary_Create(11);
}
