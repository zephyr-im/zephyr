#ifndef var_MODULE
#define var_MODULE

#include "new_string.h"

/*
 *    void var_clear_all_variables()
 *        Requires: This routine must be called before any other
 *                  var module routine is called.
 *        Modifies: All description language variables
 *        Effects: Sets all description langauge variables to "".
 */

extern void var_clear_all_variables();

/*
 *    string var_get_variable(string name)
 *        Requires: var_clear_all_variables has been called
 *        Effects: Returns the value of the description langauge variable
 *                 named name.  The returned string is read-only and is
 *                 guarenteed to last only until the next var module
 *                 call.  DO NOT FREE THIS STRING.
 */

extern string var_get_variable();

/*
 *    void var_set_variable(string name, value)
 *        Requires: var_clear_all_variables has been called
 *        Modifies: The value of description langauge variable
 *                  named name.
 *        Effects: Sets the description langauge variable named name
 *                 to have the value value.
 */

extern void var_set_variable();

/*
 *    void var_set_variable_to_number(string name; int number)
 *        Requires: var_clear_all_variables has been called
 *        Modifies: The value of description langauge variable
 *                  named name.
 *        Effects: Sets the description langauge variable named name
 *                 to have as its value number's ascii representation.
 */

extern void var_set_variable_to_number();

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

extern void var_set_variable_then_free_value();

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

extern void var_set_number_variables_to_fields();

#endif
