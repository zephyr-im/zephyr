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
static char rcsid_dictionary_c[] = "$Id$";
#endif

/*
 * dictionary - a module implementing a generic dictionary.  That is,
 *              any type can be used for the values that keys are bound to.
 *              Keys are always strings.
 *
 * Overview:
 *
 *        A dictionary is a set of bindings which bind values of some
 *    type (this type is the generic parameter of the dictionary) to
 *    strings.  At most one value can be bound to any one string.
 *    The value that a string is bound to can be changed later.
 *    Bindings can also be deleted later.  It is also possible to
 *    enumerate all of the bindings in a dictionary.  Dictionarys
 *    are heap based and must be created & destroyed accordingly.
 *
 *    Note: This module assumes that malloc NEVER returns 0 for reasonable
 *          requests.  It is the users responsibility to either ensure that
 *          this happens or supply a version of malloc with error
 *          handling.
 *
 *    Dictionarys are mutable.
 *
 * Implementation:
 *
 *        A standard chaining hash table is used to implement dictionarys.
 *    Each dictionary has an associated size (# of slots), allowing
 *    different size dictionaries as needed.
 */

#include "TYPE_T_dictionary.h"
#include "new_string.h"
#include "new_memory.h"

#ifndef NULL
#define NULL 0
#endif

/*
 *    TYPE_T_dictionary TYPE_T_dictionary_Create(int size):
 *        Requires: size > 0
 *        Effects: Returns a new empty dictionary containing no bindings.
 *                 The returned dictionary must be destroyed using
 *                 TYPE_T_dictionary_Destroy.  Size is a time vs space
 *                 parameter.  For this implementation, space used is
 *                 proportional to size and time used is proportional
 *                 to number of bindings divided by size.  It is preferable
 *                 that size is a prime number.
 */

TYPE_T_dictionary TYPE_T_dictionary_Create(size)
     int size;
{
    int i;
    TYPE_T_dictionary result;

    result = (TYPE_T_dictionary)malloc(sizeof(struct _TYPE_T_dictionary));
    result->size = size;
    result->slots = (TYPE_T_dictionary_binding **)malloc(
		     size*sizeof(TYPE_T_dictionary_binding *));

    for (i=0; i<size; i++)
      result->slots[i] = NULL;

    return(result);
}

/*
 *    void TYPE_T_dictionary_Destroy(TYPE_T_dictionary d):
 *        Requires: d is a non-destroyed TYPE_T_dictionary
 *        Modifies: d
 *        Effects: Destroys dictionary d freeing up the space it consumes.
 *                 Dictionary d should never be referenced again.  Note that
 *                 free is NOT called on the values of the bindings.  If
 *                 this is needed, the client must do this first using
 *                 TYPE_T_dictionary_Enumerate.
 */

void TYPE_T_dictionary_Destroy(d)
     TYPE_T_dictionary d;
{
    int i;
    TYPE_T_dictionary_binding *binding_ptr, *new_binding_ptr;

    for (i=0; i<d->size; i++) {
	binding_ptr = d->slots[i];
	while (binding_ptr) {
	    new_binding_ptr = binding_ptr->next;
	    free(binding_ptr->key);
	    free(binding_ptr);
	    binding_ptr = new_binding_ptr;
	}
    }
    free(d->slots);
    free(d);
}

/*
 *    void TYPE_T_dictionary_Enumerate(TYPE_T_dictionary d; void (*proc)()):
 *        Requires: proc is a void procedure taking 1 argument, a
 *                  TYPE_T_dictionary_binding pointer, which does not
 *                  make any calls using dictionary d.
 *        Effects: Calls proc once with each binding in dictionary d.
 *                 Order of bindings passed is undefined.  Note that
 *                 only the value field of the binding should be considered
 *                 writable by proc.
 */

void TYPE_T_dictionary_Enumerate(d, proc)
     TYPE_T_dictionary d;
     void (*proc)(/* TYPE_T_dictionary_binding *b */);
{
    int i;
    TYPE_T_dictionary_binding *binding_ptr;

    for (i=0; i<d->size; i++) {
	binding_ptr = d->slots[i];
	while (binding_ptr) {
	    proc(binding_ptr);
	    binding_ptr = binding_ptr->next;
	}
    }
}

/*
 *  Private routine:
 *
 *    unsigned int dictionary__hash(char *s):
 *        Effects: Hashs s to an unsigned integer.  This number mod the
 *                 hash table size is supposed to roughly evenly distribute
 *                 keys over the table's slots.
 */

static unsigned int dictionary__hash(s)
     char *s;
{
    unsigned int result = 0;

    if (!s)
      return(result);

    while (s[0]) {
        result <<= 1;
        result += s[0];
        s++;
    }

    return(result);
}

/*
 *    TYPE_T_dictionary_binding *TYPE_T_dictionary_Lookup(TYPE_T_dictionary d,
 *                                                        char *key):
 *        Effects: If key is not bound in d, returns 0.  Othersize,
 *                 returns a pointer to the binding that binds key.
 *                 Note the access restrictions on bindings...
 */

TYPE_T_dictionary_binding *TYPE_T_dictionary_Lookup(d, key)
     TYPE_T_dictionary d;
     char *key;
{
    TYPE_T_dictionary_binding *binding_ptr;

    binding_ptr = d->slots[dictionary__hash(key)%(d->size)];
    while (binding_ptr) {
	if (string_Eq(key, binding_ptr->key))
	  return(binding_ptr);
	binding_ptr = binding_ptr->next;
    }

    return(NULL);
}

/*
 *    TYPE_T_dictionary_binding *TYPE_T_dictionary_Define(TYPE_T_dictionary d,
 *                                            char *key,
 *                                            int *already_existed):
 *        Modifies: d
 *        Effects: If key is bound in d, returns a pointer to the binding
 *                 that binds key.  Otherwise, adds a binding of key to
 *                 d and returns its address.  If already_existed is non-zero
 *                 then *already_existed is set to 0 if key was not
 *                 previously bound in d and 1 otherwise.
 *                 Note the access restrictions on bindings...  Note also
 *                 that the value that key is bounded to if a binding is
 *                 created is undefined.  The caller should set the value
 *                 in this case.
 */

TYPE_T_dictionary_binding *TYPE_T_dictionary_Define(d, key, already_existed)
     TYPE_T_dictionary d;
     char *key;
     int *already_existed;
{
    TYPE_T_dictionary_binding **ptr_to_the_slot, *binding_ptr;

    ptr_to_the_slot = &(d->slots[dictionary__hash(key)%(d->size)]);

    binding_ptr = *ptr_to_the_slot;
    while (binding_ptr) {
	if (string_Eq(binding_ptr->key, key)) {
	    if (already_existed)
	      *already_existed = 1;
	    return(binding_ptr);
	}
	binding_ptr = binding_ptr->next;
    }

    if (already_existed)
      *already_existed = 0;
    binding_ptr = (TYPE_T_dictionary_binding *)malloc(
				        sizeof(TYPE_T_dictionary_binding));
    binding_ptr->next = *ptr_to_the_slot;
    binding_ptr->key = string_Copy(key);
    *ptr_to_the_slot = binding_ptr;
    return(binding_ptr);
}

/*
 *    void TYPE_T_dictionary_Delete(TYPE_T_dictionary d,
 *                                  TYPE_T_dictionary_binding *b):
 *        Requires: *b is a binding in d.
 *        Modifies: d
 *        Effects: Removes the binding *b from d.  Note that if 
 *                 b->value needs to be freed, it should be freed
 *                 before making this call.
 */

void TYPE_T_dictionary_Delete(d, b)
     TYPE_T_dictionary d;
     TYPE_T_dictionary_binding *b;
{
    TYPE_T_dictionary_binding **ptr_to_binding_ptr;

    ptr_to_binding_ptr = &(d->slots[dictionary__hash(b->key)%(d->size)]);

    while (*ptr_to_binding_ptr != b)
      ptr_to_binding_ptr = &((*ptr_to_binding_ptr)->next);

    *ptr_to_binding_ptr = b->next;
    free(b->key);
    free(b);
}
