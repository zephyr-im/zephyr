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

#ifndef TYPE_T_dictionary_TYPE
#define TYPE_T_dictionary_TYPE

typedef struct _TYPE_T_dictionary_binding {
    struct _TYPE_T_dictionary_binding *next;       /* PRIVATE */
    char *key;                                     /* READ-ONLY */
    TYPE_T value;
} TYPE_T_dictionary_binding;

typedef struct _TYPE_T_dictionary {                /* PRIVATE */
    int size;
    TYPE_T_dictionary_binding **slots;
} *TYPE_T_dictionary;

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

extern TYPE_T_dictionary TYPE_T_dictionary_Create(/* int size */);

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

extern void TYPE_T_dictionary_Destroy(/* TYPE_T_dictionary d */);

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

extern void TYPE_T_dictionary_Enumerate(/* TYPE_T_dictionary d, 
					   void (*proc)() */);

/*
 *    TYPE_T_dictionary_binding *TYPE_T_dictionary_Lookup(TYPE_T_dictionary d,
 *                                                        char *key):
 *        Effects: If key is not bound in d, returns 0.  Othersize,
 *                 returns a pointer to the binding that binds key.
 *                 Note the access restrictions on bindings...
 */

extern TYPE_T_dictionary_binding *TYPE_T_dictionary_Lookup(/* d, key */);

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

extern TYPE_T_dictionary_binding *TYPE_T_dictionary_Define();

/*
 *    void TYPE_T_dictionary_Delete(TYPE_T_dictionary d,
 *                                  TYPE_T_dictionary_binding *b):
 *        Requires: *b is a binding in d.
 *        Modifies: d
 *        Effects: Removes the binding *b from d.  Note that if 
 *                 b->value needs to be freed, it should be freed
 *                 before making this call.
 */

extern void TYPE_T_dictionary_Delete();

#endif
