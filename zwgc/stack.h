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
static char rcsid_stack_h[] = "$Header$";
#endif

#include <zephyr/mit-copyright.h>

/****************************************************************************/
/*                                                                          */
/*               A generic stack type based on linked lists:                */
/*                                                                          */
/****************************************************************************/

#ifndef TYPE_T_stack_TYPE
#define TYPE_T_stack_TYPE

#ifndef  NULL
#define  NULL 0
#endif

typedef struct _TYPE_T_stack {
    struct _TYPE_T_stack *next;
    TYPE_T data;
} *TYPE_T_stack;

#define  TYPE_T_stack_create()           ((struct _TYPE_T_stack *) NULL)

#define  TYPE_T_stack_empty(stack)       (!(stack))

#ifdef DEBUG
#define  TYPE_T_stack_top(stack)         ((stack) ? (stack)->data :\
					  (abort(),(stack)->data))
#else
#define  TYPE_T_stack_top(stack)         ((stack)->data)
#endif

#ifdef DEBUG
#define  TYPE_T_stack_pop(stack)  { TYPE_T_stack old = (stack);\
				    if (!old)\
				      abort(); /*<<<>>>*/\
				    (stack) = old->next;\
				    free(old); }
#else
#define  TYPE_T_stack_pop(stack)  { TYPE_T_stack old = (stack);\
				    (stack) = old->next;\
				    free(old); }
#endif

#define  TYPE_T_stack_push(stack,object) \
           { TYPE_T_stack new = (struct _TYPE_T_stack *)\
	       malloc(sizeof (struct _TYPE_T_stack));\
	     new->next = (stack);\
	     new->data = object;\
	     (stack) = new; }

#endif
