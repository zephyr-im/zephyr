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
static char rcsid_eval_c[] = "$Id$";
#endif

#include <zephyr/mit-copyright.h>

/****************************************************************************/
/*                                                                          */
/*                      Code to evaluate an expression:                     */
/*                                                                          */
/****************************************************************************/

#include <zephyr/zephyr.h>
#include "new_memory.h"
#include "node.h"
#include "eval.h"
#include "substitute.h"
#include "port.h"
#include "buffer.h"
#include "regexp.h"
#include "text_operations.h"
#include "zwgc.h"
#include "variables.h"

/****************************************************************************/
/*                                                                          */
/*                Code to deal with string/boolean conversion:              */
/*                                                                          */
/****************************************************************************/

/*
 *  Internal Routine:
 *
 *    int string_to_bool(string str)
 *       Effects: Returns true iff the string str represents true.
 *                True is represented by any string which is equal to
 *                "true" when case is disregraded.
 */

#define  string_to_bool(str)      (!strcasecmp(str,"true"))

/*
 *  Internal Routine:
 *
 *    string bool_to_string(int bool)
 *       Effects: Returns a string representive for the C boolean bool.
 *                (In C, true == non-zero)  I.e.,
 *                string_to_bool(bool_to_string(x)) == !!x.
 *                The string returned is on the heap & must be freed
 *                eventually.
 */

static string bool_to_string(bool)
     int bool;
{
    return(bool ? string_Copy("TRUE") : string_Copy("FALSE"));
}

/*
 *    int eval_bool_expr(Node *expr)
 *        Modifies: dict
 *        Requires: expr is a proper expression or NULL.  (see node.c)
 *        Effects: Evaluates expr to its boolean value which is returned.
 *                 NULL is defined to have the boolean value true.
 */

int eval_bool_expr(expr)
     Node *expr;
{
    string temp;
    int result;

    if (!expr)
      return(1);

    temp = eval_expr(expr);
    result = string_to_bool(temp);
    free(temp);

    return(result);
}

/****************************************************************************/
/*                                                                          */
/*                      Code to evaluate an expression:                     */
/*                                                                          */
/****************************************************************************/

/*
 *    string eval_expr(Node *expr)
 *        Modifies: dict
 *        Requires: expr is a proper expression (NOT NULL).  (see node.c)
 *        Effects: Evaluates expr to its string value which is returned.
 *                 The returned string is on the heap and must be freed
 *                 eventually.
 */

string eval_expr(expr)
     Node *expr;
{
    int opcode = expr->opcode;
    int bool_result;
    string first, second;
    char *result;
    string *text_ptr;
    char *getenv();           /* UNIX get environment variable function */

    /*
     * Dispatch based on the opcode of the top node in the expression:
     */
    switch (opcode) {
      case STRING_CONSTANT_OPCODE:
	return(string_Copy(expr->d.string_constant));

      case VARREF_OPCODE:
	return(string_Copy(var_get_variable(expr->d.string_constant)));

      case BUFFER_OPCODE:
	return(string_Copy(buffer_to_string()));

	/*
	 * Handle unary expressions:
	 */
      case NOT_OPCODE:
      case SUBSTITUTE_OPCODE:
      case PROTECT_OPCODE:
      case VERBATIM_OPCODE:
      case GETENV_OPCODE:
      case UPCASE_OPCODE:
      case DOWNCASE_OPCODE:
      case ZVAR_OPCODE:
      case GET_OPCODE:
	first = eval_expr(expr->d.nodes.first);

	switch (opcode) {
	  case NOT_OPCODE:
	    result = bool_to_string(! string_to_bool(first));
	    break;

	  case SUBSTITUTE_OPCODE:
	    result = substitute(var_get_variable, first);
	    break;

	  case PROTECT_OPCODE:
	    result=protect(first);
	    break;

	  case VERBATIM_OPCODE:
	    return(verbatim(first));

	  case GETENV_OPCODE:
	    result = getenv(first);
	    if (!result)
	      result = string_Copy("");
	    else
	      result = string_Copy(result);
	    break;

	  case UPCASE_OPCODE:
	    return(string_Upcase(first));

	  case DOWNCASE_OPCODE:
	    return(string_Downcase(first));

	  case ZVAR_OPCODE:
	    result = ZGetVariable(first);
	    if (!result)
	      result = string_Copy("");
	    else
	      result = string_Copy(result);
	    break;

	  case GET_OPCODE:
	    result = read_from_port(first);
	    break;
	}
	free(first);
	break;

	/*
	 * Handle binary operators:
	 */
      case PLUS_OPCODE:
      case AND_OPCODE:
      case OR_OPCODE:
      case EQ_OPCODE:
      case NEQ_OPCODE:
      case REGEQ_OPCODE:
      case REGNEQ_OPCODE:
	first = eval_expr(expr->d.nodes.first);
	second = eval_expr(expr->d.nodes.second);

	switch (opcode) {
	  case PLUS_OPCODE:
	    result = string_Concat(first, second);
	    free(first);
	    free(second);
	    return(result);

	  case AND_OPCODE:
	    bool_result = string_to_bool(first) && string_to_bool(second);
	    break;

	  case OR_OPCODE:
	    bool_result = string_to_bool(first) || string_to_bool(second);
	    break;

	  case EQ_OPCODE:
	    bool_result = string_Eq(first, second);
	    break;

	  case NEQ_OPCODE:
	    bool_result = string_Neq(first, second);
	    break;

	  case REGEQ_OPCODE:
	    bool_result = ed_regexp_match_p(first, second);
	    break;

	  case REGNEQ_OPCODE:
	    bool_result = !ed_regexp_match_p(first, second);
	    break;
	}
	free(first);
	free(second);
	result = bool_to_string(bool_result);
	break;

	/*
	 * Handle text-manipulation operators:
	 */
      case LANY_OPCODE:    case RANY_OPCODE:  
      case LBREAK_OPCODE:  case RBREAK_OPCODE:
      case LSPAN_OPCODE:   case RSPAN_OPCODE:
	first = eval_expr(expr->d.nodes.first);
	second = eval_expr(expr->d.nodes.second);
	text_ptr = &first;

	switch (opcode) {
	  case LANY_OPCODE:
	    result = lany(text_ptr, second);
	    break;

	  case RANY_OPCODE:  
	    result = rany(text_ptr, second);
	    break;

	  case LBREAK_OPCODE:
	    result = lbreak(text_ptr, string_to_character_class(second));
	    break;

	  case RBREAK_OPCODE:
	    result = rbreak(text_ptr, string_to_character_class(second));
	    break;

	  case LSPAN_OPCODE:
	    result = lspan(text_ptr, string_to_character_class(second));
	    break;

	  case RSPAN_OPCODE:
	    result = rspan(text_ptr, string_to_character_class(second));
	    break;
	}

	if (expr->d.nodes.first->opcode == VARREF_OPCODE)
	  var_set_variable(expr->d.nodes.first->d.string_constant, first);
	free(first);
	free(second);
	break;

#ifdef DEBUG
      default:
	printf("zwgc: internal error: attempt to evaluate the following non-expression:\n");  fflush(stdout);
	node_display(expr);
	printf("\n\n");
	exit(2);
#endif
    }

    return(result);
}
