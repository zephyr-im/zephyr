#ifndef eval_MODULE
#define eval_MODULE

#include "new_string.h"

/*
 *    string eval_expr(Node *expr)
 *        Modifies: dict
 *        Requires: expr is a proper expression (NOT NULL).  (see node.c)
 *        Effects: Evaluates expr to its string value which is returned.
 *                 The returned string is on the heap and must be freed
 *                 eventually.
 */

extern string eval_expr();

/*
 *    int eval_bool_expr(Node *expr)
 *        Modifies: dict
 *        Requires: expr is a proper expression or NULL.  (see node.c)
 *        Effects: Evaluates expr to its boolean value which is returned.
 *                 NULL is defined to have the boolean value true.
 */

extern int eval_bool_expr();

#endif
