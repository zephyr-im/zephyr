/* This file is part of the Project Athena Zephyr Notification System.
 * It is one of the source files comprising zwgc, the Zephyr WindowGram
 * client.
 *
 *      Created by:     Marc Horowitz <marc@athena.mit.edu>
 *
 *      $Id$
 *
 *      Copyright (c) 1989 by the Massachusetts Institute of Technology.
 *      For copying and distribution information, see the file
 *      "mit-copyright.h".
 */


#include <zephyr/mit-copyright.h>

#ifndef node_MODULE
#define node_MODULE

#include "new_string.h"

#define  STRING_CONSTANT_OPCODE         0
#define  VARREF_OPCODE                  1
#define  VARNAME_OPCODE                 2

#define  NOT_OPCODE                     3

#define  PLUS_OPCODE                    4
#define  AND_OPCODE                     5
#define  OR_OPCODE                      6
#define  EQ_OPCODE                      7
#define  NEQ_OPCODE                     8
#define  REGEQ_OPCODE                   9
#define  REGNEQ_OPCODE                  10

#define  BUFFER_OPCODE                  11

#define  SUBSTITUTE_OPCODE              12
#define  PROTECT_OPCODE                 13
#define  VERBATIM_OPCODE                14
#define  STYLESTRIP_OPCODE              15
#define  GETENV_OPCODE                  16
#define  UPCASE_OPCODE                  17
#define  DOWNCASE_OPCODE                18
#define  ZVAR_OPCODE                    19
#define  GET_OPCODE                     20

#define  LANY_OPCODE                    21
#define  RANY_OPCODE                    22
#define  LBREAK_OPCODE                  23
#define  RBREAK_OPCODE                  24
#define  LSPAN_OPCODE                   25
#define  RSPAN_OPCODE                   26

#define  LAST_EXPR_OPCODE               26

#define  NOOP_OPCODE                    27
#define  SET_OPCODE                     28
#define  FIELDS_OPCODE                  29

#define  PRINT_OPCODE                   30
#define  CLEARBUF_OPCODE                31

#define  APPENDPORT_OPCODE              32
#define  EXECPORT_OPCODE                33
#define  INPUTPORT_OPCODE               34
#define  OUTPUTPORT_OPCODE              35
#define  PUT_OPCODE                     36
#define  CLOSEINPUT_OPCODE              37
#define  CLOSEOUTPUT_OPCODE             38
#define  CLOSEPORT_OPCODE               39

#define  EXEC_OPCODE                    40

#define  IF_STMT_OPCODE                 41
#define  CASE_OPCODE                    42
#define  WHILE_OPCODE                   43
#define  BREAK_OPCODE                   44
#define  EXIT_OPCODE                    45

#define  IF_OPCODE                      46
#define  ELSEIF_OPCODE                  47
#define  ELSE_OPCODE                    48
#define  MATCHLIST_OPCODE               49
#define  DEFAULT_OPCODE                 50

#define  NUMBER_OF_OPCODES              51

typedef struct _Node {
    int opcode;                              /* Read-only */
    struct _Node *next;
    union {
	string string_constant;
	struct {
	    struct _Node *first;
	    struct _Node *second;
	} nodes;
    } d;
} Node;

/* Function externs */

extern void node_DestroyAllNodes(void);

extern Node *node_create_string_constant(int, string);

extern Node *node_create_noary(int);
extern Node *node_create_unary(int, Node *);
extern Node *node_create_binary(int, Node *, Node *);

/*
 *    Node *reverse_list_of_nodes(Node *list)
 *        Modifies: the nodes on the linked list list
 *        Effects: Reverses the linked list list and returns it.
 *                 This is done by modifing the next pointers of the
 *                 list elements to point to the previous node & returning
 *                 the address of the (previously) last node.
 */

extern Node *reverse_list_of_nodes(Node *);

#ifdef DEBUG
extern void node_display(Node *);
#endif

#endif
