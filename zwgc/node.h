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
#define  GETENV_OPCODE                  15
#define  UPCASE_OPCODE                  16
#define  DOWNCASE_OPCODE                17
#define  ZVAR_OPCODE                    18
#define  GET_OPCODE                     19

#define  LANY_OPCODE                    20
#define  RANY_OPCODE                    21
#define  LBREAK_OPCODE                  22
#define  RBREAK_OPCODE                  23
#define  LSPAN_OPCODE                   24
#define  RSPAN_OPCODE                   25

#define  LAST_EXPR_OPCODE               25

#define  NOOP_OPCODE                    26
#define  SET_OPCODE                     27
#define  FIELDS_OPCODE                  28

#define  PRINT_OPCODE                   29
#define  CLEARBUF_OPCODE                30

#define  APPENDPORT_OPCODE              31
#define  EXECPORT_OPCODE                32
#define  INPUTPORT_OPCODE               33
#define  OUTPUTPORT_OPCODE              34
#define  PUT_OPCODE                     35
#define  CLOSEINPUT_OPCODE              36
#define  CLOSEOUTPUT_OPCODE             37
#define  CLOSEPORT_OPCODE               38

#define  EXEC_OPCODE                    39

#define  IF_STMT_OPCODE                 40
#define  CASE_OPCODE                    41
#define  WHILE_OPCODE                   42
#define  BREAK_OPCODE                   43
#define  EXIT_OPCODE                    44

#define  IF_OPCODE                      45
#define  ELSEIF_OPCODE                  46
#define  ELSE_OPCODE                    47
#define  MATCHLIST_OPCODE               48
#define  DEFAULT_OPCODE                 49

#define  NUMBER_OF_OPCODES              50

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

extern void node_DestroyAllNodes();

extern Node *node_create_string_constant();

extern Node *node_create_noary();
extern Node *node_create_unary();
extern Node *node_create_binary();

/*
 *    Node *reverse_list_of_nodes(Node *list)
 *        Modifies: the nodes on the linked list list
 *        Effects: Reverses the linked list list and returns it.
 *                 This is done by modifing the next pointers of the
 *                 list elements to point to the previous node & returning
 *                 the address of the (previously) last node.
 */

extern Node *reverse_list_of_nodes();

#ifdef DEBUG
extern void node_display();
#endif

#endif
