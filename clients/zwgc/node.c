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
static char rcsid_node_c[] = "$Id$";
#endif

#include <zephyr/mit-copyright.h>

#include <stdio.h>
#include "new_memory.h"
#include "node.h"

/****************************************************************************/
/*                                                                          */
/*            Internal node construction & destruction functions:           */
/*                                                                          */
/****************************************************************************/

/*
 * NODE_BATCH_SIZE - the number of nodes to malloc at once to save overhead:
 */

#define  NODE_BATCH_SIZE    100

/*
 * The nodes we have malloced are kept in a linked list of bunches of
 * NODE_BATCH_SIZE nodes.  Nodes points to the first bunch on the list
 * and current_bunch to the last.  All nodes from the first one in the first
 * bunch to the last_node_in_current_bunch_used'th one in the last bunch
 * are in use.  The others have not been used yet.
 */

static struct _bunch_of_nodes {
    struct _bunch_of_nodes *next_bunch;
    Node nodes[NODE_BATCH_SIZE];
} *nodes = NULL;
static struct _bunch_of_nodes *current_bunch = NULL;
static int last_node_in_current_bunch_used = -1;

/*
 *  Internal Routine:
 *
 *    Node *node_create(int opcode)
 *        Effects: Creates a node with opcode opcode and returns a pointer
 *                 to it.  The next pointer of the returned node is NULL.
 *                 If the opcode is STRING_CONSTANT_OPCODE the caller must
 *                 ensure that the string_constant field points to a valid
 *                 string on the heap when node_DestroyAllNodes is called.
 */

static Node *node_create(opcode)
     int opcode;
{
    Node *result;

    if (!nodes) {
	/*
	 * Handle special case where no nodes allocated yet:
	 */
	current_bunch = nodes = (struct _bunch_of_nodes *)
	  malloc(sizeof(struct _bunch_of_nodes));
	nodes->next_bunch = NULL;
	last_node_in_current_bunch_used = -1;
    }

    /*
     * If all nodes allocated so far in use, allocate another
     * bunch of NODE_BATCH_SIZE nodes:
     */
    if (last_node_in_current_bunch_used == NODE_BATCH_SIZE-1) {
	current_bunch->next_bunch = (struct _bunch_of_nodes *)
	  malloc(sizeof(struct _bunch_of_nodes));
	current_bunch = current_bunch->next_bunch;
	current_bunch->next_bunch = NULL;
	last_node_in_current_bunch_used = -1;
    }

    /*
     * Get next not already used node & ready it for use:
     */
    last_node_in_current_bunch_used++;
    result = &(current_bunch->nodes[last_node_in_current_bunch_used]);
    result->opcode = opcode;
    result->next = NULL;

    return(result);
}

/*
 *
 */

void node_DestroyAllNodes()
{
    struct _bunch_of_nodes *next_bunch;
    int i, last_node_used_in_this_bunch;

    while (nodes) {
	next_bunch = nodes->next_bunch;
	last_node_used_in_this_bunch = next_bunch ?
	  NODE_BATCH_SIZE-1 : last_node_in_current_bunch_used;
	for (i=0; i<=last_node_used_in_this_bunch; i++) {
	    if (nodes->nodes[i].opcode==STRING_CONSTANT_OPCODE)
	      free(nodes->nodes[i].d.string_constant);
	    else if (nodes->nodes[i].opcode==VARREF_OPCODE)
	      free(nodes->nodes[i].d.string_constant);
	    else if (nodes->nodes[i].opcode==VARNAME_OPCODE)
	      free(nodes->nodes[i].d.string_constant);
	}
	free(nodes);
	nodes = next_bunch;
    }

    current_bunch = nodes;
}

/****************************************************************************/
/*                                                                          */
/*                     Node construction functions:                         */
/*                                                                          */
/****************************************************************************/

Node *node_create_string_constant(opcode, text)
     int opcode;
     string text;
{
    Node *n;

    n = node_create(opcode);
    n->d.string_constant = text;
    return(n);
}

Node *node_create_noary(opcode)
     int opcode;
{
    Node *n;

    n = node_create(opcode);
    return(n);
}

Node *node_create_unary(opcode, arg)
     int opcode;
     Node *arg;
{
    Node *n;

    n = node_create(opcode);
    n->d.nodes.first = arg;
    return(n);
}

Node *node_create_binary(opcode, first_arg, second_arg)
     int opcode;
     Node *first_arg;
     Node *second_arg;
{
    Node *n;

    n = node_create(opcode);
    n->d.nodes.first = first_arg;
    n->d.nodes.second = second_arg;
    return(n);
}

/****************************************************************************/
/*                                                                          */
/*                        Node utility functions:                           */
/*                                                                          */
/****************************************************************************/

/*
 *    Node *reverse_list_of_nodes(Node *list)
 *        Modifies: the nodes on the linked list list
 *        Effects: Reverses the linked list list and returns it.
 *                 This is done by modifing the next pointers of the
 *                 list elements to point to the previous node & returning
 *                 the address of the (previously) last node.
 */

Node *reverse_list_of_nodes(list)
     Node *list;
{
    Node *next_node;
    Node *head = NULL;

    while (list) {
	next_node = list->next;

	/*
	 * Add the node list to the beginning of linked list head:
	 */
	list->next = head;
	head = list;

	list = next_node;
    }

    return(head);
}

/****************************************************************************/
/*                                                                          */
/*                        Node display functions:                           */
/*                                                                          */
/****************************************************************************/

#ifdef DEBUG

static void print_stuff(node, format_string)
     Node *node;
     string format_string;
{
    char c;

    for (c=(*(format_string++)); c; c=(*(format_string++))) {
	if (c!='%') {
	    putchar(c);
	    continue;
	}
	c=(*(format_string++));
	if (!c) {
	    format_string--;
	    continue;
	}
	if (c=='s')
	  printf("%s", node->d.string_constant);
	else if (c=='1')
	  node_display(node->d.nodes.first);
	else if (c=='2')
	  node_display(node->d.nodes.second);
	else
	  putchar(c);
    }
}

static string how_to_print[] = {
    "\"%s\"",        /* constant string */
    "$%s",           /* varref */
    "%s",            /* varname */

    "!%1",

    "( %1 + %2 )",
    "( %1 and %2 )",
    "( %1 or %2 )",
    "( %1 == %2 )",
    "( %1 != %2 )",
    "( %1 =~ %2 )",
    "( %1 !~ %2 )",

    "buffer()",
    
    "substitute(%1)",
    "protect(%1)",
    "verbatim(%1)",
    "getenv(%1)",
    "upcase(%1)",
    "downcase(%1)",
    "zvar(%1)",
    "get(%1)",

    "lany(%1, %2)",
    "rany(%1, %2)",
    "lbreak(%1, %2)",
    "rbreak(%1, %2)",
    "lspan(%1, %2)",
    "rspan(%1, %2)",

    "noop\n",
    "set %1 = %2\n",
    "fields %1\n",

    "print %1\n",
    "clearbuf\n",
    
    "appendport %1 %2\n",
    "execport %1 %2\n",
    "inputport %1 %2\n",
    "outputport %1 %2\n",
    "put %1 %2\n",
    "closeinput %1\n",
    "closeoutput %1\n",
    "closeport %1\n",

    "exec %1 %2\n",

    "%1endif\n",
    "case %1\n%2endcase\n",
    "while %1 do\n%2endwhile\n",
    "break\n",
    "exit\n",
    
    "if %1 then\n%2",
    "elseif %1 then\n%2",
    "else\n%2",
    "match %1\n%2",
    "default\n%2" };

void node_display(node)
     Node *node;
{
    int opcode = LAST_EXPR_OPCODE + 1;

    for (; node; node=node->next) {
	if (opcode<=LAST_EXPR_OPCODE)
	  printf(" ");

	opcode = node->opcode;
	if (opcode>=0 && opcode<NUMBER_OF_OPCODES)
	  print_stuff(node, how_to_print[opcode]);
	else
	  printf("[opcode %d]", opcode);
    }
}

#endif
