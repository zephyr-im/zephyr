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
static char rcsid_exec_c[] = "$Id$";
#endif

#include <zephyr/mit-copyright.h>

/****************************************************************************/
/*                                                                          */
/*               Module containing code to execute a program:               */
/*                                                                          */
/****************************************************************************/

#include <zephyr/zephyr.h>
#include "new_memory.h"
#include "exec.h"
#include "eval.h"
#include "node.h"
#include "buffer.h"
#include "port.h"
#include "variables.h"
#include "notice.h"

static int exec_subtree(), exec_fields();

/****************************************************************************/
/*                                                                          */
/*                           Utility subroutines:                          */
/*                                                                          */
/****************************************************************************/

static string eval_exprlist_to_string(exprlist)
     Node *exprlist;
{
    string result = string_Copy("");
    string temp;
    int first_time = 1;
    
    for (; exprlist; exprlist=exprlist->next) {
	if (!first_time)
	  result = string_Concat2(result, " ");
	else
	  first_time = 0;
	
	temp = eval_expr(exprlist);
	result = string_Concat2(result, temp);
	free(temp);
    }
    
    return(result);
}

static char **eval_exprlist_to_args(exprlist)
     Node *exprlist;
{
    char **result = (char **)malloc(sizeof(char *));
    int argc = 0;

    for (; exprlist; exprlist=exprlist->next) {
	result[argc] = eval_expr(exprlist);
	argc++;
	result = (char **)realloc(result, (argc+1)*sizeof(char *));
    }
    
    result[argc] = NULL;
    return(result);
}

static void free_args(args)
     char **args;
{
    char **p;

    for (p=args; *p; p++) {
      free(*p);
  }
	
    free(args);
}

/****************************************************************************/
/*                                                                          */
/*          Subroutines to handle each particular statement type:           */
/*                                                                          */
/****************************************************************************/

#define  NOBREAK   0
#define  BREAK     1
#define  EXIT      2

/*ARGSUSED*/
static int exec_noop(node)
     Node *node;
{
    return(NOBREAK);
}

/*ARGSUSED*/
static int exec_break(node)
     Node *node;
{
    return(BREAK);
}

/*ARGSUSED*/
static int exec_exit(node)
     Node *node;
{
    return(EXIT);
}

static int exec_set(node)
     Node *node;
{
    var_set_variable_then_free_value(node->d.nodes.first->d.string_constant,
				     eval_expr(node->d.nodes.second));

    return(NOBREAK);
}

static int exec_execport(node)
     Node *node;
{
    string name = eval_expr(node->d.nodes.first);
    char **argv = eval_exprlist_to_args(node->d.nodes.second);

    create_subprocess_port(name, argv);

    free(name);
    free_args(argv);
    return(NOBREAK);
}

static int exec_appendport(node)
     Node *node;
{
    string name, filename;

    name = eval_expr(node->d.nodes.first);
    filename = eval_expr(node->d.nodes.second);

    create_file_append_port(name, filename);

    free(name);
    free(filename);
    return(NOBREAK);
}

static int exec_inputport(node)
     Node *node;
{
    string name, filename;

    name = eval_expr(node->d.nodes.first);
    filename = eval_expr(node->d.nodes.second);

    create_file_input_port(name, filename);

    free(name);
    free(filename);
    return(NOBREAK);
}

static int exec_outputport(node)
     Node *node;
{
    string name, filename;

    name = eval_expr(node->d.nodes.first);
    filename = eval_expr(node->d.nodes.second);

    create_file_output_port(name, filename);

    free(name);
    free(filename);
    return(NOBREAK);
}

static int exec_closeinput(node)
     Node *node;
{
    string name;

    name = eval_expr(node->d.nodes.first);
    close_port_input(name);

    free(name);
    return(NOBREAK);
}

static int exec_closeoutput(node)
     Node *node;
{
    string name;

    name = eval_expr(node->d.nodes.first);
    close_port_output(name);

    free(name);
    return(NOBREAK);
}

static int exec_closeport(node)
     Node *node;
{
    string name;

    name = eval_expr(node->d.nodes.first);
    close_port_input(name);
    close_port_output(name);

    free(name);
    return(NOBREAK);
}

static int exec_put(node)
     Node *node;
{
    string name, temp;

    if (node->d.nodes.second)
      temp = eval_exprlist_to_string(node->d.nodes.second);
    else
      temp = string_Copy(buffer_to_string());

    if (node->d.nodes.first) {
	name = eval_expr(node->d.nodes.first);

	write_on_port(name, temp, strlen(temp));
	free(name);
    } else
      write_on_port(var_get_variable("output_driver"), temp, strlen(temp));

    free(temp);
    return(NOBREAK);
}

static int exec_print(node)
     Node *node;
{
    string temp;

    temp = eval_exprlist_to_string(node->d.nodes.first);
    append_buffer(temp);
    free(temp);
    
    return(NOBREAK);
}

/*ARGSUSED*/
static int exec_clearbuf(node)
     Node *node;
{
    clear_buffer();

    return(NOBREAK);
}

static int exec_case(node)
     Node *node;
{
    string constant,temp;
    Node *match, *cond;
    int equal_p;

    constant = string_Downcase(eval_expr(node->d.nodes.first));
   
    for (match=node->d.nodes.second; match; match=match->next) {
	cond = match->d.nodes.first;
	if (!cond) {  /* default case */
	    free(constant);
	    return(exec_subtree(match->d.nodes.second));
	}
	for (; cond; cond=cond->next) {
	    temp = string_Downcase(eval_expr(cond));
	    equal_p = string_Eq(constant, temp);
	    free(temp);
	    if (equal_p) {
		free(constant);
		return(exec_subtree(match->d.nodes.second));
	    }
	}
    }

    free(constant);
    return(NOBREAK);
}

static int exec_while(node)
     Node *node;
{
    int continue_code = NOBREAK;

    while (eval_bool_expr(node->d.nodes.first)) {
	continue_code = exec_subtree(node->d.nodes.second);
	if (continue_code != NOBREAK)
	  break;
    }

    if (continue_code == BREAK)
      continue_code = NOBREAK;

    return(continue_code);
}

static int exec_if(node)
     Node *node;
{
    Node *conds;

    for (conds=node->d.nodes.first; conds; conds=conds->next)
      if (eval_bool_expr(conds->d.nodes.first))
	return(exec_subtree(conds->d.nodes.second));

    return(NOBREAK);
}

static int exec_exec(node)
     Node *node;
{
    int pid;
    char **argv = eval_exprlist_to_args(node->d.nodes.first);

    pid = fork();
    if (pid == -1) {
	fprintf(stderr, "zwgc: error while attempting to fork: ");
	perror("");
    } else if (pid == 0) { /* in child */
	execvp(argv[0], argv);
	fprintf(stderr,"zwgc: unable to exec %s: ", argv[0]);
	perror("");
	_exit(errno);
    }
    
    free_args(argv);
    return(NOBREAK);
}

static struct _Opstuff {
    int (*exec)();
} opstuff[] = {
    { exec_noop },                         /* string_constant */
    { exec_noop },                         /* varref */
    { exec_noop },                         /* varname */
    { exec_noop },                         /* not */
    { exec_noop },                         /* plus */
    { exec_noop },                         /* and */
    { exec_noop },                         /* or */
    { exec_noop },                         /* eq */
    { exec_noop },                         /* neq */
    { exec_noop },                         /* regeq */
    { exec_noop },                         /* regneq */
    { exec_noop },                         /* buffer */
    { exec_noop },                         /* substitute */
    { exec_noop },                         /* protect */
    { exec_noop },                         /* verbatim */
    { exec_noop },                         /* getenv */
    { exec_noop },                         /* upcase */
    { exec_noop },                         /* downcase */
    { exec_noop },                         /* zvar */
    { exec_noop },                         /* get */
    { exec_noop },                         /* lany */
    { exec_noop },                         /* rany */
    { exec_noop },                         /* lbreak */
    { exec_noop },                         /* rbreak */
    { exec_noop },                         /* lspan */
    { exec_noop },                         /* rspan */

    { exec_noop },                          /* noop statement */
    { exec_set },
    { exec_fields },

    { exec_print },
    { exec_clearbuf },

    { exec_appendport },
    { exec_execport },
    { exec_inputport },
    { exec_outputport },
    { exec_put },
    { exec_closeinput },
    { exec_closeoutput },
    { exec_closeport },

    { exec_exec },

    { exec_if },
    { exec_case },
    { exec_while },
    { exec_break },
    { exec_exit },

    { exec_noop },                           /* if */
    { exec_noop },                           /* elseif */
    { exec_noop },                           /* else */
    { exec_noop },                           /* matchlist */
    { exec_noop },                           /* default */
};

static int exec_subtree(node)
     Node *node;
{
    int retval = NOBREAK;
    
    for (; node; node=node->next) {
	retval = (opstuff[node->opcode].exec)(node);
	if (retval != NOBREAK)
	  return(retval);
    }

    return(NOBREAK);
}

/***************************************************************************/

static char *notice_fields;
static notice_fields_length = 0;
static number_of_fields = 0;

static int exec_fields(node)
     Node *node;
{
    for (node=node->d.nodes.first; node; node=node->next) {
	var_set_variable_then_free_value(node->d.string_constant,
				 get_next_field(&notice_fields,
						&notice_fields_length));
	if (number_of_fields)
	  number_of_fields--;
    }
    
    var_set_variable_to_number("number_of_fields", number_of_fields);

    return(NOBREAK);
}

void exec_process_packet(program, notice)
     Node *program;
     ZNotice_t *notice;
{
    notice_fields = notice->z_message;
    notice_fields_length = notice->z_message_len;

    var_set_number_variables_to_fields(notice_fields, notice_fields_length);

    number_of_fields = count_nulls(notice_fields, notice_fields_length);
    var_set_variable_to_number("number_of_fields", number_of_fields);

    clear_buffer();
    (void)exec_subtree(program);
}
