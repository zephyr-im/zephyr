%{
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
static char rcsid_parser_y[] = "$Id$";
#endif

#include <zephyr/mit-copyright.h>

/* Saber-C suppressions because yacc loses */

/*SUPPRESS 288*/
/*SUPPRESS 287*/

#include <stdio.h>
#include "lexer.h"
#include "parser.h"
#include "node.h"
#include "zwgc.h"

/*
 * the_program - local variable used to communicate the program's node
 *               representation from the program action to the parse_file
 *               function.
 */

static Node *the_program;
%}

%union{
    char *text;
    struct _Node *node;
}

%start program

%token  ERROR
%token  <text>    VARNAME VARREF STRING SHOW

%token  APPENDPORT BUFFER BREAK CLOSEINPUT CLOSEOUTPUT
%token  CLOSEPORT CASE CLEARBUF DEFAULT DISPLAY DO DOWNCASE
%token  ELSE ELSEIF ENDCASE ENDIF ENDWHILE EXEC EXECPORT EXIT
%token  FIELDS GET GETENV IF INPUTPORT LANY LBREAK LSPAN
%token  MATCH NOOP NOT OUTPUTPORT PRINT PROTECT VERBATIM PUT RANY RBREAK
%token  RSPAN SET SHOW SUBSTITUTE THEN UPCASE WHILE ZVAR

%type <node> expr varname string
%type <node> exprlist comma_exprlist varnamelist
%type <node> statement statements program elseparts elseifparts
%type <node> match matchlist

%left '|'
%left '&'
%left EQ NEQ REGEQ REGNEQ
%left '+'
%left '!'

%%

/*
 * A program is simply a list of statements: (may be NULL if no statements...)
 */
program : statements
        { the_program = reverse_list_of_nodes($1);
	  $$ = the_program; }
        ;

varname : VARNAME
       { $$ = node_create_string_constant(VARNAME_OPCODE, $1); }
        ;

string : STRING
       { $$ = node_create_string_constant(STRING_CONSTANT_OPCODE, $1); }
       ;

expr : '(' expr ')'
        { $$ = $2; }

     | string
        { $$ = $1; }
     | VARREF
       { $$ = node_create_string_constant(VARREF_OPCODE, $1); }

     | '!' expr
        { $$ = node_create_unary(NOT_OPCODE, $2); }

     | expr '+' expr
        { $$ = node_create_binary(PLUS_OPCODE, $1, $3); }
     | expr '|' expr                             /* note "or" == '|' */
        { $$ = node_create_binary(OR_OPCODE, $1, $3); }
     | expr '&' expr                             /* note "and" == '&' */
        { $$ = node_create_binary(AND_OPCODE, $1, $3); }
     | expr EQ expr
        { $$ = node_create_binary(EQ_OPCODE, $1, $3); }
     | expr NEQ expr
        { $$ = node_create_binary(NEQ_OPCODE, $1, $3); }
     | expr REGEQ expr
        { $$ = node_create_binary(REGEQ_OPCODE, $1, $3); }
     | expr REGNEQ expr
        { $$ = node_create_binary(REGNEQ_OPCODE, $1, $3); }

     | BUFFER '(' ')'
        { $$ = node_create_noary(BUFFER_OPCODE); }

     | SUBSTITUTE '(' expr ')'
        { $$ = node_create_unary(SUBSTITUTE_OPCODE, $3); }
     | PROTECT '(' expr ')'
	{ $$ = node_create_unary(PROTECT_OPCODE, $3); }
     | VERBATIM '(' expr ')'
	{ $$ = node_create_unary(VERBATIM_OPCODE, $3); }
     | GETENV '(' expr ')'
        { $$ = node_create_unary(GETENV_OPCODE, $3); }
     | UPCASE '(' expr ')'
        { $$ = node_create_unary(UPCASE_OPCODE, $3); }
     | DOWNCASE '(' expr ')'
        { $$ = node_create_unary(DOWNCASE_OPCODE, $3); }
     | ZVAR '(' expr ')'
        { $$ = node_create_unary(ZVAR_OPCODE, $3); }
     | GET '(' expr ')'
        { $$ = node_create_unary(GET_OPCODE, $3); }

     | LANY '(' expr ',' expr ')'
        { $$ = node_create_binary(LANY_OPCODE, $3, $5 ); }
     | RANY '(' expr ',' expr ')'
        { $$ = node_create_binary(RANY_OPCODE, $3, $5 ); }
     | LBREAK '(' expr ',' expr ')'
        { $$ = node_create_binary(LBREAK_OPCODE, $3, $5 ); }
     | RBREAK '(' expr ',' expr ')'
        { $$ = node_create_binary(RBREAK_OPCODE, $3, $5 ); }
     | LSPAN '(' expr ',' expr ')'
        { $$ = node_create_binary(LSPAN_OPCODE, $3, $5 ); }
     | RSPAN '(' expr ',' expr ')'
        { $$ = node_create_binary(RSPAN_OPCODE, $3, $5 ); }
     ;

statement : NOOP
              { $$ = node_create_noary(NOOP_OPCODE); }
          | SET varname '=' expr
              { $$ = node_create_binary(SET_OPCODE, $2, $4); }
	  | FIELDS varnamelist
              { $$ = node_create_unary(FIELDS_OPCODE,
				       reverse_list_of_nodes($2)); }

         /*
  	  * Output to & control of output buffer statements:
	  */
 	  | PRINT exprlist
              { $$ = node_create_unary(PRINT_OPCODE,
				       reverse_list_of_nodes($2)); }
	  | SHOW
              { $$ = node_create_unary(PRINT_OPCODE,
		       node_create_unary(SUBSTITUTE_OPCODE,
			 node_create_string_constant(STRING_CONSTANT_OPCODE,
						     $1))); }
          | CLEARBUF
	      { $$ = node_create_noary(CLEARBUF_OPCODE); }

          /*
	   * Statements to manage ports:
	   */
          | APPENDPORT expr expr
              { $$ = node_create_binary(APPENDPORT_OPCODE, $2, $3); }
          | EXECPORT expr expr exprlist
              { $3->next = reverse_list_of_nodes($4);
		$$ = node_create_binary(EXECPORT_OPCODE, $2, $3); }
          | INPUTPORT expr expr
              { $$ = node_create_binary(INPUTPORT_OPCODE, $2, $3); }
          | OUTPUTPORT expr expr
              { $$ = node_create_binary(OUTPUTPORT_OPCODE, $2, $3); }
	  | PUT expr exprlist
              { $$ = node_create_binary(PUT_OPCODE, $2,
					reverse_list_of_nodes($3)); }
	  | PUT
              { $$ = node_create_binary(PUT_OPCODE, 0, 0); }
          | CLOSEINPUT expr
              { $$ = node_create_unary(CLOSEINPUT_OPCODE, $2); }
          | CLOSEOUTPUT expr
              { $$ = node_create_unary(CLOSEOUTPUT_OPCODE, $2); }
          | CLOSEPORT expr
              { $$ = node_create_unary(CLOSEPORT_OPCODE, $2); }

          /*
	   * Statements to run subprocesses without I/O to them:
	   */
	  | EXEC expr exprlist
              { $2->next = reverse_list_of_nodes($3);
		$$ = node_create_unary(EXEC_OPCODE, $2); }

          /*
	   * Control statements:
	   */
          | IF expr THEN statements elseparts ENDIF
              { Node *n = node_create_binary(IF_OPCODE, $2,
					     reverse_list_of_nodes($4));
		n->next = $5;
		$$ = node_create_unary(IF_STMT_OPCODE, n); }
	  | CASE expr matchlist ENDCASE
              { $$ = node_create_binary(CASE_OPCODE, $2,
					reverse_list_of_nodes($3)); }
	  | WHILE expr DO statements ENDWHILE
              { $$ = node_create_binary(WHILE_OPCODE, $2,
					reverse_list_of_nodes($4)); }
          | BREAK
              { $$ = node_create_noary(BREAK_OPCODE); }
          | EXIT
              { $$ = node_create_noary(EXIT_OPCODE); }
	  ;

elseparts : elseifparts
                { $$ = reverse_list_of_nodes($1); }
          | elseifparts ELSE statements
                { $$ = node_create_binary(ELSE_OPCODE, 0,
					  reverse_list_of_nodes($3));
		  $$->next = $1;
	          $$ = reverse_list_of_nodes($$); }

/* elseifparts needs to be reversed before using... */
elseifparts : /* empty */
                { $$ = 0; }
            | elseifparts ELSEIF expr THEN statements
                { $$ = node_create_binary(ELSEIF_OPCODE, $3,
					  reverse_list_of_nodes($5));
		  $$->next = $1; }
            ;

match : MATCH comma_exprlist statements
                { $$ = node_create_binary(MATCHLIST_OPCODE,
					  reverse_list_of_nodes($2),
					  reverse_list_of_nodes($3)); }
      | DEFAULT statements
                { $$ = node_create_binary(DEFAULT_OPCODE, 0,
					  reverse_list_of_nodes($2)); }
      ;

/*
 * Various lists of non-terminals like expr's and varname's.  Each is
 * built up as a linked list using the nodes' next fields.  To prevent
 * Yacc stack overflow on long lists, these are put on the linked list
 * BACKWARDS.  The user of these must first call reverse_list_of_nodes
 * on one of these before using it.  All except comma_exprlist
 * allow 0 elements on the list in which case their value is NULL.
 * (comma_exprlist requires at least one element)
 */

exprlist : /* empty */
             { $$ = 0; }
	 | exprlist expr
             { $$ = $2;
	       $$->next = $1; }
	 ;

comma_exprlist : expr
                 { $$ = $1; }
               | comma_exprlist ',' expr
                 { $$ = $3;
		   $$->next = $1; }
	       ;

varnamelist : /* empty */
             { $$ = 0; }
            | varnamelist varname
             { $$ = $2;
	       $$->next = $1; }
	    ;

matchlist : /* empty */
                { $$ = 0; }
          | matchlist match
                { $$ = $2;
		  $$->next = $1; }
          ;

statements : /* empty */
        { $$ = 0; }
           | statements statement
        { $$ = $2;
	  $$->next = $1; }
           ;

%%

/*
 * error_occured - Set to true when a parse error is reported.  If it is false
 *                 at the time a parse error is reported, a message is
 *                 printed on stderr.  See report_parse_error for more
 *                 details.
 */

static int error_occured = 0;

/*
 *  Parser-Lexer Internal Routine:
 *
 *    void report_parse_error(char *error_message, int line_number)
 *        Modifies: error_occured, stderr
 *        Effects: This routine is called to report a parser or lexer
 *                 error.  Error_message is the error message and line_number
 *                 the line number it occured on.  The reported error message
 *                 is of the form "....<error_message> on line <line #>.\n".
 *                 This routine sets error_occured (local to parser.y) to
 *                 true.  If it was previously false, the error message
 *                 is reported to the user via stderr. 
 */

void report_parse_error(error_message, line_number)
     char *error_message;
     int line_number;
{
    if (error_occured)
      return;
    error_occured = 1;

    fprintf(stderr, "zwgc: error in description file: %s on line %d.\n",
	    error_message, line_number);
    fflush(stderr);
}

/*
 *  yyerror - internal routine - used by yacc to report syntax errors and
 *            stack overflow errors.
 */
 
static void yyerror(message)
     char *message;
{
    report_parse_error(message, yylineno);
}

/*
 *    struct _Node *parse_file(FILE *input_file)
 *        Requires: input_file is opened for reading, no pointers to
 *                  existing nodes will ever be dereferened.
 *        Modifies: *input_file, stderr, all existing nodes
 *        Effects: First this routine destroys all nodes.  Then it parses
 *                 input_file as a zwgc description langauge file.  If
 *                 an error is encountered, an error message is printed
 *                 on stderr and NULL is returned.  If no error is
 *                 encountered, a pointer to the node representation of
 *                 the parsed program is returned, suitable for passing to
 *                 exec.c.  Note that NULL will also be returned for a
 *                 empty file & is a valid program.  Either way, input_file
 *                 is closed before this routine returns.
 */

struct _Node *parse_file(input_file)
     FILE *input_file;
{
    the_program = NULL;
    error_occured = 0;
    node_DestroyAllNodes();

    lex_open(input_file);
    yyparse();
    fclose(input_file);

    if (error_occured) {
	node_DestroyAllNodes();
	the_program = NULL;
    }

#ifdef DEBUG
    if (zwgc_debug) {
	printf("****************************************************************************\n");
	node_display(the_program);
	printf("****************************************************************************\n");
    }
#endif
    
    return(the_program);
}
