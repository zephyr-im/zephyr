/****************************************************************************/
/*                                                                          */
/*               The lexer for the zwgc description language:               */
/*                                                                          */
/****************************************************************************/

#include <stdio.h>
#include "new_memory.h"
#include "new_string.h"
#include "int_dictionary.h"
#include "lexer.h"
#include "parser.h"
#include "y.tab.h"

/*
 * yylineno - this holds the current line # we are on.  Updated automatically
 *            by input() and unput().
 */

int yylineno;

/*
 * keyword_dict - this dictionary maps keyword names to their token numbers.
 */

static int_dictionary keyword_dict = NULL;

/****************************************************************************/
/*                                                                          */
/*                               I/O functions:                             */
/*                                                                          */
/****************************************************************************/

/*
 * input_file - this holds the FILE pointer to the file currently being lexed.
 */

static FILE *input_file;

/*
 * pushback - if not -1, holds a character that was pushed back by unput but
 *            not yet read by input.
 */

static int pushback = -1;

static char input()
{
    int c;

    if (pushback != -1) {
	c = pushback;
	pushback = -1;
	if (c=='\n')
	  yylineno++;
	return(c);
    }

    c = getc(input_file);
    if (c=='\n')
      yylineno++;
    if (c==EOF)
      c = 0;

    return(c);
}

static void unput(c)
     int c;
{
#ifdef DEBUG
    if (pushback != -1) {
	printf("Attempt to push back 2 characters at one time!\n");
	exit(1);
    }
#endif

    pushback = c;
    if (c == '\n')
      yylineno--;
}

/****************************************************************************/
/*                                                                          */
/*                           Initialization routines:                       */
/*                                                                          */
/****************************************************************************/

struct keyword_info {
    string keyword;
    int keyword_number;
};

/*
 * keywords - This table holds a copy of the mapping from keyword name to
 *            token number and is used to initialize keyword_dict:
 */

static struct keyword_info keywords[] =   {
                   { "and", '&' },
		   { "appendport", APPENDPORT },
		   { "buffer", BUFFER },
		   { "break", BREAK },
		   { "closeinput", CLOSEINPUT },
		   { "closeoutput", CLOSEOUTPUT },
		   { "closeport", CLOSEPORT },
		   { "case", CASE },
		   { "clearbuf", CLEARBUF },
		   { "default", DEFAULT },
		   { "do", DO },
		   { "downcase", DOWNCASE },
		   { "else", ELSE },
		   { "elseif", ELSEIF },
		   { "endcase", ENDCASE },
		   { "endif", ENDIF },
		   { "endwhile", ENDWHILE },
		   { "exec", EXEC },
		   { "execport", EXECPORT },
		   { "exit", EXIT },
		   { "fields", FIELDS },
		   { "get", GET },
		   { "getenv", GETENV },
		   { "if", IF },
		   { "inputport", INPUTPORT },
		   { "lany", LANY },
		   { "lbreak", LBREAK },
		   { "lspan", LSPAN },
		   { "match", MATCH },
		   { "noop", NOOP },
		   { "not", '!' },		
		   { "or", '|' },
		   { "outputport", OUTPUTPORT },
		   { "print", PRINT },
		   { "protect", PROTECT },
		   { "put", PUT },
		   { "rany", RANY },
		   { "rbreak", RBREAK },
		   { "rspan", RSPAN },
		   { "set", SET },
		   { "show", SHOW },
		   { "substitute", SUBSTITUTE },
		   { "then", THEN },
		   { "upcase", UPCASE },
		   { "while", WHILE },
		   { "verbatim", VERBATIM },
		   { "zvar", ZVAR } };

/*
 * lex_open - this routine [re]initializes the lexer & prepares it to lex
 *            a file.  Resets current line # to 1.
 */

void lex_open(file)
     FILE *file;
{
    /*
     * Initialize I/O:
     */
    input_file = file;
    yylineno = 1;
    pushback = -1;

    /*
     * Initialize keyword_dict from keywords if needed:
     */
    if (!keyword_dict) {
	int i;

	keyword_dict = int_dictionary_Create(101);

	for (i=0; i<sizeof(keywords)/sizeof(struct keyword_info); i++)
	  int_dictionary_Define(keyword_dict, keywords[i].keyword,
				0)->value = keywords[i].keyword_number;
    }
}

/****************************************************************************/
/*                                                                          */
/*                            lex subroutines:                              */
/*                                                                          */
/****************************************************************************/

/*
 * eat_escape_code - this rountine eats an escape code & returns the character
 *                   it codes for or 0 if it codes for "".
 *                   (an escape code is what follows a '\\' in a quoted
 *                   string)  Current escape codes are:
 *
 *                       "n"          == '\n'
 *                       "t"          == '\t'
 *                       "b"          == '\b'
 *                       "\n"         == "" (i.e., returns 0)
 *                       <EOF>        == ""
 *                       [0-7]{1,3}   == the character represented by the code
 *                                       interpreted as an octal number.
 *                       [^ntb0-7\n]  == the same character.  I.e., "*" == '*'
 */

#define  is_octal_digit(c)           (((c)>='0') && ((c)<='7'))

static char eat_escape_code()
{
    int c, coded_char;

    c = input();

    switch (c) {
      case 0:  /* i.e., EOF */
	unput(c);
	return(c);
      case '\n':
	return(0);
      case 'n':
	return('\n');
      case 't':
	return('\t');
      case 'b':
	return('\b');
      case '0':   case '1':   case '2':   case '3':
      case '4':   case '5':   case '6':   case '7':
	coded_char = c - '0';
	c = input();
	if (!is_octal_digit(c)) {
	    unput(c);
	    return(coded_char);
	}
	coded_char = coded_char*8 + c-'0';
	c = input();
	if (!is_octal_digit(c)) {
	    unput(c);
	    return(coded_char);
	}
	return(coded_char*8 + c-'0');
      default:
	return(c);
    }
}

/*
 * eat_string - this routine eats characters allowing escape codes via '\\'
 *              until a '"' is eaten.  If no '"' is seen before a '\n' or
 *              the <EOF>, a parse_error is set & 0 is returned.  Otherwise,
 *              the string represented by what has been eaten is returned.
 *              I.e., 'hello \n there"' would cause "hello \n there" to be
 *              returned.  (thats not a <cr> in the first case, a <cr> in the
 *              second)  The returned string is on the heap & must be freed
 *              eventually.  This routine should be passed the line # that the
 *              string we are eating started on.
 */

static char *eat_string(starting_line)
     int starting_line;
{
    int c;
    char buffer[500];
    char *ptr = buffer;

    for (;;) {
	/*
	 * Get the next input character, handling EOF:
	 */
	c = input();
	if (!c) {
	    unput(c);
	    report_parse_error("unterminated string found beginning",
			    starting_line);
	    return(0);
	}

	/*
	 * Deal with special characters ('\\', '"', and '\n'):
	 */
	if (c=='\\') {
	    c = eat_escape_code();
	    if (!c)
	      continue;
	} else if (c == '"') {
	    *ptr = 0;
	    return(string_Copy(buffer));
	} else if (c == '\n') {
	    unput(c);        /* fix line # reference to right line # */
	    report_parse_error("carriage return found in string", yylineno);
	    return(0);
	}

	/*
	 * Add the character c to the current string:
	 */
	*ptr = c;
	ptr++;

	/*
	 * If out of buffer space, do a recursive call then
	 * concatanate the result to the string read in so far to get the
	 * entire string and return that:
	 */
	if (ptr>buffer+sizeof(buffer)-20) {
	    string rest_of_string, result;

	    rest_of_string = eat_string(starting_line);
	    if (!rest_of_string)
	      return(0);
	    
	    *ptr = 0;
	    result = string_Concat(buffer, rest_of_string);
	    free(rest_of_string);
	    return(result);
	}
    }
}

/*
 * eat_show_line - internal routine for eat_show:
 *
 *        This routine reads in a physical line of text allowing escape
 *    codes via '\\'.  If the line ends with a newline, the newline is eaten.
 *    If the line ends with a EOF, the EOF is not eaten.  The string
 *    represented by what has been eaten is returned.  The returned string
 *    is on the heap & must be freed eventually.  If test_for_endshow is
 *    true and the line read in starts off with "endshow" exactly
 *    (i.e., no escape codes) followed by any non-identifier-char, then
 *    instead of doing the above, we just eat the "endshow" & return 0.
 */

static char *eat_show_line(test_for_endshow)
     int test_for_endshow;
{
    int c;
    int saw_escape_code = 0;
    int starting_line = yylineno;
    char buffer[200];      /* This must be large enough to hold "endshow" */
    char *ptr = buffer;

    while (yylineno == starting_line) {
	c = input();
	if (!c) {
	    unput(c);
	    *ptr = '\0';
	    return(string_Copy(buffer));
	} else if (c == '\\') {
	    saw_escape_code = 1;
	    c = eat_escape_code();
	    if (!c)
	      continue;
	}

	*ptr = c;
	ptr++;

	if ((ptr==buffer+strlen("endshow")) && test_for_endshow)
	  if (!strncmp(buffer, "endshow", strlen("endshow"))
	      && !saw_escape_code) {
	      c = input();
	      unput(c);
	      if (!is_identifier_char(c))
		return(0);
	  }

	if (ptr>buffer+sizeof(buffer)-2) {
	    string the_line;
	    string rest_of_line = eat_show_line(0);

	    *ptr = '\0';
	    the_line = string_Concat(buffer, rest_of_line);
	    free(rest_of_line);
	    return(the_line);
	}
    }

    *ptr = '\0';
    return(string_Copy(buffer));
}

/*
 * eat_til_endshow - this routine eats characters allowing escape codes via
 *                   '\\' up to a endshow\{nonalpha} found at the
 *                   start of a line not counting leading whitespace.
 *                   If <EOF> is seen before the terminator, a parse_error
 *                   is set & 0 returned.  Otherwise, the string represented
 *                   by what has been eaten (escape codes replaced by what
 *                   they stand for and leading spaces and tabs removed from
 *                   each physical line) is returned.  The returned string
 *                   is on the heap & must be freed eventually.  Note that
 *                   to embed endshow in a message, endsho\w can be used.
 *                   This routine should be passed the line # of the show
 *                   command it is being used to process for use in error
 *                   messages.
 */

static char *eat_til_endshow(start_line_no)
     int start_line_no;
{
    register int c;
    string text_so_far = string_Copy("");
    string next_line;

    for (;;) {
	/*
	 * Skip the spaces & tabs at the start of the current line:
	 */
	while ((c=input()), c==' ' || c=='\t') ;
	unput(c);

	/*
	 * Handle unterminated shows:
	 */
	if (!c) {
	    report_parse_error("unterminated show beginning", start_line_no);
	    free(text_so_far);
	    return(0);
	}

	/*
	 * Read in rest of the line (including the <cr> at end), allowing
	 * for escape codes and checking for "endshow{nonalpha}" at the
	 * start of the line.  (Note: \<newline> is considered the
	 * end of a line here!)
	 */
	next_line = eat_show_line(1);

	if (!next_line)  /* i.e., is this the endshow line? */
	  return(text_so_far);

	text_so_far = string_Concat2(text_so_far, next_line);
	free(next_line);
    }
}

/*
 * handle_show - this routine is called after "show"\{nonalpha} is
 *               found to handle up to the endshow.  The token # is
 *               returned.
 */

static int handle_show()
{
    int c;
    int start_line_no = yylineno;

    /*
     * Eat up ' ' and '\t's after show.  If the next character is a newline,
     * eat it.  This is so we don't get an extra newline when we call
     * eat_til_endshow:
     */
    while (c=input(), c==' ' || c=='\t') ;
    if (c!='\n')
      unput(c);

    if (yylval.text = eat_til_endshow(start_line_no))
      return(SHOW);
    else
      return(ERROR);
}

/****************************************************************************/
/*                                                                          */
/*                         The main lexer itself:                           */
/*                                                                          */
/****************************************************************************/

/*
 * yylex - performs as per. the yacc manual's requirements
 */

int yylex()
{
    register int c, last_char;
    register char *ptr;
    int start_line_no;
    int_dictionary_binding *binding;
    char varname[MAX_IDENTIFIER_LENGTH+1];

    for (;;) {
	switch (c = input()) {

	    /*
	     * Skip whitespace:
	     */
	  case ' ':   case '\t':   case '\n':
	    continue;

	    /*
	     * '#' comments out everything up to the and including
	     * the next <cr>:
	     */
	  case '#':
	    while ( (c=input()) && (c!='\n') ) ;
	    if (!c)
	      unput(c);
	    continue;

	    /*
	     * Handle c-style comments.  Note that "/[^*]" is not the start
	     * of any valid token.
	     */
	  case '/':
	    start_line_no = yylineno;

	    /* verify that next character is a '*': */
	    if ((c=input()) != '*')
	      return(ERROR);

	    /* Scan until "*\/" or <EOF>: */
	    for (last_char=0; ; last_char=c) {
		c = input();
		if (c == '/' && (last_char=='*'))
		  break;
		if (!c) {
		    unput(c);
		    report_parse_error("unterminated c style comment found beginning", start_line_no);
		    return(ERROR);
		}
	    }
	    continue;

	    /*
	     * The following characters lex as themselves:
	     *   '+', '|', '&', '(', ')', '.', ',' and <EOF>:
	     */
	  case   0:   case '+':   case '|':   case '&':   case '(':
	  case ')':   case '.':	  case ',':
	    return(c);

	    /*
	     * Handle "=[^~=]", "=~", and "==":
	     */
	  case '=':
	    switch (c = input()) {
	      case '~':
		return(REGEQ);
	      case '=':
		return(EQ);
	      default:
		unput(c);
		return('=');
	    }

	    /*
	     * Handle "![^~=]", "!~", and "!=":
	     */
	  case '!':
	    switch (c = input()) {
	      case '~':
		return(REGNEQ);
	      case '=':
		return(NEQ);
	      default:
		unput(c);
		return('!');
	    }

	    /*
	     * Handle identifiers and keywords:
	     *
	     * Note that the below set of characters is hard coded from
	     * is_identifier_char from parser.h.
	     */
	  case 'a':   case 'b':   case 'c':   case 'd':   case 'e':
	  case 'f':   case 'g':   case 'h':   case 'i':   case 'j':
	  case 'k':   case 'l':   case 'm':   case 'n':   case 'o':
	  case 'p':   case 'q':   case 'r':   case 's':   case 't':
	  case 'u':   case 'v':   case 'w':   case 'x':   case 'y':
	  case 'z':
	  case 'A':   case 'B':   case 'C':   case 'D':   case 'E':
	  case 'F':   case 'G':   case 'H':   case 'I':   case 'J':
	  case 'K':   case 'L':   case 'M':   case 'N':   case 'O':
	  case 'P':   case 'Q':   case 'R':   case 'S':   case 'T':
	  case 'U':   case 'V':   case 'W':   case 'X':   case 'Y':
	  case 'Z':
	  case '0':   case '1':   case '2':   case '3':   case '4':
	  case '5':   case '6':   case '7':   case '8':   case '9':
	  case '_':
	    /*
	     * Read in the first MAX_IDENTIFIER_LENGTH characters of the
	     * identifier into varname null terminated.  Eat
	     * the rest of the characters of the identifier:
	     */
	    for (ptr = varname;;) {
		if (ptr<varname+MAX_IDENTIFIER_LENGTH)
		  *(ptr++) = c;
		c = input();
		if (!is_identifier_char(c))
		  break;
	    }
	    unput(c);
	    *ptr = '\0';

	    /*
	     * Look up the identifier in the keyword dictionary.
	     * If its a match, return the keyword's #.  In the case
	     * of show, call handle_show to do more processing.
	     * If not a match, treat as a variable name.
	     */
	    binding = int_dictionary_Lookup(keyword_dict, varname);
	    if (!binding) {
		yylval.text = string_Copy(varname);
		return(VARNAME);
	    }
	    if (binding->value == SHOW)
	      return(handle_show());
	    else
	      return(binding->value);

	    /*
	     * Handle "${identifier}".  Note that $ followed by a
	     * non-identifier character is not the start of any valid token.
	     */
	  case '$':
	    c = input();
	    if (!is_identifier_char(c))
	      return(ERROR);
    
	    /*
	     * Read in the first MAX_IDENTIFIER_LENGTH characters of the
	     * identifier into varname null terminated.  Eat
	     * the rest of the characters of the identifier:
	     */
	    for (ptr = varname;;) {
		if (ptr<varname+MAX_IDENTIFIER_LENGTH)
		  *(ptr++) = c;
		c = input();
		if (!is_identifier_char(c))
		  break;
	    }
	    unput(c);
	    *ptr = '\0';

	    yylval.text = string_Copy(varname);
	    return(VARREF);

	    /*
	     * Handle constant strings:
	     */
	  case '"':
	    if (yylval.text = eat_string(yylineno))
	      return(STRING);
	    else
	      return(ERROR);

	    /*
	     * All other characters do not start valid tokens:
	     */
	  default:
	    return(ERROR);
	}
    }
}
