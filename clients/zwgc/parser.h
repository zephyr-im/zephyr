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


#include <zephyr/mit-copyright.h>

#ifndef parser_MODULE
#define parser_MODULE

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

extern void report_parse_error();

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

extern struct _Node *parse_file();

#endif
