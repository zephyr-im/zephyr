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
static char rcsid_standard_ports_c[] = "$Id$";
#endif

#include <zephyr/mit-copyright.h>

/****************************************************************************/
/*                                                                          */
/*                        Code to setup standard ports:                     */
/*                                                                          */
/****************************************************************************/

#include <stdio.h>
#include "new_memory.h"
#include "port.h"
#include "variables.h"
#include "error.h"
#include <zephyr/zephyr.h>

extern string tty_filter();
extern char *X_driver();

extern int X_driver_init();
extern int tty_filter_init();

extern void usage();

/*
 *
 */

char *plain_driver(input)
     string input;
{
    string processed_input = tty_filter(input, 0);

    fputs(processed_input, stdout);
    fflush(stdout);
    free(processed_input);
    return(NULL);
}

/*
 *
 */

char *tty_driver(input)
     string input;
{
    string processed_input = tty_filter(input, 1);

    fputs(processed_input, stdout);
    fflush(stdout);
    free(processed_input);
    return(NULL);
}

/*
 *
 */

string noop_filter(input)
     string input;
{
    return(input);
}

/*
 *
 */

string plain_filter(input)
     string input;
{
    return(tty_filter(input, 0));
}

/*
 *
 */

string fancy_filter(input)
     string input;
{
    return(tty_filter(input, 1));
}

/*
 *
 */

static struct standard_port_info {
    char *port_name;
/*
 * 0 = ok to use as the default output port
 * 1 = not ok to use as the default output port
 * 2 = disabled
 */
#define	DEFAULT_OK	0
#define	DEFAULT_NOTOK	1
#define	DISABLED	2

    int port_setup_status;
    int (*port_init)();
#define  INPUT_DESC  0
#define  OUTPUT_DESC 1
#define  FILTER      2
#define  OUTPUT_PROC 3
    int type;
    char *(*function)();
    int setup_arg;
} standard_port_info_table[] = {
{ "X",            DEFAULT_OK, X_driver_init,      OUTPUT_PROC, X_driver, 0},
{ "tty",          DEFAULT_NOTOK, tty_filter_init, OUTPUT_PROC, tty_driver,  0},
{ "plain",        DEFAULT_NOTOK, tty_filter_init, OUTPUT_PROC, plain_driver, 0},
{ "stdout",       DEFAULT_NOTOK, NULL,            OUTPUT_DESC, NULL, 1},
{ "stderr",       DEFAULT_NOTOK, NULL,            OUTPUT_DESC, NULL, 2},

{ "stdin",        DEFAULT_NOTOK, NULL,            INPUT_DESC,  NULL, 0},
{ "loopback",     DEFAULT_NOTOK, NULL,            FILTER, noop_filter, 0},
{ "plain_filter", DEFAULT_NOTOK, tty_filter_init, FILTER, plain_filter, 0},
{ "tty_filter",   DEFAULT_NOTOK, tty_filter_init, FILTER, fancy_filter, 0},

{ NULL,           DISABLED, NULL,            FILTER,      NULL,         0} };

/*
 * <<<>>>
 */

static struct standard_port_info *get_standard_port_info(port_name)
     string port_name;
{
    struct standard_port_info *p;

    for (p=standard_port_info_table; p->port_name; p++)
      if (string_Eq(p->port_name, port_name) && p->port_setup_status!=DISABLED)
        return(p);

    return(NULL);
}

/*
 *  Internal Routine:
 *
 *    int boolean_value_of(string text)
 *         Effects: If text represents yes/true/on, return 1.  If text
 *                  representes no/false/off, return 0.  Otherwise,
 *                  returns -1.
 */

static int boolean_value_of(text)
     string text;
{
    if (!text)
	return(-1);			/* not set */
    if (!strcasecmp("yes", text) || !strcasecmp("y", text) ||
        !strcasecmp("true", text) || !strcasecmp("t", text) ||
        !strcasecmp("on", text))
      return(1);
    else if (!strcasecmp("no", text) || !strcasecmp("n", text) ||
        !strcasecmp("false", text) || !strcasecmp("f", text) ||
        !strcasecmp("off", text))
      return(0);
    else
      return(-1);
}

/*
 *
 */

void init_standard_ports(pargc, argv)
     int *pargc;
     char **argv;
{
    struct standard_port_info *p;
    string first_working_port = "";
    string default_port = "";
    char **new, **current;
    int fallback;

    /*
     * Process argument list handling "-disable <port>" and
     * "-default <output port>" arguments, as well as "-ttymode"
     */
    for (new=current=argv+1; *current; current++) {
        if (string_Eq((string) *current, "-disable")) {
            current++; *pargc -= 2;
            if (!*current)
              usage();
            if (p = get_standard_port_info((string) *current))
		p->port_setup_status = DISABLED;
        } else if (string_Eq((string) *current, "-default")) {
            current++; *pargc -= 2;
            if (!*current)
              usage();
            default_port = (string) *current;
            if (p = get_standard_port_info((string) *current))
		p->port_setup_status = DEFAULT_OK;
        } else if (string_Eq((string) *current, "-ttymode")) {
	    default_port = (string) "tty";
	    (*pargc)--;
            if (p = get_standard_port_info(default_port)) {
		p->port_setup_status = DEFAULT_OK;
		if (p = get_standard_port_info ((string) "X"))
		    p->port_setup_status = DISABLED;
	    }
	} else
          *(new++) = *current;
    }
    *new = *current;

    fallback = boolean_value_of(ZGetVariable("fallback"));
    /*
     * Initialize all non-disabled ports.  If a port reports an error,
     * disable that port.  Set default_port if not already set
     * by the -default argument to the first non-disabled port.
     */
    for (p = standard_port_info_table; p->port_name; p++) {
        if (p->port_setup_status == DISABLED)
          continue;

        if (p->port_init && (*(p->port_init))(p->port_name,
					      *first_working_port,
					      pargc, argv)) {
            p->port_setup_status = DISABLED;
            continue;
        }

	if (fallback == 1) {
	    /* we are doing fallback,  make DEFAULT_NOTOK ports OK */
	    p->port_setup_status = DEFAULT_OK;
	}
        if (!*first_working_port)
          first_working_port = p->port_name;
	switch (p->type) {
	  case INPUT_DESC:
	    create_port_from_files(p->port_name, fdopen(p->setup_arg, "r"),0);
	    break;

	  case OUTPUT_DESC:
	    create_port_from_files(p->port_name, 0, fdopen(p->setup_arg, "w"));
	    break;

	  case FILTER:
	    create_port_from_filter(p->port_name, p->function);
	    break;

	  case OUTPUT_PROC:
	    create_port_from_output_proc(p->port_name, p->function);
	    break;
	}
    }

    if (!default_port[0]) {
	/* no default port has been set */
	for (p = get_standard_port_info(first_working_port); p->port_name; p++)
	    if ((p->port_setup_status == DEFAULT_OK))
		break;
	if (p->port_name)
	    var_set_variable("output_driver", p->port_name);
	else { /* no suitable default has been found */
	    if (fallback == -1)		/* complain, since indeterminate */
		ERROR(
"\7\7\7There is no X display available, so zwgc cannot run.\n\
THIS MEANS THAT YOU WILL NOT RECEIVE ANY ZEPHYR MESSAGES.\n\
If you wish to receive Zephyr messages, you should start zwgc\n\
with the -ttymode option (type '/usr/etc/zwgc -ttymode').\n\
Read the zwgc(1) manual page for details on the fallback variable.\n\n");
	    exit(1);
	}
    } else
	var_set_variable("output_driver", default_port);

}
