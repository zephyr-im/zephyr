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
static char rcsid_standard_ports_c[] = "$Header$";
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

extern string tty_filter();
extern char *X_driver();

extern int X_driver_init();
extern int tty_filter_init();

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
    { "X",            0, X_driver_init,   OUTPUT_PROC, X_driver,     0},
    { "tty",          0, tty_filter_init, OUTPUT_PROC, tty_driver,   0},
    { "plain",        0, tty_filter_init, OUTPUT_PROC, plain_driver, 0},
    { "stdout",       0, NULL,            OUTPUT_DESC, NULL,         1},
    { "stderr",       0, NULL,            OUTPUT_DESC, NULL,         2},

    { "stdin",        1, NULL,            INPUT_DESC,  NULL,         0},
    { "loopback",     1, NULL,            FILTER,      noop_filter,  0},
    { "plain_filter", 1, tty_filter_init, FILTER,      plain_filter, 0},
    { "tty_filter",   1, tty_filter_init, FILTER,      fancy_filter, 0},

    { NULL,           2, NULL,            FILTER,      NULL,         0} };

#ifdef notdef
/*
 * <<<>>>
 */

static struct standard_port_info *get_standard_port_info(port_name)
     string port_name;
{
    struct standard_port_info *p;

    for (p=standard_port_info_table; p->port_name; p++)
      if (string_Eq(p->port_name, port_name) && p->port_setup_status!=2)
        return(p);

    return(NULL);
}
#endif

/*
 *
 */

void init_standard_ports(pargc, argv)
     int *pargc;
     char **argv;
{
    struct standard_port_info *p;
#ifdef notdef
    string first_working_port = "";
    string default_port = "";

    /*
     * Process argument list handling "-disable <port>" and
     * "-default <output port>" arguments:
     */
    for (new=current=argv+1; *current; current++) {
        if (string_Eq(*current, "-disable")) {
            current++; *pargc -= 2;
            if (!*current)
              usage();
            if (p = get_standard_port_info(*current))
              p->port_setup_status = 2;
        } else if (string_Eq(*current, "-default")) {
            current++; *pargc -= 2;
            if (!*current)
              usage();
            default_port = *current;
        } else
          *(new++) = *current;
    }
    *new = *current;

    /*
     * Initialize all non-disabled ports.  If a port reports an error,
     * disable that port.  Set default_port if not already set
     * by the -default argument to the first non-disabled port.
     */
    for (p = standard_port_info_table; p->port_name; p++) {
        if (p->port_setup_status==2)
          continue;

        if (p->port_init && p->port_init(pargc, argv)) {
            p->port_setup_status = 2;
            continue;
        }

        if (!*first_working_port)
          first_working_port = p->port_name;
    }

    if (!get_standard_port_info(default_port))
      default_port = first_working_port;

    var_set_variable("output_driver", default_port);
#endif

    var_set_variable("output_driver", "X");
    X_driver_init(pargc, argv);
    tty_filter_init();

    /*
     * <<<>>>
     */
    for (p=standard_port_info_table; p->port_name; p++) {
	if (p->port_setup_status == 2)
	  continue;
	
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
}
