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
static char rcsid_port_c[] = "$Id$";
#endif

#include <zephyr/mit-copyright.h>

/****************************************************************************/
/*                                                                          */
/*                    The Implementation of the port type:                  */
/*                                                                          */
/****************************************************************************/

#include <stdio.h>
#include <fcntl.h>
#include "new_string.h"
#include "port_dictionary.h"
#include "port.h"
#include "notice.h"
#include "variables.h"

/*
 * <<<>>>
 */

#if defined(SUNOS) || defined(vax)
extern int errno, sys_nerr;
extern char *sys_errlist[];

string perror_to_string(errno)
     int errno;
{
    if (errno>=0 && errno<sys_nerr)
      return(sys_errlist[errno]);

    /* <<<>>> */
    return("illegal error number returned in errno!");
}
#else
#include <errno.h>

string perror_to_string(errno)
     int errno;
{
     return(strerror(errno));
}
#endif

/****************************************************************************/
/*                                                                          */
/*                        Port methods (internal):                          */
/*                                                                          */
/****************************************************************************/

static string port_get(p)
     port *p;
{
    char *(*get_proc)();
    char *error = NULL;
    char *result;

    if (p->status & INPUT_CLOSED) {
	var_set_variable("error",
		    "Attempt to read from a port whose input has been closed");
	return(string_Copy(""));
    }

    get_proc = p->get;
    if (!get_proc) {
	var_set_variable("error",
		 "Attempt to read from a port which does not support reading");
	return(string_Copy(""));
    }

    result = get_proc(p, &error);
    if (!result) {
	var_set_variable("error", error);
	return(string_Copy(""));
    } else
      return(result);
}

static void port_put(p, data, length)
     port *p;
     char *data;
     int length;
{
    char *(*put_proc)();
    char *error;

    if (p->status & OUTPUT_CLOSED) {
	var_set_variable("error",
		 "Attempt to write to a port whose output has been closed");
	return;
    }

    put_proc = p->put;
    if (!put_proc) {
	var_set_variable("error",
		 "Attempt to write to a port which does not support writing");
	return;
    }

    error = put_proc(p, data, length);
    if (error)
      var_set_variable("error", error);
}

static void port_close_input(p)
     port *p;
{
    char *(*close_input_proc)();
    char *error;

    if (p->status & INPUT_CLOSED)
      return;
    p->status |= INPUT_CLOSED;

    close_input_proc = p->close_input;
    if (!close_input_proc)
      return;

    if (error = close_input_proc(p))
      var_set_variable("error", error);
}

static void port_close_output(p)
     port *p;
{
    char *(*close_output_proc)();
    char *error;

    if (p->status & OUTPUT_CLOSED)
      return;
    p->status |= OUTPUT_CLOSED;

    close_output_proc = p->close_output;
    if (!close_output_proc)
      return;

    if (error = close_output_proc(p))
      var_set_variable("error", error);
}

/****************************************************************************/
/*                                                                          */
/*                 Code to implement a namespace of ports:                  */
/*                                                                          */
/****************************************************************************/

/*
 * port_dict - the dictionary mapping portnames to ports
 */

static port_dictionary port_dict = NULL;

/*
 *    void init_ports()
 *        Modifies: all ports
 *        Effects: Closes all existing ports.  Must be called before
 *                 any other port call is made.
 */

static void close_port_from_binding(b)
     port_dictionary_binding *b;
{
    port_close_input(&(b->value));
    port_close_output(&(b->value));
}

void init_ports()
{
    if (port_dict) {
	port_dictionary_Enumerate(port_dict, close_port_from_binding);
	port_dictionary_Destroy(port_dict);
    }

    port_dict = port_dictionary_Create(31);
}

/*
 * Internal Routine:
 *
 *    port *create_named_port(string name)
 *        Modifies: the port named name
 *        Requires: init_ports has been called
 *        Effects: If a port with name name already exists, it is first
 *                 closed (& destroyed).  A new unfilled in port is then
 *                 created and assigned the name name.  Its address is
 *                 then returned.  It is up to the caller to fill in its
 *                 various fields correctly.
 */

static port *create_named_port(name)
     string name;
{
    int already_exists;
    port_dictionary_binding *binding;

    binding = port_dictionary_Define(port_dict, name, &already_exists);
    if (already_exists) {
	port_close_input(&(binding->value));
	port_close_output(&(binding->value));
    }

    return(&(binding->value));
}

/*
 * Internal Routine:
 *
 *    port *get_named_port(string name)
 *        Requires: init_ports has been called
 *        Effects: If there is a port by name name, returns a pointer to
 *                 it.  Otherwise returns NULL.
 */

static port *get_named_port(name)
     string name;
{
    port_dictionary_binding *binding;

    binding = port_dictionary_Lookup(port_dict, name);
    if (!binding)
      return(NULL);

    return(&(binding->value));
}
    
/****************************************************************************/
/*                                                                          */
/*                    External interface to named ports:                    */
/*                                                                          */
/****************************************************************************/

/*
 *    string read_from_port(string name)
 *        Requires: init_ports has been called
 *        Modifies: the port named name if any, $error
 *        Effects: If a port by name name does not exist, sets $error to
 *                 "No such port" & returns "".  Otherwise, attempts to
 *                 read from that port.  If an error occurs, $error is
 *                 set to the error message and "" returned.  Otherwise
 *                 the read string is returned.  The returned string is
 *                 on the heap & must be eventually freed.
 */

string read_from_port(name)
     string name;
{
    port *p;

    if (!(p = get_named_port(name))) {
	var_set_variable("error", "No such port");
	return(string_Copy(""));
    }

    return(port_get(p));
}

/*
 *    void write_on_port(string name, char *text, int length)
 *        Requires: init_ports has been called, length>=0
 *        Modifies: the port named name if any, $error
 *        Effects: If a port by name name does not exist, sets $error to
 *                 "No such port" & returns.  Otherwise, attempts to
 *                 write text[0..length-1] on that port.  If an error
 *                 occurs, $error is set to the error message.
 */

void write_on_port(name, text, length)
     string name;
     char *text;
     int length;
{
    port *p;

    if (!(p = get_named_port(name))) {
	var_set_variable("error", "No such port");
	return;
    }

    port_put(p, text, length);
}

/*
 *    void close_port_input(string name)
 *        Requires: init_ports has been called
 *        Modifies: the port named name if any, $error
 *        Effects: If a port by name name does not exist, sets $error to
 *                 "No such port" & returns.  Otherwise, closes the
 *                 input part of the port by name name.  When both a
 *                 port's input & output parts have been closed, the
 *                 port is deleted to save space.  If an error
 *                 occurs, $error is set to the error message.
 */

void close_port_input(name)
     string name;
{
    port_dictionary_binding *binding;

    binding = port_dictionary_Lookup(port_dict, name);
    if (!binding)
      return;

    port_close_input(&(binding->value));
    if (binding->value.status == PORT_CLOSED)
      port_dictionary_Delete(port_dict, binding);
}

/*
 *    void close_port_output(string name)
 *        Requires: init_ports has been called
 *        Modifies: the port named name if any, $error
 *        Effects: If a port by name name does not exist, sets $error to
 *                 "No such port" & returns.  Otherwise, closes the
 *                 output part of the port by name name.  When both a
 *                 port's input & output parts have been closed, the
 *                 port is deleted to save space.  If an error
 *                 occurs, $error is set to the error message.
 */

void close_port_output(name)
     string name;
{
    port_dictionary_binding *binding;

    binding = port_dictionary_Lookup(port_dict, name);
    if (!binding)
      return;

    port_close_output(&(binding->value));
    if (binding->value.status == PORT_CLOSED)
      port_dictionary_Delete(port_dict, binding);
}

/****************************************************************************/
/*                                                                          */
/*               Code to implement a port given some FILE *'s:              */
/*                                                                          */
/****************************************************************************/

static string get_file(p, error_p)
     port *p;
     char **error_p;
{
    char buffer[10000]; /* <<<>>> */

    if (!p->data.file.input_connector) {
	*error_p = "Attempt to read past end of file";
	return(NULL);
    }

    buffer[0] = 0;
    errno = 0;
    if (!fgets(buffer, 9999, p->data.file.input_connector)) {
	if (errno)
	  *error_p = perror_to_string(errno);
	else
	  *error_p = "Attempt to read past end of file";

	return(NULL);
    }

    buffer[9999] = 0;
    return(string_Copy(buffer));
}

static char *put_file(p, text, length)
     port *p;
     string text;
     int length;
{
    if (!p->data.file.output_connector)
      return(NULL);

    errno = 0;
    fwrite(text, 1, length, p->data.file.output_connector);
    fflush(p->data.file.output_connector);

    if (errno)
      return(perror_to_string(errno));

    return(NULL);
}

static char *close_file_input(p)
     port *p;
{
    errno = 0;
    if (p->data.file.input_connector) {
	fclose(p->data.file.input_connector);
	p->data.file.input_connector = 0;
    }

    if (errno)
      return(perror_to_string(errno));

    return(NULL);
}

static char *close_file_output(p)
     port *p;
{
    errno = 0;
    if (p->data.file.output_connector) {
	fclose(p->data.file.output_connector);
	p->data.file.output_connector = 0;
    }

    if (errno)
      return(perror_to_string(errno));

    return(NULL);
}

void create_port_from_files(name, input, output)
     string name;
     FILE *input;
     FILE *output;
{
    port *p = create_named_port(name);

#if !defined(__HIGHC__)
    p->get = input ? get_file : NULL;
    p->put = output ? put_file : NULL;
#else
    /* RT compiler (hc2.1y) bug workaround */
    if (input)
        p->get = get_file;
    else
        p->get = NULL;
    if (output)
        p->put = put_file;
    else
        p->put = NULL;
#endif
    p->close_input = close_file_input;
    p->close_output = close_file_output;
    p->status = 0;
    p->data.file.input_connector = input;
    p->data.file.output_connector = output;
}

/****************************************************************************/
/*                                                                          */
/*            Code for creating various types of FILE * ports:              */
/*                                                                          */
/****************************************************************************/

void create_subprocess_port(name, argv)
     string name;
     char **argv;
{
    int pid;
    int to_child_descriptors[2];
    int to_parent_descriptors[2];
    FILE *in = 0;
    FILE *out = 0;

    /* <<<>>> (file leak) */
    if (pipe(to_child_descriptors)!=0 || pipe(to_parent_descriptors)!=0)
      return;

    pid = fork();
    if (pid == -1) {
	fprintf(stderr, "zwgc: error while attempting to fork: ");
	perror("");
	return; /* <<<>>> */
    } else if (pid == 0) { /* in child */
	close(0);
	close(1);
	dup2(to_child_descriptors[0], 0);
	dup2(to_parent_descriptors[1], 1);
	close(to_child_descriptors[1]);
	close(to_parent_descriptors[0]);

	execvp(argv[0], argv);
	fprintf(stderr,"zwgc: unable to exec %s: ", argv[0]);
	perror("");
	_exit(errno);
    }

    fcntl(to_parent_descriptors[0], F_SETFD, 1);
    fcntl(to_child_descriptors[1], F_SETFD, 1);
    in = fdopen(to_parent_descriptors[0],"r");
    out = fdopen(to_child_descriptors[1],"w");
    close(to_child_descriptors[0]);
    close(to_parent_descriptors[1]);

    create_port_from_files(name, in, out);
}

void create_file_append_port(name, filename)
     string name;
     string filename;
{
    FILE *out;
    int oumask;

    errno = 0;

    oumask = umask(077);		/* allow read/write for us only */
    out = fopen(filename, "a");
    (void) umask(oumask);
    if (out == NULL) {
	var_set_variable("error", perror_to_string(errno));
	return;
    }

    create_port_from_files(name, 0, out);
}

void create_file_input_port(name, filename)
     string name;
     string filename;
{
    FILE *in;

    errno = 0;
    in = fopen(filename, "r");
    if (in == NULL) {
	var_set_variable("error", perror_to_string(errno));
	return;
    }

    create_port_from_files(name, in, 0);
}

void create_file_output_port(name, filename)
     string name;
     string filename;
{
    FILE *out;
    int oumask;

    errno = 0;

    oumask = umask(077);		/* allow read/write for us only */
    out = fopen(filename, "w");
    (void) umask(oumask);
    if (out == NULL) {
	var_set_variable("error", perror_to_string(errno));
	return;
    }

    create_port_from_files(name, 0, out);
}

/****************************************************************************/
/*                                                                          */
/*             Code to implement a port given a filter function:            */
/*                                                                          */
/****************************************************************************/

static string get_filter(p, error_p)
     port *p;
     char **error_p;
{
    string result;

    if (string_stack_empty(p->data.filter.waiting_packets)) {
	*error_p = "Attempt to read from port when no data available";
	return(NULL);
    }

    result = string_stack_top(p->data.filter.waiting_packets);
    string_stack_pop(p->data.filter.waiting_packets);
    return(result);
}

static char *put_filter(p, text, length)
     port *p;
     string text;
     int length;
{
    string input;
    string output;

    if (p->status & INPUT_CLOSED)
      return(NULL);

    input = convert_nulls_to_newlines(text, length);
    output = (*(p->data.filter.filter))(input);
    free(input);
    string_stack_push(p->data.filter.waiting_packets, output);
    return(NULL);
}

static char *close_filter_input(p)
     port *p;
{
    while (!string_stack_empty(p->data.filter.waiting_packets))
      string_stack_pop(p->data.filter.waiting_packets);

    return(NULL);
}

/*ARGSUSED*/
static char *close_filter_output(p)
     port *p;
{
    return(NULL);
}

void create_port_from_filter(name, filter)
     string name;
     string (*filter)();
{
    port *p = create_named_port(name);

    p->get = get_filter;
    p->put = put_filter;
    p->close_input = close_filter_input;
    p->close_output = close_filter_output;
    p->status = 0;
    p->data.filter.waiting_packets = string_stack_create();
    p->data.filter.filter = filter;
}

/****************************************************************************/
/*                                                                          */
/*             Code to implement a port given an output function:           */
/*                                                                          */
/****************************************************************************/

static char *put_output(p, text, length)
     port *p;
     string text;
     int length;
{
    string input;
    char *error;

    input = convert_nulls_to_newlines(text, length);
    error = p->data.output.output(input);
    free(input);
    return(error);
}

/*ARGSUSED*/
static char *close_output(p)
     port *p;
{
    return(NULL);
}

void create_port_from_output_proc(name, output)
     string name;
     char *(*output)();
{
#ifdef SABER /* Yes, it's another ANSI incompatiblity */
    port *p;
#else
    port *p = create_named_port(name);
#endif

#ifdef SABER
    p = create_named_port(name);
#endif

    p->get = NULL;
    p->put = put_output;
    p->close_input = close_output;
    p->close_output = close_output;
    p->status = 0;
    p->data.output.output = output;
}
