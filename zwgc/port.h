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
static char rcsid_port_h[] = "$Header$";
#endif

#include <zephyr/mit-copyright.h>

#ifndef port_TYPE
#define port_TYPE

#include <stdio.h>
#include "new_string.h"
#include "string_stack.h"

union port__data {
    struct {
	FILE *input_connector;
	FILE *output_connector;
    } file;
    struct {
	string_stack waiting_packets;
	string (*filter)();
    } filter;
    struct {
	char *(*output)();
    } output;
};

typedef struct {                /* PRIVATE */
    char *(*get)();
    char *(*put)();
    char *(*close_input)();
    char *(*close_output)();
#define  INPUT_CLOSED   0x1
#define  OUTPUT_CLOSED  0x2
#define  PORT_CLOSED    0x3
    int status;
    union port__data data;
} port;

/*
 *    void init_ports()
 *        Modifies: all ports
 *        Effects: Closes all existing ports.  Must be called before
 *                 any other port call is made.
 */

extern void init_ports();

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

extern string read_from_port();

/*
 *    void write_on_port(string name, char *text, int length)
 *        Requires: init_ports has been called, length>=0
 *        Modifies: the port named name if any, $error
 *        Effects: If a port by name name does not exist, sets $error to
 *                 "No such port" & returns.  Otherwise, attempts to
 *                 write text[0..length-1] on that port.  If an error
 *                 occurs, $error is set to the error message.
 */

extern void write_on_port();

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

extern void close_port_input();

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

extern void close_port_output();


extern void create_subprocess_port();
extern void create_file_append_port();
extern void create_file_input_port();
extern void create_file_output_port();
extern void create_port_from_filter();
extern void create_port_from_output_proc();

extern void init_standard_ports();
extern void create_port_from_files();

#endif
