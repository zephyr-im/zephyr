/* This file is part of the Project Athena Zephyr Notification System.
 * It is one of the source files comprising zwgc, the Zephyr WindowGram
 * client.
 *
 *      Created by:     Marc Horowitz <marc@athena.mit.edu>
 *
 *      $Id$
 *
 *      Copyright (c) 1989 by the Massachusetts Institute of Technology.
 *      For copying and distribution information, see the file
 *      "mit-copyright.h".
 */


#include <zephyr/mit-copyright.h>

#ifndef zephyr_MODULE
#define zephyr_MODULE

#include <zephyr/zephyr.h>

extern void zephyr_init(void(*)(ZNotice_t *));
extern void finalize_zephyr(void);
extern void write_wgfile(void);

#endif
