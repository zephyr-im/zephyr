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
static char rcsid_subscriptions_h[] = "$Header$";
#endif

#include <zephyr/mit-copyright.h>

#ifndef subscriptions_MODULE
#define subscriptions_MODULE

extern int zwgc_active;

extern int puntable_address_p(/* string class, instance, recipient */);
extern void punt();
extern void unpunt();
extern void zwgc_shutdown();
extern void zwgc_startup();

#endif
