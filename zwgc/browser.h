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
static char rcsid_browser_h[] = "$Header$";
#endif

#include <zephyr/mit-copyright.h>

#define BROWSER_NEW_REQ            1
#define BROWSER_NEW_REQ_RESP       2
#define BROWSER_ZPACKET            3
#define BROWSER_ZPACKET_RESP       4
#define BROWSER_TEXT               5
#define BROWSER_WINDOW_ID          6
#define BROWSER_VAR_REQ            7
#define BROWSER_VAR_REQ_RESP       8


#define BROWSER_TYPE_OVERRIDE      11
#define BROWSER_TYPE_DRIVER        12
#define BROWSER_TYPE_WM            13
#define BROWSER_TYPE_SIMPLE        14

#define BROWSER_ACK                21
#define BROWSER_NAK                22

#define BROWSER_KEEP               31
#define BROWSER_LOSE               32

extern int ZBOpenConnection();
extern void ZBCloseConnection( /* int fd */ );
extern char *var_get_variable( /* char *varname */ );
