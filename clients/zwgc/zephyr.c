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

#include <sysdep.h>

#if (!defined(lint) && !defined(SABER))
static const char rcsid_zephyr_c[] = "$Id$";
#endif

#include <zephyr/mit-copyright.h>

/****************************************************************************/
/*                                                                          */
/*               Module containing code dealing with zephyr:                */
/*                                                                          */
/****************************************************************************/

#include <zephyr/zephyr.h>
#include <sys/socket.h>
#include "new_string.h"
#include "zephyr.h"
#include "error.h"
#include "mux.h"
#include "subscriptions.h"
#include "variables.h"
#include "pointer.h"
#ifndef X_DISPLAY_MISSING
#include "X_driver.h"
#endif

#ifdef DEBUG
extern int zwgc_debug;
#endif /* DEBUG */

/*
 *  Internal Routine:
 *
 *    string get_zwgc_port_number_filename()
 *        Effects: Returns the filename that the zwgc port # is/should be
 *                 stored in, based on the user's uid & the environment
 *                 variable WGFILE.  The returned string points into a
 *                 static buffer that may change on further calls to this
 *                 routine or getenv.  The returned string should not be
 *                 modified in any way.
 */

static string get_zwgc_port_number_filename()
{
    static char buffer[40];
    char *temp;
    char *getenv();

    if (temp = getenv("WGFILE"))
      return(temp);
    else {
	sprintf(buffer, "/tmp/wg.%d", getuid());
	return(buffer);
    }
}

/*
 *
 */

static void handle_zephyr_input(notice_handler)
     void (*notice_handler)();
{
    ZNotice_t notice;
    struct sockaddr_in from;
    int complete_packets_ready;

    for (;;) {
	errno = 0;
	if ( (complete_packets_ready=ZPending()) < 0 )
	  FATAL_TRAP( errno, "while calling ZPending()" );
    
	if (complete_packets_ready==0)
	  return;

	TRAP( ZReceiveNotice(&notice, &from), "while getting zephyr notice" );
	if (!error_code) {
	    notice.z_auth = ZCheckAuthentication(&notice, &from);
	    notice_handler(&notice);
	    ZFreeNotice(&notice);
	}
    }
}

static int zephyr_inited = 0;
    
/*
 *
 */

void zephyr_init(notice_handler)
     void (*notice_handler)();
{
    unsigned short port = 0;           /* Use any old port */
    char *temp;
    char *exposure;
    char *tty = NULL;
    FILE *port_file;

    /*
     * Initialize zephyr.  If error, print error message & exit.
     */
    FATAL_TRAP( ZInitialize(), "while initializing Zephyr" );
    FATAL_TRAP( ZOpenPort(&port), "while opening Zephyr port" );

    /*
     * Save away our port number in a special place so that zctl and
     * other clients can send us control messages: <<<>>>
     */
    temp = get_zwgc_port_number_filename();
    errno = 0;
    port_file = fopen(temp, "r");
    if (port_file) {
	fprintf(stderr, "zwgc: windowgram file already exists.  If you are\n");
	fprintf(stderr, "zwgc: not already running zwgc, delete %s\n", temp);
	fprintf(stderr, "zwgc: and try again.\n");
	exit(1);
    }
    port_file = fopen(temp, "w");
    if (port_file) {
	fprintf(port_file, "%d\n", port);
	fclose(port_file);
    } else {
	fprintf(stderr, "zwgc: error while opening %s for writing: ", temp);
	perror("");
    }

    /* Set hostname and tty for locations.  If we support X, use the
     * display string for the tty name. */
#ifndef X_DISPLAY_MISSING
    if (dpy)
	tty = DisplayString(dpy);
#endif
    error_code = ZInitLocationInfo(NULL, tty);
    TRAP( error_code, "while initializing location information" );

    /*
     * Retrieve the user's desired exposure level (from the zephyr variable
     * "exposure"), convert it to the proper internal form then 
     * set the user's location using it.  If the exposure level is
     * not one of the allowed ones, print an error and treat it as
     * EXPOSE_NONE.
     */

    error_code = set_exposure("*", ZGetVariable("exposure"));
    if (error_code)
      TRAP( error_code, "while setting location" );

    zwgc_startup();

    /*
     * Set $realm to our realm and $user to our zephyr username:
     */
    var_set_variable("realm", ZGetDefaultRealm());
    var_set_variable("user", ZGetSender());

    /*
     * <<<>>>
     */
    mux_add_input_source(ZGetFD(), (void (*)())handle_zephyr_input,
			 (pointer)notice_handler);
    zephyr_inited = 1;
    return;
}

/*
 *
 */

void finalize_zephyr() /* <<<>>> */
{
    string temp;

    if (zephyr_inited) {
	/*
	 * Remove the file containing our port # since it is no longer needed:
	 */
	errno = 0;
	temp = get_zwgc_port_number_filename();
	unlink(temp);
	if (errno) {
	    fprintf(stderr, "zwgc: error while trying to delete %s: ", temp);
	    perror("");
	}

	/*
	 * Cancel our subscriptions, unset our location, and close our zephyr
	 * connection:
	 */
#ifdef DEBUG
	if (zwgc_debug) {
	    TRAP( ZCancelSubscriptions(NULL, 0),
		  "while canceling subscriptions" );
	    TRAP( ZUnsetLocation(NULL), "while unsetting location" );
	} else {
#endif /* DEBUG */
	    (void) ZCancelSubscriptions(NULL, 0);
	    (void) ZUnsetLocation(NULL);
#ifdef DEBUG
	}
#endif /* DEBUG */
	ZClosePort();
    }
    return;
}
