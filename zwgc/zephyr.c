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
static char rcsid_zephyr_c[] = "$Id$";
#endif

#include <zephyr/mit-copyright.h>

/****************************************************************************/
/*                                                                          */
/*               Module containing code dealing with zephyr:                */
/*                                                                          */
/****************************************************************************/

#include <stdio.h>
#include <zephyr/zephyr.h>
#include <sys/socket.h>
#include "new_string.h"
#include "zephyr.h"
#include "error.h"
#include "mux.h"
#include "subscriptions.h"
#include "variables.h"
#include "pointer.h"

/*
 *  Internal Routine:
 *
 *    char *parse_exposure_level(string text)
 *        Effects: Compares text to each of the standard zephyr
 *                 exposure levels ignoring case.  If it matches,
 *                 returns the corresponding magic constant for
 *                 use with ZSetLocation.  (i.e., returns EXPOSE_OPSTAFF
 *                 for "opstaff", etc.)  If it does not match, returns
 *                 NULL.
 */

static char *parse_exposure_level(text)
     string text;
{
    if (!strcasecmp(text, EXPOSE_NONE))
      return (EXPOSE_NONE);
    else if (!strcasecmp(text, EXPOSE_OPSTAFF))
      return (EXPOSE_OPSTAFF);
    else if (!strcasecmp(text, EXPOSE_REALMVIS))
      return (EXPOSE_REALMVIS);
    else if (!strcasecmp(text, EXPOSE_REALMANN))
      return (EXPOSE_REALMANN);
    else if (!strcasecmp(text, EXPOSE_NETVIS))
      return (EXPOSE_NETVIS);
    else if (!strcasecmp(text, EXPOSE_NETANN))
      return (EXPOSE_NETANN);
    else
      return(NULL);
}

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
    
/*
 *
 */

void zephyr_init(notice_handler)
     void (*notice_handler)();
{
    unsigned short port = 0;           /* Use any old port */
    char *temp;
    char *exposure;
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
    port_file = fopen(temp, "w+");
    if (port_file) {
	fprintf(port_file, "%d\n", port);
	fclose(port_file);
    } else {
	fprintf(stderr, "zwgc: error while opening %s for writing: ", temp);
	perror("");
    }

    /*
     * Retrieve the user's desired exposure level (from the zephyr variable
     * "exposure"), convert it to the proper internal form then 
     * set the user's location using it.  If the exposure level is
     * not one of the allowed ones, print an error and treat it as
     * EXPOSE_NONE.
     */
    if (temp = ZGetVariable("exposure")) {
	if (!(exposure = parse_exposure_level(temp))) {
	    ERROR2("invalid exposure level %s, using exposure level none instead.\n", temp);
	    exposure = EXPOSE_NONE;
	}
    } else
      exposure = EXPOSE_NONE;
    error_code = ZSetLocation(exposure); /* <<<>>> */
    if (error_code != ZERR_LOGINFAIL)
      TRAP( error_code, "while setting location" );

    /*
     * If the exposure level isn't EXPOSE_NONE, turn on recieving notices.
     * (this involves reading in the subscription file, etc.)
     */
    if (string_Neq(exposure, EXPOSE_NONE))
      zwgc_startup();

    /*
     * Set $realm to our realm and $user to our zephyr username:
     */
    var_set_variable("realm", ZGetRealm());
    var_set_variable("user", ZGetSender());

    /*
     * <<<>>>
     */
    mux_add_input_source(ZGetFD(), (void (*)())handle_zephyr_input,
			 (pointer)notice_handler);
}

/*
 *
 */

void finalize_zephyr() /* <<<>>> */
{
    string temp;

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
    TRAP( ZCancelSubscriptions(0), "while canceling subscriptions" );
    TRAP( ZUnsetLocation(), "while unsetting location" );
    ZClosePort();
}
