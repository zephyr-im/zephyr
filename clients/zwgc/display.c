/****************************************************************************/
/*                                                                          */
/*             "Bus" module for plug in output driver modules:              */
/*                                                                          */
/****************************************************************************/

#include <stdio.h>
#include "new_memory.h"
#include "new_string.h"
#include "variables.h"
#include "display.h"

/*
 * driver_table - <<<>>>
 */

extern void X_driver();
extern void tty_driver();
extern void plain_driver();
extern void raw_driver();

extern int X_driver_init();
extern int tty_driver_init();

static struct driver_info {
    string driver_name;
    void   (*driver)();
    int    (*driver_init)();
    void   (*driver_reset)();
} driver_table[] = {
    {"X",     X_driver,     X_driver_init,   X_driver_reset},
    {"tty",   tty_driver,   tty_driver_init, NULL},
    {"plain", plain_driver, NULL,            NULL},
    {"raw",   raw_driver,   NULL,            NULL},
    {NULL,    NULL,         NULL,            NULL}
};

/*
 * <<<>>>
 */

struct driver_info *get_driver_info(driver_name)
     string driver_name;
{
    struct driver_info *d;

    for (d=driver_table; d->driver_name; d++)
      if (string_Eq(d->driver_name, driver_name) && d->driver)
	return(d);

    return(NULL);
}

/*
 *    void init_display(int *pargc; char **argv)
 *        Effects: <<<>>>
 */

void display_init(pargc, argv)
     int *pargc;
     char **argv;
{
    char **new, **current;
    struct driver_info *d;
    string first_working_driver = "";
    string default_driver = "";

    /*
     * Process argument list handling "-disable <driver>" and
     * "-default <driver>" arguments:
     */
    for (new=current=argv+1; *current; current++) {
	if (string_Eq(*current, "-disable")) {
	    current++; *pargc -= 2;
	    if (!*current)
	      usage();
	    if (d = get_driver_info(*current))
	      d->driver = NULL;
	} else if (string_Eq(*current, "-default")) {
	    current++; *pargc -= 2;
	    if (!*current)
	      usage();
	    default_driver = *current;
	} else
	  *(new++) = *current;
    }
    *new = *current;

    /*
     * Initialize all non-disabled drivers.  If a driver reports an error,
     * disable that driver.  Set default_driver if not already set
     * by the -default argument to the first non-disabled driver.
     */    
    for (d = driver_table; d->driver_name; d++) {
	if (!d->driver)
	  continue;
	
	if (d->driver_init && d->driver_init(pargc, argv)) {
	    d->driver = NULL;
	    continue;
	}

	if (!*first_working_driver)
	  first_working_driver = d->driver_name;
    }

    if (!get_driver_info(default_driver))
      default_driver = first_working_driver;

    var_set_variable("output_driver", default_driver);
}

void display_reset()
{
   for (d = driver_table; d->driver_name; d++)
      if (d->driver) d->driver_reset();
}
