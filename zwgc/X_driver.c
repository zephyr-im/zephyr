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
static char rcsid_X_driver_c[] = "$Id$";
#endif

#include <zephyr/mit-copyright.h>

/****************************************************************************/
/*                                                                          */
/*                             The X driver:                                */
/*                                                                          */
/****************************************************************************/

#include <stdio.h>
#include "X_driver.h"
#include <X11/Xresource.h>
#include "new_memory.h"
#include "formatter.h"
#include "mux.h"
#include "variables.h"
#include "error.h"
#include "X_gram.h"
#include "xselect.h"
#include "ulong_dictionary.h"

char *app_instance;

/*
 * dpy - the display we are outputting to
 */

Display *dpy = NULL;

/****************************************************************************/
/*                                                                          */
/*                  Code to deal with getting X resources:                  */
/*                                                                          */
/****************************************************************************/

/*
 *
 */

#ifndef  APPDEFDATABASE
#define  APPDEFDATABASE "/usr/athena/lib/zephyr/zwgc_resources"
#endif

/*
 *
 */

#ifndef  APPNAME
#define  APPNAME        "zwgc"
#endif

/*
 *
 */

#ifndef  APPCLASS
#define  APPCLASS        "Zwgc"
#endif

/*
 * x_resources - our X resources from application resources, command line,
 *               and user's X resources.
 */

static XrmDatabase x_resources = NULL;

/*
 *  Internal Routine:
 *
 *    int convert_string_to_bool(string text)
 *         Effects: If text represents yes/true/on, return 1.  If text
 *                  representes no/false/off, return 0.  Otherwise,
 *                  returns -1.
 */

static int convert_string_to_bool(text)
     string text;
{
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

char *get_string_resource(name, class)
     string name;
     string class;
{
    string full_name, full_class;
    int status;
    char *type;
    XrmValue value;

    full_name = string_Concat(APPNAME, ".");
    full_name = string_Concat2(full_name, name);
    full_class = string_Concat(APPCLASS, ".");
    full_class = string_Concat2(full_class, class);

    status = XrmGetResource(x_resources, full_name, full_class, &type, &value);
    free(full_name);
    free(full_class);

    if (status != True)
      return(NULL);

    if (string_Neq(type, "String"))
      return(NULL);

    return(value.addr);
}

/*
 *
 */

int get_bool_resource(name, class, default_value)
     string name;
     string class;
     int default_value;
{
    int result;
    char *temp;

    if (!(temp = get_string_resource(name, class)))
      return(default_value);

    result = convert_string_to_bool(temp);
    if (result == -1)
      result = default_value;

    return(result);
}

static ulong_dictionary color_dict = NULL;

/* Requires: name points to color name or hex string.  name must be free'd
 *     eventually by the caller.
 * Effects: returns unsigned long pixel value, or default if the
 *     color is not known by the server.  If name is NULL, returns
 *     default;
 *
 * comment: caches return values from X server round trips.  If name does
 *     not resolve, this fact is NOT cached, and will result in a round
 *     trip each time.
 */

unsigned long x_string_to_color(name,def)
     char *name;
     unsigned long def;
{
   ulong_dictionary_binding *binding;
   int exists;
   XColor xc;

   if (name == NULL)
     return(def);

   binding = ulong_dictionary_Define(color_dict,name,&exists);

   if (exists) {
      return((unsigned long) binding->value);
   } else {
      if (XParseColor(dpy,DefaultColormapOfScreen(DefaultScreenOfDisplay(dpy)),
		      name,&xc)) {
	 if (XAllocColor(dpy,
			 DefaultColormapOfScreen(DefaultScreenOfDisplay(dpy)),
			 &xc)) {
	    binding->value = (ulong) xc.pixel;
	    return(xc.pixel);
	 } else {
	    ERROR2("Error in XAllocColor on \"%s\": using default color\n",
		   name);
	 }
      } else {
	 ERROR2("Error in XParseColor on \"%s\": using default color\n",
	       name);
      }      
      ulong_dictionary_Delete(color_dict,binding);
      return(def);
   }
   /*NOTREACHED*/
}

/*
 * Standard X Toolkit command line options:
 */

static XrmOptionDescRec cmd_options[] = {
    {"+rv",          "*reverseVideo", XrmoptionNoArg,  (caddr_t) "off"},
    {"+synchronous", "*synchronous",  XrmoptionNoArg,  (caddr_t) "off"},
    {"-background",  "*background",   XrmoptionSepArg, (caddr_t) NULL},
    {"-bd",          "*borderColor",  XrmoptionSepArg, (caddr_t) NULL},
    {"-bg",          "*background",   XrmoptionSepArg, (caddr_t) NULL},
    {"-bordercolor", "*borderColor",  XrmoptionSepArg, (caddr_t) NULL},
    {"-borderwidth", ".borderWidth",  XrmoptionSepArg, (caddr_t) NULL},
    {"-bw",          ".borderWidth",  XrmoptionSepArg, (caddr_t) NULL},
    {"-display",     ".display",      XrmoptionSepArg, (caddr_t) NULL},
    {"-fg",          "*foreground",   XrmoptionSepArg, (caddr_t) NULL},
    {"-fn",          "*font",         XrmoptionSepArg, (caddr_t) NULL},
    {"-font",        "*font",         XrmoptionSepArg, (caddr_t) NULL},
    {"-foreground",  "*foreground",   XrmoptionSepArg, (caddr_t) NULL},
    {"-geometry",    ".geometry",     XrmoptionSepArg, (caddr_t) NULL},
    {"-iconname",    ".iconName",     XrmoptionSepArg, (caddr_t) NULL},
    {"-name",        ".name",         XrmoptionSepArg, (caddr_t) NULL},
    {"-reverse",     "*reverseVideo", XrmoptionNoArg,  (caddr_t) "on"},
    {"-rv",          "*reverseVideo", XrmoptionNoArg,  (caddr_t) "on"},
    {"-transient",   "*transient",    XrmoptionNoArg,  (caddr_t) "on"},
    {"-synchronous", "*synchronous",  XrmoptionNoArg,  (caddr_t) "on"},
    {"-title",       ".title",        XrmoptionSepArg, (caddr_t) NULL},
    {"-xrm",         NULL,            XrmoptionResArg, (caddr_t) NULL} };

#define NUMBER_OF_OPTIONS ((sizeof (cmd_options))/ sizeof(cmd_options[0]))

/*
 *
 */

int open_display_and_load_resources(pargc, argv)
     int *pargc;
     char **argv;
{
    XrmDatabase temp_db1, temp_db2, temp_db3;
    char *filename, *res, *xdef;
    extern char *getenv();

    /* Initialize X resource manager: */
    XrmInitialize();

    /*
     * Parse X toolkit command line arguments (including -display)
     * into resources:
     */
    XrmParseCommand(&x_resources, cmd_options, NUMBER_OF_OPTIONS, APPNAME,
		    pargc, argv);

    /*
     * Try and open the display using the display specified if given.
     * If can't open the display, return an error code.
     */
    dpy = XOpenDisplay(get_string_resource("display", "display"));
    if (!dpy)
      return(1);

    /* Read in our application-specific resources: */
    temp_db1 = XrmGetFileDatabase(APPDEFDATABASE);

    /*
     * Get resources from the just opened display:
     */
    xdef = XResourceManagerString(dpy);
    if (xdef)
	temp_db2 = XrmGetStringDatabase(xdef);
    else
	temp_db2 = NULL;

    /*
     * Merge the 4 sets of resources together such that when searching
     * for resources, they are checking in the following order:
     * command arguments, XENVIRONMENT resources, server resources,
     * application resources
     */
    XrmMergeDatabases(temp_db2, &temp_db1);

#if XlibSpecificationRelease > 4
    /* X11 R5 per-screen resources */
    res = XScreenResourceString (DefaultScreenOfDisplay (dpy));
    if (res != NULL)
	XrmMergeDatabases(XrmGetStringDatabase(res), &temp_db1);
#endif

    /*
     * Get XENVIRONMENT resources, if they exist, and merge
     */
    if (filename = getenv("XENVIRONMENT"))
    {
	temp_db3 = XrmGetFileDatabase(filename);
	XrmMergeDatabases(temp_db3, &temp_db1);
    }
    XrmMergeDatabases(x_resources, &temp_db1);
    x_resources = temp_db1;

    return(0);
}

/*
 * X_driver_ioerror: called by Xlib in case of an X IO error.
 * Shouldn't return (according to man page).
 *
 * on IO error, we clean up and exit.
 *
 * XXX it would be better to set mux_end_loop_p, but we can't return to
 * get there (Xlib will exit if this routine returns).
 *
 */

int X_driver_ioerror(display)
Display *display;
{
    extern void finalize_zephyr();

    ERROR2("X IO error on display '%s'--exiting\n", DisplayString(display));
    finalize_zephyr();
    exit(1);
}
/****************************************************************************/
/*                                                                          */
/*                Code to deal with initializing the driver:                */
/*                                                                          */
/****************************************************************************/

extern void x_get_input();

/*ARGSUSED*/
int X_driver_init(drivername, notfirst, pargc, argv)
     char *drivername;
     char notfirst;
     int *pargc;
     char **argv;
{
    string temp;
    int sync;

    /*
     * Attempt to open display and read resources, including from the
     * command line.  If fail, exit with error code, disabling this
     * driver:
     */
    if (open_display_and_load_resources(pargc, argv)) {
	ERROR("Unable to open X display -- disabling X driver.\n");
	return(1);
    }

    XSetIOErrorHandler(X_driver_ioerror);

    /*
     * For now, set some useful variables using resources:
     */
    if (sync=get_bool_resource("synchronous", "Synchronous", 0))
      XSynchronize(dpy,sync);
    if (temp = get_string_resource("geometry", "Geometry"))
      var_set_variable("default_X_geometry", temp);

    temp=strrchr(argv[0],'/');

    app_instance=string_Copy(temp?temp+1:argv[0]);

    color_dict = ulong_dictionary_Create(37);

    xshowinit();
    x_gram_init(dpy);
    xicccmInitAtoms(dpy);
    
    mux_add_input_source(ConnectionNumber(dpy), x_get_input, dpy);

    return(0);
}

void X_driver_reset()
{
}

/****************************************************************************/
/*                                                                          */
/*                         The display routine itself:                      */
/*                                                                          */
/****************************************************************************/

char *X_driver(text)
     string text;
{
    string text_copy;
    desctype *desc;
    int numstr, numnl;
    
    text_copy = string_Copy(text);
    desc = disp_get_cmds(text_copy, &numstr, &numnl);
    
    xshow(dpy, desc, numstr, numnl);
    
    free(text_copy);
    free_desc(desc);
    return(NULL);
}
