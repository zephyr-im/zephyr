#ifndef x_driver_MODULE
#define x_driver_MODULE

#include <X11/Xlib.h>

extern Display *dpy;

extern char *get_string_resource();
extern int get_bool_resource();

#endif
