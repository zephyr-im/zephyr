#include <stdio.h>
#include <X11/Intrinsic.h>
#include <X11/StringDefs.h>

#include <X11/Xaw/Toggle.h>

#include "xzwrite.h"
#include "GetString.h"

extern Widget getString, closeOnSend, pings, verbose, authentic, yankDest,
     addGlobals, classInst;
extern Defaults defs;

#define toggle(v)	(v = !v)
void menu_toggle(w)
   Widget w;
{
     if (w == closeOnSend)
	  toggle(defs.close_on_send);
     else if (w == pings)
	  toggle(defs.ping);
     else if (w == verbose)
	  toggle(defs.verbose);
     else if (w == authentic)
	  toggle(defs.auth);
     else if (w == yankDest)
	  toggle(defs.yank_dest);
     else if (w == addGlobals)
	  toggle(defs.add_globals);
     else if (w == classInst)
	  toggle(defs.class_inst);
     else
	  Warning("Unknown toggle widget, ignoring.", NULL);
}
#undef toggle

#define set(w, i) XtVaSetValues(w, XtNstate, i ? True : False, NULL)
void menu_match_defs()
{
     set(closeOnSend, defs.close_on_send);
     set(pings, defs.ping);
     set(verbose, defs.verbose);
     set(authentic, defs.auth);
     set(yankDest, defs.yank_dest);
     set(addGlobals, defs.add_globals);
     set(classInst, defs.class_inst);
}
#undef set

void menu_signature()
{
     char buf[BUFSIZ];
     int ret;

     ret = GetString(getString, "Enter new signature:", defs.signature,
		     0, buf, BUFSIZ);

     if (ret != GETSTRING_ACCEPT)
	  return;
     
     /* XXX Is this safe? */
     free(defs.signature);
     defs.signature = (char *) Malloc(strlen(buf) + 1,
				      "while setting signature", NULL);
     strcpy(defs.signature, buf);
}
