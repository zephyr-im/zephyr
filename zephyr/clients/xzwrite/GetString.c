#include <X11/Intrinsic.h>
#include <X11/StringDefs.h>
#include <X11/Shell.h>
#include <X11/Xaw/Form.h>
#include <X11/Xaw/Label.h>
#include <X11/Xaw/AsciiText.h>
#include <X11/Xaw/Command.h>

#include "GetString.h"

#define XVCMW XtVaCreateManagedWidget

static int accepted, cancelled;
static void Accept(), Cancel(), Focus();

extern void Popup();

static XtActionsRec actionTable[] = {
     {"Accept", (XtActionProc) Accept},
     {"Cancel", (XtActionProc) Cancel},
     {"Focus", (XtActionProc) Focus},
};
     
Widget InitGetString(parent, name)
   Widget parent;
   char *name;
{
     static int first_time = 1;
     Widget getStringWindow, form, title, edit, accept, cancel;

     if (first_time) {
	  XtAppAddActions(XtWidgetToApplicationContext(parent), actionTable,
			  XtNumber(actionTable));
	  first_time = 0;
     };

     getStringWindow = XtVaCreatePopupShell(name, transientShellWidgetClass,
					    parent,
					    XtNinput, True,
					    NULL);
     form = XVCMW("getStringForm", formWidgetClass, getStringWindow, NULL);
     title = XVCMW("getStringTitle", labelWidgetClass, form, NULL);
     edit = XVCMW("getStringEdit", asciiTextWidgetClass, form, NULL);
     accept = XVCMW("getStringAccept", commandWidgetClass, form, NULL);
     cancel = XVCMW("getStringCancel", commandWidgetClass, form, NULL);
     XtSetKeyboardFocus(form, edit);

     return getStringWindow;
}

int GetString(getStringWindow, label, value, pop_type, buf, len)
   Widget getStringWindow;
   String label, value;
   int pop_type;
   char *buf;
   int len;
{
     XtAppContext app_con;
     Widget title, edit;
     XEvent event;

     app_con = XtWidgetToApplicationContext(getStringWindow);
     title = XtNameToWidget(getStringWindow, "getStringForm.getStringTitle");
     edit = XtNameToWidget(getStringWindow, "getStringForm.getStringEdit");

     XtVaSetValues(title, XtNlabel, label, NULL);
     XtVaSetValues(edit, XtNstring, value, NULL);

     XtRealizeWidget(getStringWindow);
     Popup(getStringWindow, XtGrabExclusive, pop_type);

     accepted = cancelled = 0;
     while (! accepted && ! cancelled) {
	  XtAppNextEvent(app_con, &event);
	  XtDispatchEvent(&event);
     }

     XtPopdown(getStringWindow);

     if (accepted) {
	  char *s;
	  Widget text_source;

	  XtVaGetValues(edit, XtNstring, (XtArgVal) &s, XtNtextSource,
			(XtArgVal) &text_source, NULL);
	  strncpy(buf, s, len-2);
	  buf[len-1] = '\0';
	  XawAsciiSourceFreeString(text_source);
	  
	  return GETSTRING_ACCEPT;
     }
     else
	  return GETSTRING_CANCEL;
}

/* ARGSUSED */
static void Accept(w, e, p, n)
   Widget w;
   XEvent *e;
   String *p;
   Cardinal *n;
{
     accepted = 1;
}

/* ARGSUSED */
static void Cancel(w, e, p, n)
   Widget w;
   XEvent *e;
   String *p;
   Cardinal *n;
{
     cancelled = 1;
}

/* ARGSUSED */
static void Focus(w, e, p, n)
   Widget w;
   XEvent *e;
   String *p;
   Cardinal *n;
{
     XSetInputFocus(XtDisplay(w), XtWindow(w), RevertToPointerRoot,
		    CurrentTime);
}
