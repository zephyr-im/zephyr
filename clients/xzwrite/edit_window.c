#include <X11/Intrinsic.h>
#include <X11/StringDefs.h>
#include <X11/Xaw/Paned.h>
#include <X11/Xaw/Label.h>
#include <X11/Xaw/Form.h>
#include <X11/Xaw/Command.h>
#include <X11/Xaw/AsciiText.h>

#include "xzwrite.h"

extern Widget toplevel, editor, editTitle;
extern Defaults defs;
extern DestRec	current_dest;

void edit_win_init()
{
     edit_set_title(&current_dest);
}

void send_message()
{
     char	*buf;
     int	ret;

     /* I should do more interesting things with these error conditions */

     XtVaGetValues(editor,
		   XtNstring, (XtArgVal) &buf,
		   NULL);

     ret = zeph_send_message(&current_dest, buf);
     XawAsciiSourceFreeString(editor);

     switch (ret) {
     case SEND_OK:
	  break;
     case SENDFAIL_SEND:
     case SENDFAIL_RECV:
     case SENDFAIL_ACK:
	  if (defs.verbose)
	       XBell(XtDisplay(toplevel), 0);
	  break;
     }

     /* Only the second argument matters */
     if (defs.close_on_send)
	  XtCallActionProc(toplevel, "CloseSend", NULL, NULL, 0);
}

void edit_set_title(dest)
   Dest	dest;
{
     char	*title;

     /* alloc two extra bytes  for * in case zinst or zrecip are "" */
     title = (char *) Malloc( strlen(dest->zclass) + strlen(dest->zinst) +
			     strlen(dest->zrecip) + 20, "while setting title",
			     NULL);
     sprintf(title, "Sending to <%s, %s, %s>", dest->zclass,
	     *dest->zinst ? dest->zinst : "*",
	     *dest->zrecip ? dest->zrecip : "*");

     XtVaSetValues(editTitle,
		   XtNlabel, title,
		   NULL);

     free(title);
}

void edit_clear()
{
     XtVaSetValues(editor,
		   XtNstring, "",
		   NULL);
}

void edit_yank_prev()
{
     Yank     yank;

     yank = yank_prev();
     if (! yank)
	  return;
     
     XtVaSetValues(editor,
                 XtNstring, (XtArgVal) yank->msg,
                 NULL);
     if (defs.yank_dest) {
        dest_set_current_dest(&yank->dest);
	edit_set_title(&yank->dest);
   }
}

void edit_yank_next()
{
     Yank     yank;

     yank = yank_next();
     if (! yank)
	  return;
     
     XtVaSetValues(editor,
                 XtNstring, (XtArgVal) yank->msg,
                 NULL);
     if (defs.yank_dest) {
	  dest_set_current_dest(&yank->dest);
	  edit_set_title(&yank->dest);
     }
}

void edit_yank_store()
{
     char *buf;

     XtVaGetValues(editor,
                 XtNstring, (XtArgVal) &buf,
                 NULL);

     if (buf != NULL && *buf != '\0')
	  yank_store(&current_dest, buf);

     XawAsciiSourceFreeString(editor);
}
