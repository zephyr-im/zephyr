#include <X11/Intrinsic.h>
#include <X11/StringDefs.h>
#include <X11/Shell.h>
#include <X11/Xaw/Command.h>
#include <X11/Xaw/Form.h>
#include <X11/Xaw/Toggle.h>
#include <X11/Xaw/List.h>

#include "xzwrite.h"
#include "GetString.h"

extern Widget toplevel, getString, destList;
extern DestRec current_dest;
extern Defaults defs;

void display_dest()
{
     XawListChange(destList, (String *) dest_text(), dest_num(), 0, True);
}

void delete_dest()
{
     XawListReturnStruct *item;

     item = XawListShowCurrent(destList);
     if (item->list_index == XAW_LIST_NONE)
	  return;

     dest_delete_string(item->string);
     display_dest();
}

void create_dest()
{
     char buf[ZLEN*3+2], *s;
     int ret;

     ret = GetString(getString, "Enter new <class,instance,recipient> triple:",
		     "", 0, buf, ZLEN*3+2);
     if (ret == GETSTRING_ACCEPT) {
	  s = (char *) malloc(strlen(buf)+1);
	  strcpy(s, buf);
	  if (dest_add_string(s) == NULL) {
	       XBell(XtDisplay(toplevel), 0);
	       free(s);
	  }
	  else
	       display_dest();
     }
}

void select_dest()
{
     DestRec dest;
     XawListReturnStruct *item;
     int ret, used_global = 0;

     item = XawListShowCurrent(destList);
     if (item->list_index == XAW_LIST_NONE)
	  return;
     
     parse_into_dest(&dest, item->string);

     if (! strcmp(dest.zclass, "...")) {
	  ret = GetString(getString, "Enter CLASS to send to:", "", 0,
			  dest.zclass, ZLEN);
	  if (ret != GETSTRING_ACCEPT) return;
	  used_global = 1;
     }

     if (! strcmp(dest.zinst, "...")) {
	  ret = GetString(getString, "Enter INSTANCE to send to:", "", 0,
			  dest.zinst, ZLEN);
	  if (ret != GETSTRING_ACCEPT) return;
	  used_global = 1;
     }

     if (! strcmp(dest.zrecip, "...")) {
	  ret = GetString(getString, "Enter RECIPIENT to send to:", "", 0,
			  dest.zrecip, ZLEN);
	  if (ret != GETSTRING_ACCEPT) return;
	  used_global = 1;
     }

     if (defs.add_globals && used_global) {
	  /* A hack so using "..." looks pretty */
	  if (! strcmp(dest.zclass, DEFAULT_CLASS) &&
	      ! strcmp(dest.zinst, DEFAULT_INST)) {
	       char *temp;

	       temp = (char *) malloc(strlen(dest.zrecip) + 1);
	       strcpy(temp, dest.zrecip);
	       dest_add_string(temp);
	  }
	  else
	       dest_add(&dest);
	  display_dest();
     }

     if (defs.ping && *dest.zrecip) {
	  ret = zeph_ping(&dest);
	  switch (ret) {
	  case SEND_OK:
	       edit_set_title(&dest);
	       _BCOPY((char *) &dest, (char *) &current_dest, sizeof(DestRec));
	       break;
	  case SENDFAIL_SEND:
	  case SENDFAIL_RECV:
	  case SENDFAIL_ACK:
	       XBell(XtDisplay(toplevel), 0);
	       return;
	  }
     }
     else {
	  edit_set_title(&dest);
	  _BCOPY((char *) &dest, (char *) &current_dest, sizeof(DestRec));
     }
}
