#include <X11/Intrinsic.h>   /* for Boolean */
#include <zephyr/zephyr.h>
#include <dyn.h>

#include "xzwrite.h"

extern Defaults defs;

#define distance(a,b)		((int) b - (int) a)
void logins_deal(notice)
   ZNotice_t *notice;
{
     char		*newdest;
     int		d;

     d = distance(notice->z_class_inst, index(notice->z_class_inst, '@'));
     newdest = (char *) Malloc(d+1, "while dealing with login/logout notice",
			       NULL);
     strncpy(newdest, notice->z_class_inst, d);
     newdest[d] = '\0';
     
     if (! strcmp(notice->z_opcode, "USER_LOGIN")) {
	  dest_add_string(newdest);
	  display_dest();
     }
     else if (! strcmp(notice->z_opcode, "USER_LOGOUT")) {
	  dest_delete_string(newdest);
	  display_dest();
     }
     else {
	  Warning("Invalid login/logout notice.  Opcode: ",
		  notice->z_opcode, "\n", NULL);
	  free(newdest);
     }
}
#undef distance

/* Considers a destination with a , and without a . in to be a username */
void logins_subscribe()
{
     DestRec dest;
     DynObject users;
     char **list;
     int num;

     users = DynCreate(sizeof(char *), 0);
     if (! users)
	  Error("Out of memory subscribing to logins", NULL);

     list = dest_text();
     num = dest_num();
     while (--num) {
	  parse_into_dest(&dest, list[num]);
	  if (*dest.zrecip)
	       if (DynAdd(users, list + num) != DYN_OK)
		    Error("Out of memory subscribing to logins", NULL);
     }

     zeph_subto_logins((char **) DynGet(users, 0), DynSize(users));

     DynDestroy(users);
}

/* ARGSUSED */
Boolean login_scan_work(client_data)
   caddr_t	client_data;
{
     static int	i, num, first = 1;
     static DestRec dest = {"MESSAGE", "PERSONAL", ""};
     static char **text;

     if (first) {
	  text = dest_text();
	  num = dest_num();
	  i = first = 0;
     }

     if (i >= num)
	  return True;

     if (index(text[i], ',') || index(text[i], '.')) {
	  i += 1;
	  return False; }

     strcpy(dest.zrecip, text[i]);
     if ((defs.pong_scan && zeph_pong(&dest) != SEND_OK) ||
	 (! defs.pong_scan && ! zeph_locateable(text[i]))) {
	  dest_delete_string(text[i]);
	  i -= 1;
	  num -= 1;
	  display_dest();
     }
     
     i += 1;

     return False;
}

