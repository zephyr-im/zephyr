#include <stdio.h>
#include <dyn.h>
#include <strings.h>

#include "xzwrite.h"

/*
 * The following code extracts keypressed from an X event:
 * 
 * keyevent = event->xkey;
 * XLookupString(&keyevent, buffer, 1, NULL, NULL);
 */

/*
 * This entire file could easily be changes so that multiple destination
 * lists could be used.  But I don't know that that's necessary for this
 * program.
 */

/* Globals */
DestRec current_dest;

static DynObject	dests;
extern Defaults		defs;

static void get_dest_from_file(), _get_default_dest();
static int sort_dest_func();

/* A function for debugging */
void dest_print()
{
     char **d;
     int i;

     d = (char **) DynGet(dests, 0);
     for (i=0; i<DynSize(dests); i++)
	  printf("%d %s\n", i, d[i]);
}

char **dest_text()
{
     return ((char **) DynGet(dests, 0));
}

int dest_num()
{
     return (DynSize(dests));
}

void dest_set_current_dest(dest)
   Dest       dest;
{
     bcopy((char *) dest, (char *) &current_dest, sizeof(DestRec));
}

void dest_init()
{
     dests = DynCreate(sizeof(char *), 0);
     if (! dests)
	  Error("Out of memory reading destinations", NULL);

     strcpy(current_dest.zclass, DEFAULT_CLASS);
     strcpy(current_dest.zinst, DEFAULT_INST);
     strcpy(current_dest.zrecip, get_username());
}

char **load_default_dest()
{
     char	*get_home_dir();

     if (! *get_home_dir())
	  Error("Cannot find your home directory.", NULL);

     if (defs.read_xzwrite)
	  _get_default_dest(XZWRITE_DEST_FILE);
     if (defs.read_zephyr)
	  _get_default_dest(ZEPHYR_FILE);
     if (defs.read_anyone)
	  _get_default_dest(ANYONE_FILE);

     if (DynSize(dests) == 0)
	  Error("No destinations specified", NULL);

     sort_destinations();
     return ((char **) DynGet(dests, 0));
}

static void _get_default_dest(s)
   char *s;
{
     char	*filename;
     
     filename = (char *) Malloc(strlen(get_home_dir()) + strlen(s) + 1,
				"While reading file ", s, NULL);
     sprintf(filename, "%s%s", get_home_dir(), s);
     get_dest_from_file(dests, filename);
     free(filename);
}

static void get_dest_from_file(dests, f)
   DynObject 	dests;
   char		*f;
{
     FILE	*file;
     char	*line, buf[BUFSIZ];
     DestRec	dest;

     if ((file = fopen(f, "r")) == NULL) {
	  Warning("Cannot find destinations file", f, NULL);
	  return;
     }
     
     while (bfgets(buf, 80, file)) {
	  if (buf[0] == '#' || buf[0] == '\0') {
	       if (defs.debug)
		    printf("xzwrite: skipping comment or blank line\n");
	       continue;
	  }
	  
	  if (! parse_into_dest(&dest, buf)) {
	       Warning("Ignoring incorrect destination: ", buf, NULL);
	       continue;
	  }

	  line = (char *) Malloc(strlen(buf) + 1, "parsing file ", f, NULL);
	  strcpy(line, buf);
	  if (DynAdd(dests, (char *) &line) == DYN_NOMEM)
	       Error("Out of memory parsing file ", f, NULL);
     }
     
     fclose(file);
}

char **dest_add(dest)
   Dest dest;
{
     char *buf;

     /* Two extra bytes if instance or recipient are "" */
     buf = (char *) Malloc(strlen(dest->zclass) + strlen(dest->zinst) +
			   strlen(dest->zrecip) + 5,
			   "while adding destination ", NULL);
     sprintf(buf, "%s,%s,%s", dest->zclass,
	     *dest->zinst ? dest->zinst : "*",
	     *dest->zrecip ? dest->zrecip : "*");

     if (DynAdd(dests, &buf) == DYN_NOMEM) {
	  Warning("Out of memory adding destination ", buf, ".  Skipping.",
		  NULL);
	  free(buf);
     }

     sort_destinations();
     return ((char **) DynGet(dests, 0));
}

/* XXX The return/output semantics of this function are not good */
char **dest_add_string(s)
   char *s;
{
     DestRec	dest;
     
     if (! parse_into_dest(&dest, s))
	  return NULL;
     
     if (DynAdd(dests, &s) == DYN_NOMEM)
	  Warning("Out of memory adding destination ", s, ".  Skipping.",
		  NULL);

     sort_destinations();
     return ((char **) DynGet(dests, 0));
}

char **dest_delete_string(s)
   char	*s;
{
     int	i;
     char	**d;

     d = (char **) DynGet(dests, 0);
     for (i=0; i<DynSize(dests); i++) {
	  if (! strcmp(s, d[i])) {
	       DynDelete(dests, i);
	       break;
	  }
     }

     return ((char **) DynGet(dests, 0));
}

char **delete_dest_index(i)
   int i;
{
     int	ret;

     ret = DynDelete(dests, i);
     if (ret != DYN_OK)
	  return NULL;

     return ((char **) DynGet(dests, 0));
}

     
static int sort_dest_func(c1, c2)
   char	**c1, **c2;
{
     char	*s1, *s2, *i1, *i2;

     /* A string with a , in it is always less than one without */
     s1 = *c1; s2 = *c2;
     i1 = index(s1, ',');
     i2 = index(s2, ',');
     if (i1 == NULL && i2 != NULL)
	  return 1;
     else if (i1 != NULL && i2 == NULL)
	  return -1;
     else
	  return strcmp(s1, s2);
}

char **sort_destinations()
{
     char	**d;

     d = (char **) DynGet(dests, 0);
     qsort(d, DynSize(dests), sizeof(char *), sort_dest_func);
     return d;
}

/* Fills in dest from s */
#define distance(a,b)		((int) b - (int) a)
int parse_into_dest(dest, s)
   Dest	dest;
   char	*s;
{
     char	*a, *b;
     int	x, y;

     /* Check for just recipient */
     if ((a=index(s, ','))==0) {
	  if (strlen(s) > ZLEN)
	       return 0;
	  strcpy(dest->zclass, DEFAULT_CLASS);
	  strcpy(dest->zinst, DEFAULT_INST);
	  strcpy(dest->zrecip, s);
     }

     /* Check for just class,instance or instace,recipient */
     else if ((b=index((++a), ','))==0) {
	  if (defs.class_inst) {
	       x = distance(s, a-1);
	       if (x >= ZLEN)
		    return 0;

	       strncpy(dest->zclass, s, x);
	       dest->zclass[x] = '\0';
	       strcpy(dest->zinst, a);
	       strcpy(dest->zrecip, "*"); }
	  else {
	       x = distance(s, a-1);
	       if (x >= ZLEN)
		    return 0;
	       
	       strcpy(dest->zclass, DEFAULT_CLASS);
	       strncpy(dest->zinst, s, x);
	       dest->zinst[x] = '\0';
	       strcpy(dest->zrecip, a); }
     }

     /* Otherwise, deal with class,instance,recipent */
     else {
	  ++b;
	  x = distance(s, a-1);
	  y = distance(a, b-1);
	  if (x >= ZLEN || y >= ZLEN)
	       return 0;
	  
	  strncpy(dest->zclass, s, x);
	  dest->zclass[x] = '\0';
	  strncpy(dest->zinst, a, y);
	  dest->zinst[y] = '\0';
	  strcpy(dest->zrecip, b);
     }
     if (!strcmp(dest->zrecip,"*")) *(dest->zrecip) = '\0';
     if (!strcmp(dest->zinst,"*")) *(dest->zinst) = '\0';

     return 1;
}
#undef distance

/*
 * notice is from <MESSAGE,inst,sender>.  If inst is "PERSONAL", add
 * destination string "<sender>" if
 * 	1) MESSAGE,PERSONAL,<sender> is not in list, and
 * 	2) <sender> is not in list.
 * If inst is not "PERSONAL", add destination string
 * "<MESSAGE,<inst>,<sender>>" if it is not in the list.
 */
void dest_add_reply(notice)
   ZNotice_t *notice;
{
     Dest dest;
     char **list, *newdest, buf[ZLEN*3+2];
     int i, num;

     list = dest_text();
     num = dest_num();

     	  
     /* A hack so local-realm is less annoying */
     {
	  char *r;

	  r = index(notice->z_sender, '@');
	  if (r && ! strcmp(r+1, ZGetRealm()))
	       *r = '\0';
     }
     
     if (! strcasecmp(notice->z_class_inst, DEFAULT_INST)) {
	  sprintf(buf, "message,personal,%s", notice->z_sender);
	  for (i=0; i < num; i++) {
	       if (! strcasecmp(list[i], buf) ||
		   ! strcasecmp(list[i], notice->z_sender))
		    return;
	  }

	  newdest = (char *) Malloc(strlen(notice->z_sender) + 1,
				"while adding reply destination", NULL);
	  sprintf(newdest, "%s", notice->z_sender);
     }
     else {
	  sprintf(buf, "message,%s,%s", notice->z_class_inst,
		  notice->z_sender);
	  for (i=0; i < num; i++) {
	       if (! strcasecmp(list[i], buf))
		    return;
	  }

	  newdest = (char *) Malloc(strlen(notice->z_class) +
				    strlen(notice->z_class_inst) +
				    strlen(notice->z_sender) + 3,
				    "while adding reply destintion",
				    NULL);
	  sprintf(newdest, "%s,%s,%s", notice->z_class,
		  notice->z_class_inst, notice->z_sender);
     }

     dest_add_string(newdest);
     display_dest();

     if (defs.track_logins)
	  zeph_subto_logins(&notice->z_sender, 1);
}

