#include <stdio.h>
#include <string.h>
#include <pwd.h>
#include <dyn.h>

#include "xzwrite.h"

extern Defaults defs;
DynObject zsigs = NULL;

#define islower(foo) ((foo) >= 'a' && (foo) <= 'z')
#define toupper(foo) ((foo)+'A'-'a')

Boolean set_random_zsigs();

main(argc, argv)
   int	argc;
   char	**argv;
{
     zeph_init();

     build_interface(&argc, argv);

     if (argc > 1) usage();

     set_signature();
     dest_init();
     yank_init();
     edit_win_init();
     menu_match_defs();
     (void) load_default_dest();
     display_dest();

     if (defs.track_logins)
	  logins_subscribe();
     if (defs.auto_reply)
	  zeph_subto_replies();

     go();
}

set_signature()
{
     char *sig, sigbfr[BUFSIZ];
     
     /* Do magic with signature */
     if (defs.zsigfile)
       if (strcmp(defs.zsigfile, "*"))
	 if (set_random_zsigs()) return;

     if (*defs.signature)
	  return;

     sig = (char *) zeph_get_signature();
     if (!sig) {
	  /* try to find name in the password file */
	  register struct passwd *pwd;
	  register char *cp = sigbfr;
	  register char *cp2, *pp;
	  
	  pwd = getpwuid(getuid());
	  if (pwd) {
	       cp2 = pwd->pw_gecos;
	       for (; *cp2 && *cp2 != ',' ; cp2++) {
		    if (*cp2 == '&') {
			 pp = pwd->pw_name;
			 *cp++ = islower(*pp) ? toupper(*pp) : *pp;
			 pp++;
			 while (*pp)
			      *cp++ = *pp++;
		    } else
			 *cp++ = *cp2;
	       }
	       *cp = '\0';
	       sig = sigbfr;
	  }
     }	
     
     if (sig) {
	  defs.signature = (char *) Malloc(strlen(sig) + 1,
					   "getting signature",
					   NULL);
	  strcpy(defs.signature, sig);
     }
}
	 


usage()
{
     fprintf(stderr, "Usage:  xzwrite [ -toolkitoption ... ] [-s signature] [+d | -d] [+n | -n]\n\t[+v | -v] [+yd | -yd] [+av | -av] [+ci | -ci] [-my yanks]\n\t[+l | -l] [+a | -a] [+x | -x] [+z | -z] [+pong | -pong] [+reply | -reply]\n");
     exit(1);
}

#define BUF_SIZE 1024

Boolean set_random_zsigs()
{ int x, n;
  char z[BUF_SIZE], *z2;
  FILE *fp;

  fp = fopen(defs.zsigfile, "r");
  if (!fp) {
    fprintf(stderr, "xzwrite: cant open file \"%s\".\n", defs.zsigfile);
    return False; }
  
  zsigs = DynCreate(sizeof(char*), 5);
  
  while ( fgets(z, BUF_SIZE, fp) != NULL) {
    if (z[0] == '#' || z[0] == 0) continue;
    n = strlen(z);
    z2 = (char *) calloc (sizeof(char), n);
    if (!z2) {
      fprintf(stderr, "xzwrite: out of memory.\n"); exit(1); }
    if (z[n-1] == '\n') { n--; z[n] = 0; }
    for (x = 0; x <= n; x++) {
      if (z[x] != '\\') z2[x] = z[x];
      else z2[x] = '\n'; }
    DynAdd(zsigs, (DynPtr) &z2); }

  fclose(fp);
  return True;
}
