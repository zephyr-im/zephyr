#include <stdio.h>
#include <pwd.h>

#include "xzwrite.h"

extern Defaults defs;

main(argc, argv)
   int	argc;
   char	**argv;
{
     char sigbfr[BUFSIZ];
     
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
