#include <stdio.h>

#include "xzwrite.h"

extern Defaults defs;

main(argc, argv)
   int	argc;
   char	**argv;
{
     zeph_init();

     build_interface(&argc, argv);

     if (argc > 1) usage();

     /* Do magic with signature */
     if (! *defs.signature) {
	  char *sig;

	  sig = (char *) zeph_get_signature();
	  if (sig) {
	       defs.signature = (char *) Malloc(strlen(sig) + 1,
						"getting signature",
						NULL);
	       strcpy(defs.signature, sig);
	  }
     }
	 
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

usage()
{
     fprintf(stderr, "Usage:  xzwrite [ -toolkitoption ... ] [-s signature] [+d | -d] [+n | -n]\n\t[+v | -v] [+yd | -yd] [+av | -av] [+ci | -ci] [-my yanks]\n\t[+l | -l] [+a | -a] [+x | -x] [+z | -z] [+pong | -pong] [+reply | -reply]\n");
     exit(1);
}
