#include <stdio.h>
#include <pwd.h>
#include "xzwrite.h"

char *get_home_dir()
{
     struct passwd    *pwuid;
     static char      *h = NULL;

     if (h) return h;
     
     if ((h = getenv("HOME")) != NULL) return h;
     
     pwuid = getpwuid(getuid());
     return (pwuid->pw_dir);
}
