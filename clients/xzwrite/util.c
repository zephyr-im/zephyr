#include <stdio.h>
#include <varargs.h>
#include <pwd.h>

#include "xzwrite.h"

/*VARARGS*/
void Warning(first, va_alist)
   char	*first;
   va_dcl
{
     va_list	vp;
     char	*s;
     
     fputs(first, stderr);

     va_start(vp);
     while ((s = va_arg(vp, char *)) != NULL)
	  fputs(s, stderr);
     va_end(vp);
     putc('\n', stderr);
}

/*VARARGS*/
void Error(first, va_alist)
   char *first;
   va_dcl
{
     va_list	vp;
     char	*s;
     
     fputs(first, stderr);

     va_start(vp);
     while ((s = va_arg(vp, char *)) != NULL)
	  fputs(s, stderr);
     va_end(vp);
     putc('\n', stderr);

     exit(1);
}

/*VARARGS*/
char *Malloc(n, va_alist)
   int	n;
   va_dcl
{
     va_list	vp;
     char	*ptr, *s;

     ptr = (char *) malloc((unsigned) n);
     if (ptr)
	  return ptr;

     fputs("Out of memory: ", stderr);

     va_start(vp);
     while ((s = va_arg(vp, char *)) != NULL)
	  fputs(s, stderr);
     va_end(vp);
     putc('\n', stderr);

     exit(1);
}

char *get_username()
{
     struct passwd *pwuid;
     static char *u = NULL;

     if (u) return u;

     if (u = (char *) getenv("USER")) return u;

     pwuid = getpwuid(getuid());
     if (pwuid)
       return u = pwuid->pw_name;
     else
       return NULL;
}
