#include <stdio.h>
#include <pwd.h>

#include "xzwrite.h"

#ifdef __STDC__
void Warning(const char *first, ...)
#else
/*VARARGS*/
void Warning(first, va_alist)
   const char	*first;
   va_dcl
#endif
{
     va_list	vp;
     char	*s;
     
     fputs(first, stderr);

     VA_START(vp, first);
     while ((s = va_arg(vp, char *)) != NULL)
	  fputs(s, stderr);
     va_end(vp);
     putc('\n', stderr);
}

#ifdef __STDC__
void Error(const char *first, ...)
#else
/*VARARGS*/
void Error(first, va_alist)
   const char *first;
   va_dcl
#endif
{
     va_list	vp;
     char	*s;
     
     fputs(first, stderr);

     VA_START(vp, first);
     while ((s = va_arg(vp, char *)) != NULL)
	  fputs(s, stderr);
     va_end(vp);
     putc('\n', stderr);

     exit(1);
}

#ifdef __STDC__
char *Malloc(int n, ...)
#else
/*VARARGS*/
char *Malloc(n, va_alist)
   int	n;
   va_dcl
#endif
{
     va_list	vp;
     char	*ptr, *s;

     ptr = (char *) malloc((unsigned) n);
     if (ptr)
	  return ptr;

     fputs("Out of memory: ", stderr);

     VA_START(vp, n);
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

     if ((u = getenv("USER")) != NULL) return u;

     pwuid = getpwuid(getuid());
     if (pwuid)
       return u = pwuid->pw_name;
     else
       return NULL;
}
