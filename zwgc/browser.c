#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include "zwgc.h"

static int browser_fd;
struct sockaddr_un sun;

int BOpenSocket()
{
   int fd,len;
   char *temp;

   if ((fd=socket(PF_UNIX,SOCK_STREAM,0)) == -1)
      return(-1);

   sun.sun_family=AF_UNIX;
   if (temp=getenv("WGSOCK"))
      strncpy(sun.sunpath,temp,sizeof(sun.sunpath));
   else
      sprintf(sun.sun_path,"/tmp/.zwgc.%d",getuid());
   if (bind(fd,(struct sockaddr *) &sun,
	    (len=strlen(sun.sunpath)) > sizeof(sun.sunpath)?
	    sizeof(sun.sunpath):len) == -1) {
      close(fd);
      return(-1);
   }

   if (listen(fd,5) == -1) {
      unlink(sun.sunpath);
      close(fd);
      return(-1);
   }

   return(fd);
}
