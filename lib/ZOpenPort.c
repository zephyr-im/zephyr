/* This file is part of the Project Athena Zephyr Notification System.
 * It contains source for the ZOpenPort function.
 *
 *	Created by:	Robert French
 *
 *	$Source$
 *	$Author$
 *
 *	Copyright (c) 1987 by the Massachusetts Institute of Technology.
 *	For copying and distribution information, see the file
 *	"mit-copyright.h". 
 */
/* $Header$ */

#include <zephyr/mit-copyright.h>

#include <zephyr/zephyr_internal.h>
#include <sys/socket.h>

Code_t ZOpenPort(port)
	u_short	*port;
{
	int retval;
	struct sockaddr_in bindin;

	(void) ZClosePort();

	if ((__Zephyr_fd = socket(AF_INET,SOCK_DGRAM,0)) < 0) {
		__Zephyr_fd = -1;
		return (errno);
	}

	bindin.sin_family = AF_INET;

	if (port && *port)
		bindin.sin_port = *port;
	else
		/*NOSTRICT*/
		bindin.sin_port = htons((u_short)((getpid()*8)&0xfff)+
					(((int)random()>>4)&0xf)+1024);

	bindin.sin_addr.s_addr = INADDR_ANY;

	do {
		if ((retval = bind(__Zephyr_fd,&bindin,sizeof(bindin))) < 0) {
			if (errno == EADDRINUSE) {
				if (port && *port)
					return (ZERR_PORTINUSE);
				else
					/*NOSTRICT*/
					bindin.sin_port = htons(ntohs(bindin.
								      sin_port)
								+1);
			}
			else
				return (errno);
		}
	} while (retval < 0 && (!port || !*port));

	__Zephyr_port = bindin.sin_port;
	__Zephyr_open = 1;

	if (port)
		*port = bindin.sin_port;

	return (ZERR_NONE);
}
