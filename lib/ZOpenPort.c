/* This file is part of the Project Athena Zephyr Notification System.
 * It contains source for the ZOpenPort function.
 *
 *	Created by:	Robert French
 *
 *	$Id$
 *
 *	Copyright (c) 1987 by the Massachusetts Institute of Technology.
 *	For copying and distribution information, see the file
 *	"mit-copyright.h". 
 */

#ifndef lint
static const char rcsid_ZOpenPort_c[] = "$Id$";
#endif

#include <internal.h>
#include <sys/socket.h>

Code_t
ZOpenPort(u_short *port)
{
    struct sockaddr_in bindin;
    unsigned int len;
    int val = 1;
    int ret;
    
    (void) ZClosePort();

    if ((__Zephyr_fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
	__Zephyr_fd = -1;
	return errno;
    }

    bindin.sin_family = AF_INET;

    if (port && *port) {
	bindin.sin_port = *port;
	if (setsockopt(__Zephyr_fd, SOL_SOCKET, SO_REUSEADDR, &val, sizeof val) < 0)
	    return errno;
    } else {
	bindin.sin_port = htons(60000);
    }

    bindin.sin_addr.s_addr = INADDR_ANY;

    do {
	ret = bind(__Zephyr_fd, (struct sockaddr *)&bindin, sizeof(bindin));
	if (ret < 0 && !(port && *port))
	    bindin.sin_port++;
    } while (ret < 0 && errno == EADDRINUSE && !(port && *port));
    if (ret < 0 && errno == EADDRINUSE)
	return ZERR_PORTINUSE;
    else if (ret < 0)
	return errno;

    if (port && *port) {
         /* turn SO_REUSEADDR back off so no one else can steal it */
        val = 0;
	if (setsockopt(__Zephyr_fd, SOL_SOCKET, SO_REUSEADDR, &val, sizeof val) < 0)
	    return errno;
    }
    
    __Zephyr_port = bindin.sin_port;
    __Zephyr_open = 1;

    if (port)
	*port = bindin.sin_port;

    return ZERR_NONE;
}
