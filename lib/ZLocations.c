/* This file is part of the Project Athena Zephyr Notification System.
 * It contains source for the ZSetLocation function.
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

#include <pwd.h>
#include <sys/file.h>

uid_t getuid();

Code_t ZSetLocation()
{
	char bfr[BUFSIZ];
	int quiet;
	struct passwd *pw;
	
        quiet = 0;
	/* XXX a uid_t is a u_short (now), but getpwuid wants an int. AARGH! */
	if (pw = getpwuid((int) getuid())) {
		(void) sprintf(bfr,"%s/.hideme",pw->pw_dir);
		quiet = !access(bfr,F_OK);
	} 

	return (Z_SendLocation(LOGIN_CLASS,quiet?LOGIN_QUIET_LOGIN:
			       LOGIN_USER_LOGIN));
}
