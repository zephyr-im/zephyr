/*
 * This file is part of the Project Athena Zephyr Notification System.
 *
 * It contains declarations for use in the server, relating to access
 * control.
 *
 * Created by Ken Raeburn.
 *
 * $Source$
 * $Author$
 * $Id$
 *
 * Copyright (c) 1990 by the Massachusetts Institute of Technology.
 * For copying and distribution information, see the file
 * "mit-copyright.h".
 */

#include <zephyr/mit-copyright.h>

#include <zephyr/acl.h>
#include "ZString.h"
#include "unix.h"

typedef	enum _ZAccess_t {
	TRANSMIT,			/* use transmission acl */
	SUBSCRIBE,			/* use subscription acl */
	INSTWILD,			/* use instance wildcard acl */
	INSTUID				/* use instance UID identity acl */
} ZAccess_t;

class ZAcl_t {
	char *acl_filename;
	int	acl_types;	/* Flag field indcating which acls
				 are present.  Used ONLY in access.c */
    public:
	int ok (ZString, ZAccess_t);
	ZAcl_t (const char *path) {
	    extern char * strsave (const char *);
	    acl_filename = strsave (path);
	    acl_types = 0;
	    check ();
	}
	~ZAcl_t () {
	    xfree (acl_filename);
	}
    private:
	void check (void);
	void check_acl_type (ZAccess_t, int);
};

inline int access_check(ZString sender, ZAcl_t *acl, ZAccess_t accesstype) {
    return acl->ok (sender, accesstype);
}

/* found in access.c */
extern void access_init (void), access_reinit (void);

/* external data relevant */
extern int zdebug;
