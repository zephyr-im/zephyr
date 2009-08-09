/*
 * This file is part of the Project Athena Zephyr Notification System.
 *
 * It contains declarations for use in the server, relating to access
 * control.
 *
 * Created by Ken Raeburn.
 *
 * $Id$
 *
 * Copyright (c) 1990 by the Massachusetts Institute of Technology.
 * For copying and distribution information, see the file
 * "mit-copyright.h".
 */

#include <zephyr/mit-copyright.h>

#include "acl.h"
#include "zstring.h"

typedef	enum _Access {
    TRANSMIT,			/* use transmission acl */
    SUBSCRIBE,			/* use subscription acl */
    INSTWILD,			/* use instance wildcard acl */
    INSTUID				/* use instance UID identity acl */
} Access;

typedef struct _Acl {
    char *acl_filename;
    int	acl_types;		/* Internal; access fields present. */
} Acl;

/* found in access.c */
void access_init(void);
void access_reinit(void);

/* found in acl_files.c */
int acl_load(char *);

/* external data relevant */
extern int zdebug;

