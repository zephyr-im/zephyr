/* This file is part of the Project Athena Zephyr Notification System.
 * It contains declarations for use in the server.
 *
 *	Created by:	John T. Kohl
 *
 *	$Source$
 *	$Author$
 *
 *	Copyright (c) 1987 by the Massachusetts Institute of Technology.
 *	For copying and distribution information, see the file
 *	"mit-copyright.h". 
 */

/* definitions for the Zephyr server */

/* structures */
typedef struct _ZClientDesc_t {
/*    struct _ZClientDesc_t *q_forw;
    struct _ZClientDesc_t *q_back;*/
    char *dummy;
} ZClientDesc_t;

typedef struct _ZEntity_t {
    char *filler;			/* fill this in later */
} ZEntity_t;

typedef struct _ZClientList_t {
    struct	_ZClientList_t *q_forw;
    struct	_ZClientList_t *q_back;
    ZClientDesc_t	*client;
} ZClientList_t;

typedef struct _ZClass_t {
    struct	_ZClass_t *q_forw;
    struct	_ZClass_t *q_back;
    char	*classname;
    ZClientList_t	*clientlist;
} ZClass_t;


#define	NULLZCT		((ZClass_t *) 0)
#define	NULLZCDT	((ZClientDesc_t *) 0)
#define	NULLZCLT	((ZClientList_t *) 0)

/* Function declarations */

/* found in common.c */
extern char *strsave();

/* found in cm.c */
extern Code_t cm_register();
extern Code_t cm_deregister();
extern ZClientList_t *cm_lookup();

/* server internal error codes */
#define ZERR_S_BADASSOC	2000		/* client not associated with class */
