/* Copyright (c) 1987 Massachusetts Institute of Technology */

/*
 *	$Source$
 *	$Header$
 */

#ifndef lint
static char *rcsid_cm_c = "$Header$";
#endif lint

#include <zephyr/mit-copyright.h>
#include <zephyr/zephyr.h>
#include "zserver.h"

/*
 * Class manager subsystem.
 * external functions are:
 * Code_t cm_register(client, class)
 * Code_t cm_deregister(client, class)
 * struct qelem *cm_lookup(class)
 *	ZClientDesc_t *client;
 *	char *class;
 */

/* Private variables */ 
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

#define	EMPTY_CLASS	2000

#define	HSHSIZ		8192
#define	HSHMUL		243

static ZClass_t *class_bucket[511];

/* private routines */
static ZClass_t *class_alloc(class)
char *class;
{
    register ZClass_t *ptr;
    if ((ptr = (ZClass_t *) malloc(sizeof(ZClass_t))) == NULLZCT)
      return(NULLZCT);

    if ((ptr->classname = strsave(class)) == NULL) {
	free((char *) ptr);
	return(NULLZCT);
    }
    return(ptr);
}

static ZClientList_t *client_alloc(client)
ZClientDesc_t *client;
{
    register ZClientList_t *ptr;
    if ((ptr = (ZClientList_t *) malloc(sizeof(ZClientList_t))) == NULLZCLT)
      return(NULLZCLT);

    ptr->client = client;
    return(ptr);
}

static Code_t insert_client(ptr, client)
ZClass_t *ptr;
ZClientDesc_t *client;
{
    register ZClientList_t *listp;

    if ((listp = client_alloc(client)) == NULLZCLT)
      return(ZERR_UNIX);
    if (ptr->clientlist == NULLZCLT)
      ptr->clientlist = listp;
    else
      insque(listp, ptr->clientlist);
    return(ZERR_NONE);
}

static Code_t remove_client(ptr, client)
ZClass_t *ptr;
ZClientDesc_t *client;
{
    register ZClientList_t *listp = ptr->clientlist; 
    register ZClientList_t *listp2;

    if (listp->client == client) { /* found him */
	if (listp->q_forw = listp) { /* this is the only elem on this queue */
	    ptr->clientlist = NULLZCLT;
	    free(listp);
	    return(EMPTY_CLASS);
	}
	/* ok, remove him, being careful to reset the pointer to the queue */
	ptr->clientlist = listp->q_forw;
	remque(listp);
	free(listp);
	return(ZERR_NONE);
    } else {
      for (listp2 = listp->q_forw; listp2 != listp; listp2 = listp2->q_forw)
	/* walk down list, looking for him */
	if (listp2->client == client) {
	    reqmue(listp);
	    free(listp);
	    return(ZERR_NONE);
	}
      return(ZERR_S_BADASSOC);
  }
}
    
/*  */
/* public routines */
Code_t cm_register(client, class)
ZClientDesc_t *client;
char *class;
{
    register ZClass_t *ptr, *ptr2;
    int hashval = hash(class);

    if ((ptr = class_bucket[hashval]) == NULLZCT) {
	/* not registered */

	if ((ptr = class_alloc(class)) == NULLZCT)
	  return(ZERR_UNIX);

	class_bucket[hashval] = ptr;
	return(insert_client(ptr, client));

    } else if (!strcmp(ptr->classname, class)) /* match! */
      return(insert_client(ptr, client));
    else {
	for (ptr2 = ptr->q_forw; ptr2 != ptr; ptr2 = ptr2->q_forw) {
	    /* walk down the list, looking for a match */
	    if (!strcmp(ptr2->classname, class))
	      return(insert_client(ptr2, client));
	}
	if (ptr2 = ptr) { /* fell off the end, no match */
	    if ((ptr2 = class_alloc(class)) == NULLZCT)
	      return(ZERR_UNIX);
	    insque(ptr2, ptr);		/* insert new class into hash bucket */
	    return(insert_client(ptr2, client));
	}
    }
}

Code_t cm_deregister(client, class)
ZClientDesc_t *client;
char *class;
{
    register ZClass_t *ptr, *ptr2;
    int retval = -1;
    int hashval = hash(class);
 
    if ((ptr = class_bucket[hashval]) == NULLZCT)
      /* no such class to deregister */
      return(ZERR_S_BADASSOC);
    if (!strcmp(ptr->classname, class)) { /* match! */
	retval = remove_client(ptr, client);
	/* handle retval here*/
	ptr2 = ptr;
    }
    else {
	for (ptr2 = ptr->q_forw; ptr2 != ptr; ptr2 = ptr2->q_forw) {
	    /* walk down the list, looking for a match */
	    if (!strcmp(ptr2->classname, class)) {
		retval = remove_client(ptr2, client);
		/* handle it here too */
		break;
	    }
	}
	/* fell off, error */
	return(ZERR_S_BADASSOC);
    }
}
