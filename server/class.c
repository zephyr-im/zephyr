/* This file is part of the Project Athena Zephyr Notification System.
 * It contains functions for the Zephyr server class manager subsystem.
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

#include <zephyr/mit-copyright.h>

#ifndef lint
static char rcsid_cm_c[] = "$Header$";
#endif lint

#include <zephyr/zephyr.h>
#include "zserver.h"

/*
 * Class manager subsystem.
 *
 *
 * external functions are:
 *
 * Code_t cm_register(client, class)
 *
 * Code_t cm_deregister(client, class)
 *
 * ZClientList_t *cm_lookup(class)
 *	ZClientDesc_t *client;
 *	char *class;
 */

/* Private variables */ 
#define	EMPTY_CLASS	2000

#define	HASHSIZE	511
#define	HASHMUL		243

static ZClass_t *class_bucket[511];

/* private routines */
static int hash(string)
char *string;
{
    register int hval = 0;
    register char *cp = string;

    while (*cp)
      hval = (hval + (*cp++) * HASHMUL) % HASHSIZE;
    return(hval);
}

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

static void free_class(ptr)
ZClass_t *ptr;
{
    free(ptr->classname);
    free(ptr);
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

    if (ptr->clientlist == NULLZCLT) {
	listp->q_forw = listp;
	listp->q_back = listp;
	ptr->clientlist = listp;
    } else
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
	if (listp->q_forw == listp) { /* this is the only elem on this queue */
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
	    remque(listp);
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

	ptr->q_forw = ptr;
	ptr->q_back = ptr;
	class_bucket[hashval] = ptr;
	return(insert_client(ptr, client));

    } else if (!strcmp(ptr->classname, class)) /* match! */
      return(insert_client(ptr, client));
    else {
	for (ptr2 = ptr->q_forw; ptr2 != ptr; ptr2 = ptr2->q_forw)
	  /* walk down the list, looking for a match */
	  if (!strcmp(ptr2->classname, class))
	    return(insert_client(ptr2, client));

	/* fell off the end, no match */
	if ((ptr2 = class_alloc(class)) == NULLZCT)
	  return(ZERR_UNIX);
	insque(ptr2, ptr);		/* insert new class into hash bucket */
	return(insert_client(ptr2, client));
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
	if (remove_client(ptr, client) == EMPTY_CLASS) {
	    /* careful here, we need to remove it and adjust the pointer to
	       the next element unless this is the only one */
	    if (ptr = ptr->q_forw) {
		/* garbage collect this bucket */
		free_class(ptr);
		class_bucket[hashval] = NULLZCT;
	    } else {
		/* adjust pointer and garbage collect */
		class_bucket[hashval] = ptr->q_forw;
		remque(ptr);
		free_class(ptr);
	    }
	}
	return(ZERR_NONE);
    }
    else {
	for (ptr2 = ptr->q_forw; ptr2 != ptr; ptr2 = ptr2->q_forw) {
	    /* walk down the list, looking for a match */
	    if (!strcmp(ptr2->classname, class)) {
		if ((retval = remove_client(ptr2, client)) == EMPTY_CLASS) {
		    /* here ptr2 is never pointing to class_bucket[hashval],
		       so we don't worry about freeing the bucket */
		    remque(ptr2);
		    free_class(ptr2);
		    return(ZERR_NONE);
		}
		/* if not EMPTY_CLASS, it's either ZERR_S_BADASSOC (not found)
		   or ZERR_NONE (found and removed), so break */
		break;
	    }
	}

	/* fell off: either client not found or client found
	   and removed, retval contains the result */

	return(retval);
    }
}

ZClientList_t *cm_lookup(class)
char *class;
{
    register ZClass_t *ptr, *ptr2;
    int hashval = hash(class);

    if ((ptr = class_bucket[hashval]) == NULLZCT)
      return(NULLZCLT);			/* no such class */
    else if (!strcmp(ptr->classname, class))
      return(ptr->clientlist);
    else { /* go search the list for the class */
	for (ptr2 = ptr->q_forw; ptr2 != ptr; ptr2 = ptr2->q_forw) {
	    /* walk down the list, looking for a match */
	    if (!strcmp(ptr2->classname, class))
	      return(ptr2->clientlist);
	}
	/* fell off the end */
	return(NULLZCLT);
    }
}
