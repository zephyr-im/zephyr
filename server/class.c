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

#if !defined (lint) && !defined (SABER)
static char rcsid_class_c[] =
"$Id$";
#endif

#include "zserver.h"			/* includes zephyr/zephyr.h */

#include <assert.h>

/*
 * Class manager subsystem.
 *
 *
 * External functions are:
 *
 * Code_t triplet_register(client, subs)
 *
 * Code_t triplet_deregister(client, subs)
 *
 * Client *triplet_lookup(subs)
 *	Client *client;
 *	Destlist *subs;
 *
 * Acl *class_get_acl(class_name)
 *	String *class_name;
 *
 * Code_t class_restrict(class_name, acl)
 *	char *class_name;
 *	Acl *acl;
 *
 * Code_t class_setup_restricted(class_name, acl)
 *	char *class_name;
 *	Acl *acl;
 *
 * and several Destination methods.
 */

/*
 * The data structure used for the class manager is an array of hash buckets
 * each containing a pointer to a doubly linked circular list (in the style
 * of insque/remque).  Each element of this list contains a class.instance
 * name (which hashes into the bucket associated with this list) and a
 * doubly linked list of clients which are interested in this class.
 * The data pointed to by these clients is owned by other modules.  Care
 * must be taken by the caller not to a free()'d client
 * structure.
 *
 * If any hash bucket is empty, the pointer is null.
 *
 * The first element in the hash bucket is a special header unused for
 * storing classes, and is used for finding the end of the list.
 *
 * If any list of interested clients is empty, the class name is garbage
 * collected, unless the class has been registered as restricted.
 */

/* Private variables */ 
#define	EMPTY_CLASS	2000

#define ALLOC_OFFSET	8	/* Allocate 32 bytes less than a power of 2. */
#define ALLOC_INIT	8	/* Initial number of subscriptions. */

#define	HASHSIZE	1023
#define HASHVAL(c, i, r) (((c)->hash_val ^ (i)->hash_val ^ (r)->hash_val) \
			  % HASHSIZE)
#define DEST_HASHVAL(dest) HASHVAL((dest).classname, (dest).inst, (dest).recip)

static Triplet *triplet_bucket[HASHSIZE]; /* the hash table of pointers */

static Code_t remove_client __P((Triplet *triplet, Client *client));
static Code_t insert_client __P((Triplet *triplet, Client *client));
static Triplet *triplet_alloc __P((String *classname, String *inst,
				   String *recipient));
static void free_triplet __P((Triplet *));

/* public routines */

/*
 * Determine if two destination triplets are equal.  Note the backup
 * case-insensitive recipient check in the third term.  Recipients are
 * not downcased at subscription time (in order to preserve case for,
 * say, "zctl ret"), but traditional zephyr server behavior has not
 * been case-sensitive in the recipient string.  In most cases, a
 * failed match will fail on the classname or instance, and a successful
 * match will succeed on the (d1->recip == d2->recip) check, so this
 * shouldn't affect performance.  Note that this invalidates the overall
 * hash value check, which was of dubious value to start with.
 */

int ZDest_eq(d1, d2)
    Destination *d1, *d2;
{
    return((d1->classname == d2->classname) &&
	   (d1->inst == d2->inst) &&
	   (d1->recip == d2->recip ||
	    strcasecmp(d1->recip->string, d2->recip->string) == 0));
}


/* the client as interested in a triplet */

Code_t
triplet_register(client, dest)
    Client *client;
    Destination *dest;
{
    Triplet *triplet;
    unsigned long hashval;

    hashval = DEST_HASHVAL(*dest);
    for (triplet = triplet_bucket[hashval]; triplet; triplet = triplet->next) {
	if (ZDest_eq(&triplet->dest, dest))
	    return insert_client(triplet, client);
    }

    /* Triplet not present in hash table, insert it. */
    triplet = triplet_alloc(dest->classname, dest->inst, dest->recip);
    LIST_INSERT(triplet_bucket[hashval], triplet);
    return insert_client(triplet, client);
}

/* dissociate client from the class, garbage collecting if appropriate */

Code_t
triplet_deregister(client, dest)
    Client *client;
    Destination *dest;
{
    Triplet *triplet;
    int retval;
    unsigned long hashval;

#if 0
    zdbug((LOG_DEBUG, "class_dereg: %s %s", dest->classname->string,
	   dest->inst->string));
#endif
    hashval = DEST_HASHVAL(*dest);
    for (triplet = triplet_bucket[hashval]; triplet; triplet = triplet->next) {
	if (ZDest_eq(triplet->dest, client)) {
	    retval = remove_client(triplet, client);
	    if (retval != ZERR_NONE)
		return retval;
	    if (*triplet->clients == NULL && !triplet->acl) {
		LIST_DELETE(triplet);
		free_triplet(triplet);
	    }
	    return ZERR_NONE;
	}
    }
    return(ZSRV_BADASSOC);
}
	
/* return a linked list of what clients are interested in this triplet */

Client **
triplet_lookup(dest)
    Destination *dest;
{
    Triplet *triplet;
    unsigned long hashval;

    hashval = DEST_HASHVAL(*dest);
    for (triplet = triplet_bucket[hashval]; triplet; triplet = triplet->next) {
	if (ZDest_eq(&triplet->dest, dest))
	    return triplet->clients;
    }
    return NULL;
}

/*
 * return the acl structure associated with class, or NULL if there is
 * no such acl struct
 */

Acl *
class_get_acl(class_name)
    String *class_name;
{
    Triplet *triplet;
    unsigned long hashval;

    hashval = HASHVAL(class_name, empty, empty);
    for (triplet = triplet_bucket[hashval]; triplet; triplet = triplet->next) {
	if (triplet->dest.classname == class_name &&
	    triplet->dest.inst == empty && triplet->dest.recip == empty)
	    return triplet->acl;
    }

    /* No acl found, not restricted. */
    return NULL;
}

/*
 * restrict class by associating it with the acl structure acl.
 * return ZERR_NONE if no error, or ZSRV_NOCLASS if there is no such
 * class, or ZSRV_CLASSRESTRICTED if it is already restricted.
 */

Code_t
class_restrict(class_name, acl)
    char *class_name;
    Acl *acl;
{
    Triplet *triplet;
    String *d;
    unsigned long hashval;

    d = make_string(class_name,1);
    hashval = HASHVAL(d, empty, empty);
    for (triplet = triplet_bucket[hashval]; triplet; triplet = triplet->next) {
	if (triplet->dest.classname == d && triplet->dest.inst == empty &&
	    triplet->dest.recip == empty) {
	    if (triplet->acl)
		return ZSRV_CLASSRESTRICTED;
	    triplet->acl = acl;
	    free_string(d);
	    return ZERR_NONE;
	}
    }

    free_string(d);
    return ZSRV_NOCLASS;
}

/*
 * restrict class by registering it and  associating it with the acl
 * structure acl.  return ZERR_NONE if no error, or ZSRV_CLASSXISTS
 * if the class is already registered, or ENOMEM in case of malloc failure.
 */

Code_t
class_setup_restricted(class_name, acl)
    char *class_name;
    Acl *acl;
{
    Triplet *triplet;
    String *d;
    unsigned long hashval;

    d = make_string(class_name,1);
    hashval = HASHVAL(d, empty, empty);
    for (triplet = triplet_bucket[hashval]; triplet; triplet = triplet->next) {
	if (triplet->dest.classname == d && triplet->dest.inst == empty &&
	    triplet->dest.recip == d) {
	    free_string(d);
	    return ZSRV_CLASSXISTS;
	}
    }

    /* Triplet not present in hash table, insert it. */
    triplet = triplet_alloc(d, empty, empty);
    free_string(d);
    if (!triplet)
	return ENOMEM;
    triplet->acl = acl;
    LIST_INSERT(triplet_bucket[hashval], triplet);
    return ZERR_NONE;
}

/* private routines */

/* allocate space for a class structure */

static Triplet *
triplet_alloc(classname,inst,recipient)
    String *classname, *inst, *recipient;
{
    Triplet *triplet;
    Client *clist;

    triplet = (Triplet *) malloc(sizeof(Triplet));
    if (!triplet)
	return NULL;

    triplet->dest.classname = dup_string(classname);
    triplet->dest.inst = dup_string(inst);
    triplet->dest.recip = dup_string(recipient);
    triplet->clients = NULL;
    triplet->acl = NULL;

    return triplet;
}

/* insert a client into the list associated with the class *ptr */

static Code_t
insert_client(triplet, client)
    Triplet *triplet;
    Client *client;
{
    Client **clientp, **newclients;
    int new_size;

    if (triplet->clients) {
	/* Avoid duplication. */
	for (clientp = triplet->clients; *clientp; clientp++) {
	    if (*clientp == client)
		return ZSRV_CLASSXISTS;
	}

	if (clientp - triplet->clients > triplet->clients_size) {
	    new_size = triplet->clients_size * 2 + ALLOC_OFFSET;
	    newclients = (Client **) realloc(triplet->clients,
					     new_size * sizeof(Client *));
	    if (newclients == NULL)
		return ENOMEM;
	    triplet->clients = newclients;
	    triplet->clients_size = new_size;
	}
    } else {
	/* Allocate an initial list of client pointers. */
	triplet->clients = (Client **) malloc(ALLOC_INIT * sizeof(Client *));
	if (triplet->clients == NULL)
	    return ENOMEM;
	triplet->clients_size = ALLOC_INIT;
	clientp = triplet->clients;
    }

    *clientp = client;
    clientp[1] = NULL;
    return ZERR_NONE;
}

/* 
 * remove the client from the list associated with class *ptr, garbage
 * collecting if appropriate
 */

static Code_t remove_client(triplet, client)
    Triplet *triplet;
    Client *client;
{
    Client **clientp;

    for (clientp = triplet->clients; *clientp; clientp++) {
	if (*clientp == client) {
	    for (; *clientp; clientp++)
		*clientp = clientp[1];
	    return ZERR_NONE;
	}
    }

    return ZSRV_BADASSOC;
}

static void free_triplet(triplet)
    Triplet *triplet;
{
    if (triplet->clients)
	free(triplet->clients);
    free_string(triplet->dest.classname);
    free_string(triplet->dest.inst);
    free_string(triplet->dest.recip);
    free(triplet);
}

void triplet_dump_subs(fp)
    FILE *fp;
{
    int i;
    Triplet *triplet;
    Client **clientp;

    for (i = 0; i < HASHSIZE; i++) {
	for (triplet = triplet_bucket[i]; triplet; triplet = triplet->next) {
	    fputs("Triplet '", fp);
	    subscr_quote(triplet->dest.classname->string, fp);
	    fputs("' '", fp);
	    subscr_quote(triplet->dest.inst->string, fp);
	    fputs("' '", fp);
	    subscr_quote(triplet->dest.recip->string, fp);
	    fputs("':\n", fp);
	    if (triplet->clients) {
		for (clientp = triplet->clients; *clientp; clientp++) {
		    fprintf(fp, "\t%s %d (%s)\n",
			    inet_ntoa((*clientp)->addr.sin_addr),
			    ntohs((*clientp)->addr.sin_port),
			    (*clientp)->principal->string);
		}
	    }
	}
    }
}

