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

#include <ctype.h>			/* for isupper, tolower */

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
 * ZClientList_t *triplet_lookup(subs)
 *	ZClient_t *client;
 *	ZSubscr_t *subs;
 *
 * ZAcl_t *class_get_acl(ZString class_name)
 *
 * Code_t class_restrict(class_name, acl)
 *	char *class_name;
 *	ZAcl_t *acl;
 *
 * Code_t class_setup_restricted(class_name, acl)
 *	char *class_name;
 *	ZAcl_t *acl;
 *
 * and several ZDestination methods.
 */

/*
 * The data structure used for the class manager is an array of hash buckets
 * each containing a pointer to a doubly linked circular list (in the style
 * of insque/remque).  Each element of this list contains a class.instance
 * name (which hashes into the bucket associated with this list) and a
 * doubly linked list of clients which are interested in this class.
 * The data pointed to by these clients is owned by other modules.  Care
 * must be taken by the caller not to register a free()'d client
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

#define	HASHSIZE	1023
#define HASHVAL(c, i, r) (((c)->hash_val ^ (i)->hash_val ^ (r)->hash_val) \
			  % HASHSIZE)
#define DEST_HASHVAL(dest) HASHVAL((dest).classname, (dest).inst, (dest).recip)

static ZTriplet_t *class_bucket[HASHSIZE]; /* the hash table of pointers */


#ifdef __STDC__
# define        P(s) s
#else
# define P(s) ()
#endif

static Code_t remove_client P((ZTriplet_t *ptr, ZClient_t *client));
static Code_t insert_client P((ZTriplet_t *ptr, ZClient_t *client));
static ZClientList_t *client_alloc P((ZClient_t *client));
static ZTriplet_t *triplet_alloc P((ZSTRING *classname, ZSTRING *inst,
				ZSTRING *recipient));
static void free_class P((ZTriplet_t *));

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
     ZDestination *d1, *d2;
{
  return((d1->classname == d2->classname) &&
	 (d1->inst == d2->inst) &&
	 (d1->recip == d2->recip ||
	  strcasecmp(d1->recip->string, d2->recip->string) == 0));
}


/* register the client as interested in a triplet */

Code_t
triplet_register(client, dest)
     ZClient_t *client;
     ZDestination *dest;
{
	register ZTriplet_t *ptr, *ptr2;
	unsigned long hashval;

	hashval = DEST_HASHVAL(*dest);

	if (!(ptr = class_bucket[hashval])) {
		/* not registered */
		
		ptr = triplet_alloc(dest->classname, dest->inst, dest->recip);
		if (!ptr)
			return(ENOMEM);

		/* allocate the head of the bucket */

		if (!(ptr2 = (ZTriplet_t *) xmalloc(sizeof(ZTriplet_t))))
		  return(ENOMEM);

		ptr2->zct_clientlist = 0;
		ptr2->zct_acl = 0;
		ptr2->q_forw = ptr;
		ptr2->q_back = ptr;
		ptr->q_forw = ptr2;
		ptr->q_back = ptr2;

		class_bucket[hashval] = ptr2;
		return(insert_client(ptr, client));

	} else {
		for (ptr2 = ptr->q_forw; ptr2 != ptr; ptr2 = ptr2->q_forw) {
		    /* walk down the list, looking for a match */
		    if (ZDest_eq(&ptr2->zct_dest,dest))
		      return(insert_client(ptr2, client));
		}

		/* fell off the end, no match */
		ptr2 = triplet_alloc(dest->classname, dest->inst, dest->recip);
		if (!ptr2)
			return(ENOMEM);

		xinsque(ptr2, ptr);	/* insert new class into hash bucket */
		return(insert_client(ptr2, client));
	}
}

/* dissociate client from the class, garbage collecting if appropriate */

Code_t
triplet_deregister(client, dest)
     ZClient_t *client;
     ZDestination *dest;
{
	register ZTriplet_t *ptr, *ptr2;
	int retval = -1;
	unsigned long hashval;

	hashval = DEST_HASHVAL(*dest);
#if 0
	zdbug((LOG_DEBUG, "class_dereg: %s %s",	dest->classname->string,
	       dest->inst->string));
#endif
	ptr = class_bucket[hashval];
	if (!ptr)
		/* no such class to deregister */
		return(ZSRV_BADASSOC);
	
	for (ptr2 = ptr->q_forw; ptr2 != ptr; ptr2 = ptr2->q_forw) {
		/* walk down the list, looking for a match */
		if (ZDest_eq(&ptr2->zct_dest,dest)) {
			retval = remove_client(ptr2, client);
			if (retval == EMPTY_CLASS) {
#if 0
				zdbug((LOG_DEBUG,"empty class"));
#endif
				/* Don't free up restricted classes. */
				if (ptr2->zct_acl)
					return(ZERR_NONE);
				else {
					xremque(ptr2);
					free_class(ptr2);
					return(ZERR_NONE);
				}
			}
			/* if not EMPTY_CLASS, it's either ZSRV_BADASSOC
			   (not found) or ZERR_NONE (found and removed),
			   so break */
			break;
		}
	}

	/* fell off: either client not found or client found
	   and removed, retval contains the result */
	return(retval);
}

/* return a linked list of what clients are interested in this triplet */

ZClientList_t *
triplet_lookup(dest)
     ZDestination *dest;
{
	register ZTriplet_t *class, *p;
	unsigned long hashval;

	hashval = DEST_HASHVAL(*dest);
	p = class_bucket[hashval];
	if (p == NULLZT)
		return NULLZCLT;

	/* Go search the list for the class */
	for (class = p->q_forw; class != p; class = class->q_forw) {
		/* walk down the list, looking for a match */
		if (ZDest_eq(&class->zct_dest,dest))
			return class->zct_clientlist;
	}
	return NULLZCLT;
}

/*
 * return the acl structure associated with class, or NULLZACLT if there is
 * no such acl struct
 */

ZAcl_t *
class_get_acl(class_name)
     ZSTRING *class_name;
{
	register ZTriplet_t *ptr, *ptr2;
	unsigned long hashval;

	hashval = HASHVAL(class_name, empty, empty);
	if (!(ptr = class_bucket[hashval]))
		return(NULLZACLT);

	/* walk down the list, looking for a match */
	for (ptr2 = ptr->q_back; ptr2 != ptr; ptr2 = ptr2->q_back)
	    if ((ptr2->zct_dest.classname == class_name) &&
		(ptr2->zct_dest.inst == empty) &&
		(ptr2->zct_dest.recip == empty))
		return(ptr2->zct_acl);

	/* fell off the end, no match ==> not restricted */
	return(NULLZACLT);
}

/*
 * restrict class by associating it with the acl structure acl.
 * return ZERR_NONE if no error, or ZSRV_NOCLASS if there is no such
 * class, or ZSRV_CLASSRESTRICTED if it is already restricted.
 */

Code_t
class_restrict(class_name, acl)
     char *class_name;
     ZAcl_t *acl;
{
	register ZTriplet_t *ptr, *ptr2;
	ZSTRING *d;
	unsigned long hashval;

	d = make_zstring(class_name,1);
	hashval = HASHVAL(d, empty, empty);

	if (!(ptr = class_bucket[hashval])) {
	  free_zstring(d);
	  return(ZSRV_NOCLASS);
	}
	for (ptr2 = ptr->q_forw; ptr2 != ptr; ptr2 = ptr2->q_forw)
		/* walk down the list, looking for a match */
		if ((ptr2->zct_dest.classname == d) &&
		    (ptr2->zct_dest.inst == empty) &&
		    (ptr2->zct_dest.recip == empty)) {
			if (ptr2->zct_acl)
				return ZSRV_CLASSRESTRICTED;
			ptr2->zct_acl = acl;
			free_zstring(d);
			return(ZERR_NONE);
		}

	/* fell off the end, no match */
	free_zstring(d);
	return(ZSRV_NOCLASS);
}

/*
 * restrict class by registering it and  associating it with the acl
 * structure acl.  return ZERR_NONE if no error, or ZSRV_CLASSXISTS
 * if the class is already registered, or ENOMEM in case of malloc failure.
 */
  
Code_t
class_setup_restricted(class_name, acl)
     char *class_name;
     ZAcl_t *acl;
{
	register ZTriplet_t *ptr, *ptr2;
	ZSTRING *d;
	unsigned long hashval;

	d = make_zstring(class_name,1);
	hashval = HASHVAL(d, empty, empty);

	if (!(ptr = class_bucket[hashval])) {
		/* not registered */

		ptr = triplet_alloc(d,empty,empty);
		if (!ptr)
		  return(ENOMEM);

		ptr->zct_acl = acl;

		/* allocate the head of the bucket */
		ptr2 = (ZTriplet_t *) xmalloc(sizeof(ZTriplet_t));
		if (!ptr2)
		  return(ENOMEM);

		ptr2->q_forw = ptr;
		ptr2->q_back = ptr;
		ptr->q_forw = ptr2;
		ptr->q_back = ptr2;

		class_bucket[hashval] = ptr2;
		free_zstring(d);
		return(ZERR_NONE);
	} else {
	    for (ptr2 = ptr->q_forw; ptr2 != ptr; ptr2 = ptr2->q_forw)
		/* walk down the list, looking for a match */
		if ((ptr2->zct_dest.classname == d) &&
		    (ptr2->zct_dest.inst == empty) &&
		    (ptr2->zct_dest.recip == empty)) {
		  free_zstring(d);
		  return(ZSRV_CLASSXISTS);
		}
	    if (!(ptr2 = triplet_alloc(d,empty,empty))) {
	      free_zstring(d);
	      return(ENOMEM);
	    }

	    free_zstring(d);
	    ptr2->zct_acl = acl;
	    xinsque(ptr2, ptr);
	    return(ZERR_NONE);
	}
}

/* private routines */

/* allocate space for a class structure */

static ZTriplet_t *
triplet_alloc(classname,inst,recipient)
     ZSTRING *classname;
     ZSTRING *inst;
     ZSTRING *recipient;
{
	register ZTriplet_t *ptr;
	ZClientList_t *clist;

	if (!(ptr = (ZTriplet_t *) xmalloc(sizeof(ZTriplet_t))))
	    return(NULLZT);

	ptr->q_forw = ptr->q_back = ptr;
	ptr->zct_dest.classname = dup_zstring(classname);
	ptr->zct_dest.inst = dup_zstring(inst);
	ptr->zct_dest.recip = dup_zstring(recipient);

	if (!(clist = (ZClientList_t *) xmalloc (sizeof (ZClientList_t)))) {
	    xfree(ptr);
	    return(NULLZT);
	}
	clist->q_forw = clist->q_back = clist;
	ptr->zct_clientlist = clist;
	ptr->zct_acl = NULLZACLT;

	return (ptr);
}

/* allocate space for a client entry */

static ZClientList_t *
client_alloc(client)
     ZClient_t *client;
{
	register ZClientList_t *ptr;
	if (!(ptr = (ZClientList_t *) xmalloc(sizeof(ZClientList_t))))
		return(NULLZCLT);

	ptr->q_forw = ptr->q_back = ptr;
	ptr->zclt_client = client;

	return(ptr);
}

/* insert a client into the list associated with the class *ptr */

static Code_t
insert_client(ptr, client)
     ZTriplet_t *ptr;
     ZClient_t *client;
{
	register ZClientList_t *listp, *clist;

	for (clist = ptr->zct_clientlist->q_forw;
	     clist != ptr->zct_clientlist;
	     clist = clist->q_forw) {
		/* don't duplicate */
		if (clist->zclt_client == client)
			return(ZSRV_CLASSXISTS);
	}

	if (!(listp = client_alloc(client)))
		return(ENOMEM);

	xinsque(listp, ptr->zct_clientlist);
	return(ZERR_NONE);
}

/* 
 * remove the client from the list associated with class *ptr, garbage
 * collecting if appropriate
 */

static Code_t remove_client(ptr, client)
     ZTriplet_t *ptr;
     ZClient_t *client;
{
	register ZClientList_t *listp = ptr->zct_clientlist; 
	register ZClientList_t *listp2;

	if (!listp)
		return(ZSRV_BADASSOC);
	for (listp2 = listp->q_forw;
	     listp2 != listp;
	     listp2 = listp2->q_forw)
		/* walk down list, looking for him */
		if (listp2->zclt_client == client) {
			xremque(listp2);
			xfree(listp2);
			if (listp->q_forw == listp)
				return(EMPTY_CLASS);
			else
				return(ZERR_NONE);
		}
	return(ZSRV_BADASSOC);
}

static void free_class(class)
     ZTriplet_t *class;
{
  free_zstring(class->zct_dest.classname);
  free_zstring(class->zct_dest.inst);
  free_zstring(class->zct_dest.recip);
  if (class->zct_acl != NULL)
    xfree(class->zct_acl);
  if (class->zct_clientlist != NULL)
    xfree(class->zct_clientlist);
  xfree(class);
}
		     
void class_dump_subs(fp)
    register FILE *fp;
{
    int i;
    ZTriplet_t *trpq, *trp;
    ZClientList_t *cltq, *clt;

    for (i = 0; i < HASHSIZE; i++) {
	trpq = class_bucket[i];
	if (!trpq)
	    continue;
	for (trp = trpq->q_forw; trp != trpq; trp = trp->q_forw) {
	    fputs("Triplet '", fp);
	    subscr_quote(trp->zct_dest.classname->string, fp);
	    fputs("' '", fp);
	    subscr_quote(trp->zct_dest.inst->string, fp);
	    fputs("' '", fp);
	    subscr_quote(trp->zct_dest.recip->string, fp);
	    fputs("':\n", fp);
	    cltq = trp->zct_clientlist;
	    if (!cltq)
		continue;
	    for (clt = cltq->q_forw; clt != cltq; clt = clt->q_forw) {
		fprintf(fp, "\t%s %d (%s)\n",
			inet_ntoa(clt->zclt_client->zct_sin.sin_addr),
			ntohs(clt->zclt_client->zct_sin.sin_port),
			clt->zclt_client->zct_principal->string);
	    }
	}
    }
}

