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
 * Code_t class_register(client, subs)
 *
 * Code_t class_deregister(client, subs)
 *
 * ZClientList_t *class_lookup(subs)
 *	ZClient_t *client;
 *	ZSubscr_t *subs;
 *
 * void class_free(lyst)
 *	ZClientList_t *lyst;
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

#define	HASHSIZE	511
#define	HASHMUL		243

static ZClass_t *class_bucket[HASHSIZE]; /* the hash table of pointers */

#define CLASS_HASHVAL(cl,in) (cl->hash_val ^ in->hash_val) % HASHSIZE

#ifdef __STDC__
# define        P(s) s
#else
# define P(s) ()
#endif

static Code_t remove_client P((ZClass_t *ptr, ZClient_t *client)),
    insert_client P((ZClass_t *ptr, ZClient_t *client));
static ZClientList_t *client_alloc P((ZClient_t *client));
static ZClass_t *class_alloc P((ZSTRING *classname, ZSTRING *inst));
static void free_class P((ZClass_t *));

/* public routines */

void
set_ZDestination_hash(zd)
     ZDestination *zd;
{
  zd->hash_value = (zd->classname->hash_val ^ zd->inst->hash_val) % HASHSIZE;
}


int ZDest_eq(d1, d2)
     ZDestination *d1, *d2;
{
  return((d1->hash_value == d2->hash_value) &&
	 (d1->classname == d2->classname) &&
	 (d1->inst == d2->inst));
}

int order_dest_strings(d1, d2)
     ZDestination *d1, *d2;
{
  int i;

  i = strcmp(d1->classname->string, d2->classname->string);
  if (i != 0)
    return (i);
  i = strcmp(d1->inst->string, d2->inst->string);
  if (i != 0)
    return(i);
  i = strcmp(d1->recip->string, d2->recip->string);
  if (i != 0)
    return(i);
  syslog(LOG_WARNING,"order_dest_strings equal");
  return(1); /* be arbitrary */
}

int ZDest_geq(d1, d2)
     ZDestination *d1, *d2;
{
  return((d1->hash_value != d2->hash_value) ?
	 (d1->hash_value < d2->hash_value) :
	 ((order_dest_strings(d1,d2) < 0)));
}



/* register the client as interested in class */

Code_t
class_register(client, subs)
     ZClient_t *client;
     ZSubscr_t *subs;
{
	register ZClass_t *ptr, *ptr2;
	unsigned long hashval;

	hashval = CLASS_HASHVAL(subs->zst_dest.classname, subs->zst_dest.inst);

	if (!(ptr = class_bucket[hashval])) {
		/* not registered */
		
		if (!(ptr = class_alloc(subs->zst_dest.classname,
					subs->zst_dest.inst)))
			return(ENOMEM);

		/* allocate the head of the bucket */

		if (!(ptr2 = (ZClass_t *) xmalloc(sizeof(ZClass_t))))
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
		for (ptr2 = ptr->q_forw; ptr2 != ptr; ptr2 = ptr2->q_forw)
		    /* walk down the list, looking for a match */
		    if (ZDest_eq(&ptr2->zct_dest,&subs->zst_dest))
		      return(insert_client(ptr2, client));

		/* fell off the end, no match */
		if (!(ptr2 = class_alloc(subs->zst_dest.classname,
					 subs->zst_dest.inst)))
			return(ENOMEM);

		xinsque(ptr2, ptr);	/* insert new class into hash bucket */
		return(insert_client(ptr2, client));
	}
}

/* dissociate client from the class, garbage collecting if appropriate */

Code_t
class_deregister(client, subs)
     ZClient_t *client;
     ZSubscr_t *subs;
{
	register ZClass_t *ptr, *ptr2;
	int retval = -1;
	unsigned long hashval;

	hashval = CLASS_HASHVAL(subs->zst_dest.classname, subs->zst_dest.inst);
#if 0
	zdbug((LOG_DEBUG, "class_dereg: %s %s",
		subs->zst_dest.classname->string,
		subs->zst_dest.inst->string));
#endif
	if (!(ptr = class_bucket[hashval]))
		/* no such class to deregister */
		return(ZSRV_BADASSOC);
	
	for (ptr2 = ptr->q_forw; ptr2 != ptr; ptr2 = ptr2->q_forw) {
		/* walk down the list, looking for a match */
		if (ZDest_eq(&ptr2->zct_dest,&subs->zst_dest)) {
			if ((retval = remove_client(ptr2, client)) == EMPTY_CLASS) {
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

/* return a linked list of what clients are interested in this class */

ZClientList_t *
class_lookup(subs)
     ZSubscr_t *subs;
{
	register ZClass_t *ptr, *ptr2;
	register int count = 0, wc_count = 0, idx = 1;
	register ZClientList_t *list_return, *list_copy;
	ZClientList_t *list = NULLZCLT;
	ZClientList_t *wc_list = NULLZCLT;
	ZSubscr_t wc_sub;
	unsigned long hashval;

	hashval = CLASS_HASHVAL(subs->zst_dest.classname, subs->zst_dest.inst);

	if ((ptr = class_bucket[hashval]) !=  NULLZCT)
		/* go search the list for the class */
		for (ptr2 = ptr->q_forw; ptr2 != ptr; ptr2 = ptr2->q_forw) {
			/* walk down the list, looking for a match */
			if (ZDest_eq(&ptr2->zct_dest,&subs->zst_dest)) {
				list = ptr2->zct_clientlist;
				break;
			}
		}
	/* list is the list of direct matches; now check for wildcards */
	wc_sub = *subs;
	wc_sub.zst_dest.inst = wildcard_instance;
	set_ZDestination_hash(&wc_sub.zst_dest);

	hashval = CLASS_HASHVAL(wc_sub.zst_dest.classname, wc_sub.zst_dest.inst);
	if ((ptr = class_bucket[hashval]) != NULLZCT)
		/* go search the list for the class */
		for (ptr2 = ptr->q_forw; ptr2 != ptr; ptr2 = ptr2->q_forw) {
			/* walk down the list, looking for a match */
			if (ZDest_eq(&ptr2->zct_dest,&wc_sub.zst_dest)) {
				wc_list = ptr2->zct_clientlist;
				break;
			}
		}
	/* merge the lists for returning */
	if (list)
		for (list_return = list->q_forw;
		     list_return != list;
		     list_return = list_return->q_forw)
			count++;
	if (wc_list)
		for (list_return = wc_list->q_forw;
		     list_return != wc_list;
		     list_return = list_return->q_forw)
			wc_count++;
	
	if (!(wc_count + count))
		return(NULLZCLT);
	list_return = (ZClientList_t *) xmalloc((count + wc_count + 1)
						* sizeof(ZClientList_t));
	if (!list_return) {
		syslog(LOG_ERR, "class_lookup no mem");
		return(NULLZCLT);
	}
	list_return[0].q_forw = list_return[0].q_back = &list_return[0];
	if (list)
		for (list_copy = list->q_forw;
		     list_copy != list;
		     list_copy = list_copy->q_forw) {
			list_return[idx].zclt_client = list_copy->zclt_client;
			xinsque(&list_return[idx], &list_return[0]);
			idx++;
		}
	if (wc_list)
		for (list_copy = wc_list->q_forw;
		     list_copy != wc_list;
		     list_copy = list_copy->q_forw) {
			list_return[idx].zclt_client = list_copy->zclt_client;
			xinsque(&list_return[idx], &list_return[0]);
			idx++;
		}
	return(list_return);
}

/* free up the storage used by a returned list */
void
class_free(lyst)
     ZClientList_t *lyst;
{
	xfree(lyst);
	return;
}

/*
 * return the acl structure associated with class, or NULLZACLT if there is
 * no such acl struct
 */

ZAcl_t *
class_get_acl(class_name)
     ZSTRING *class_name;
{
	register ZClass_t *ptr, *ptr2;
	unsigned long hashval;

	hashval = CLASS_HASHVAL(class_name, empty);
	if (!(ptr = class_bucket[hashval]))
		return(NULLZACLT);

	/* walk down the list, looking for a match */
	for (ptr2 = ptr->q_back; ptr2 != ptr; ptr2 = ptr2->q_back)
	    if ((ptr2->zct_dest.classname == class_name) &&
		(ptr2->zct_dest.inst == empty))
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
	register ZClass_t *ptr, *ptr2;
	ZSTRING *d;
	unsigned long hashval;

	d = make_zstring(class_name,1);
	hashval = CLASS_HASHVAL(d,empty);

	if (!(ptr = class_bucket[hashval])) {
	  free_zstring(d);
	  return(ZSRV_NOCLASS);
	}
	for (ptr2 = ptr->q_forw; ptr2 != ptr; ptr2 = ptr2->q_forw)
		/* walk down the list, looking for a match */
		if ((ptr2->zct_dest.classname == d) &&
		    (ptr2->zct_dest.inst == empty)){
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
	register ZClass_t *ptr, *ptr2;
	ZSTRING *d;
	unsigned long hashval;

	d = make_zstring(class_name,1);
	hashval = CLASS_HASHVAL(d,empty);

	if (!(ptr = class_bucket[hashval])) {
		/* not registered */

		if (!(ptr = class_alloc(d,empty)))
		  return(ENOMEM);

		ptr->zct_acl = acl;

		/* allocate the head of the bucket */
		if (!(ptr2 = (ZClass_t *) xmalloc(sizeof(ZClass_t))))
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
		    (ptr2->zct_dest.inst == empty)) {
		  free_zstring(d);
		  return(ZSRV_CLASSXISTS);
		}
	    if (!(ptr2 = class_alloc(d,empty))) {
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

static ZClass_t *
class_alloc(classname,inst)
     ZSTRING *classname;
     ZSTRING *inst;
{
	register ZClass_t *ptr;
	ZClientList_t *clist;

	if (!(ptr = (ZClass_t *) xmalloc(sizeof(ZClass_t))))
	    return(NULLZCT);

	ptr->q_forw = ptr->q_back = ptr;
	ptr->zct_dest.classname = dup_zstring(classname);
	ptr->zct_dest.inst = dup_zstring(inst);
	ptr->zct_dest.recip = dup_zstring(empty);
	set_ZDestination_hash(&ptr->zct_dest);

	if (!(clist = (ZClientList_t *) xmalloc (sizeof (ZClientList_t)))) {
	    xfree(ptr);
	    return(NULLZCT);
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
     ZClass_t *ptr;
     ZClient_t *client;
{
	register ZClientList_t *listp, *clist;

	for (clist = ptr->zct_clientlist->q_forw;
	     clist != ptr->zct_clientlist;
	     clist = clist->q_forw)
		/* don't duplicate */
		if (clist->zclt_client == client)
			return(ZERR_NONE);

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
     ZClass_t *ptr;
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
     ZClass_t *class;
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
		     
