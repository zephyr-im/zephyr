/* This file is part of the Project Athena Zephyr Notification System.
 * It contains the main loop of the Zephyr server
 *
 *	Created by:	Lucien W. Van Elsen
 *
 *	$Id$
 *
 *	Copyright (c) 1991 by the Massachusetts Institute of Technology.
 *	For copying and distribution information, see the file
 *	"mit-copyright.h". 
 */

#include <zephyr/mit-copyright.h>
#include "zserver.h"

#ifndef lint
#ifndef SABER
static const char rcsid_zstring_c[] =
"$Id$";
#endif
#endif

static String *zhash[STRING_HASH_TABLE_SIZE];

String *
make_string(char *s,
	    int downcase)
{
    char *new_s,*p;
    String *new_z,*hp;
    int i;

    if (downcase) {
	new_s = strsave(s);
	p = new_s;
	while(*p) {
	    if (isascii(*p) && isupper(*p))
		*p = tolower(*p);
	    p++;
	}
    } else {
	new_s = s;
    }

    new_z = find_string(new_s,0);
    if (new_z != NULL) {
	if (downcase)
	    free(new_s);
	new_z->ref_count++;
	return(new_z);
    }

    /* Initialize new String */

    if (!downcase)
	new_s = strsave(s);
    new_z = (String *) malloc(sizeof(String));
    new_z->string = new_s;
    new_z->ref_count = 1;
  
    /* Add to beginning of hash table */
    new_z->hash_val = hash(new_s);
    i = new_z->hash_val % STRING_HASH_TABLE_SIZE;
    hp = zhash[i];
    new_z->next = hp;
    if (hp != NULL)
	hp->prev = new_z;
    new_z->prev = NULL;
    zhash[i] = new_z;

    return new_z;
}

void
free_string(String *z)
{
    if (z == (String *) NULL)
	return;

    z->ref_count--;
    if (z->ref_count > 0)
	return;

    /* delete string completely */
    if(z->prev == NULL)
	zhash[hash(z->string) % STRING_HASH_TABLE_SIZE] = z->next;
    else
	z->prev->next = z->next;
  
    if (z->next != NULL)
	z->next->prev = z->prev;

    free(z->string);
    free(z);
}

String *
find_string(char *s,
	    int downcase)
{
    char *new_s,*p;
    String *z;

    if (downcase) {
	new_s = strsave(s);
	p = new_s;
	while (*p) {
	    if (isascii(*p) && isupper(*p))
		*p = tolower(*p);
	    p++;
	}
    } else {
	new_s = s;
    }

    z = zhash[hash(new_s) % STRING_HASH_TABLE_SIZE];
    while (z != NULL) {
	if (strcmp(new_s, z->string) == 0)
	    break;
	z = z->next;
    }

    if (downcase)
	free(new_s);

    return z;
}

int
comp_string(String *a,
	    String *b)
{
    if (a->hash_val > b->hash_val)
	return 1;
    if (a->hash_val < b->hash_val)
	return -1;
    return strcmp(a->string,b->string);
}

void
print_string_table(FILE *f)
{
    String *p;
    int i;

    for(i = 0; i < STRING_HASH_TABLE_SIZE; i++) {
	p = zhash[i];
	while (p != (String *) NULL) {
	    fprintf(f,"[%d] %s\n",p->ref_count,p->string);
	    p = p->next;
	}
    }
}

String *
dup_string(String *z)
{
    z->ref_count++;
    return z;
}

