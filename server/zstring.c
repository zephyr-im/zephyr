/* This file is part of the Project Athena Zephyr Notification System.
 * It contains the main loop of the Zephyr server
 *
 *	Created by:	Lucien W. Van Elsen
 *
 *	$Source$
 *	$Author$
 *
 *	Copyright (c) 1991 by the Massachusetts Institute of Technology.
 *	For copying and distribution information, see the file
 *	"mit-copyright.h". 
 */

#include <zephyr/mit-copyright.h>

#ifndef lint
#ifndef SABER
static char rcsid_zstring_c[] =
    "$Id$";
#endif
#endif

#include <mit-copyright.h>

#include <ctype.h>
#if defined(__STDC__) && !defined(__HIGHC__) && !defined(SABER)
#include <stdlib.h>
#endif
#include <string.h>

#include <zephyr/zephyr.h>
#include "zstring.h"

static ZSTRING *zhash[ZSTRING_HASH_TABLE_SIZE];

#ifdef __STDC__
# define        P(s) s
#else
# define P(s) ()
#endif

extern unsigned long hash P((Zconst char *s));
extern char *strsave P((Zconst char *s));
#undef P

ZSTRING *
make_zstring(s, downcase)
     char *s;
     int downcase;
{
  char *new_s,*p;
  ZSTRING *new_z,*hp;
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

  new_z = find_zstring(new_s,0);
  if (new_z != NULL) {
    if (downcase)
      free(new_s);
    new_z->ref_count++;
    return(new_z);
  }

  /* Initialize new ZSTRING */

  if (!downcase)
    new_s = strsave(s);
  new_z = (ZSTRING *) malloc(sizeof(ZSTRING));
  new_z->string = new_s;
  new_z->len = strlen(new_s);
  new_z->ref_count = 1;
  
  /* Add to beginning of hash table */
  new_z->hash_val = hash(new_s);
  i = new_z->hash_val % ZSTRING_HASH_TABLE_SIZE;
  hp = zhash[i];
  new_z->next = hp;
  if (hp != NULL)
    hp->prev = new_z;
  new_z->prev = NULL;
  zhash[i] = new_z;

  return(new_z);
}

void
free_zstring(z)
     ZSTRING *z;
{
  if (z == (ZSTRING *) NULL)
    return;

  z->ref_count--;
  if (z->ref_count > 0)
    return;

  /* delete zstring completely */
  if(z->prev == NULL)
    zhash[hash(z->string) % ZSTRING_HASH_TABLE_SIZE] = z->next;
  else
    z->prev->next = z->next;
  
  if (z->next != NULL)
    z->next->prev = z->prev;

  free(z->string);
  free(z);
  return;
}

ZSTRING *
find_zstring(s,downcase)
     char *s;
     int downcase;
{
  char *new_s,*p;
  ZSTRING *z;

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

  z = zhash[hash(new_s) % ZSTRING_HASH_TABLE_SIZE];
  while (z != (ZSTRING *)NULL) {
    if (strcmp(new_s,z->string) == 0)
      break;
    z = z->next;
  }

  if (downcase)
    free(new_s);

  return(z);
}

int
comp_zstring(a,b)
     ZSTRING *a, *b;
{
  if (a->hash_val > b->hash_val)
    return(1);
  if (a->hash_val < b->hash_val)
    return(-1);
  return(strcmp(a->string,b->string));
}

void
print_zstring_table(f)
     FILE *f;
{
  ZSTRING *p;
  int i;

  for(i=0;i<ZSTRING_HASH_TABLE_SIZE;i++) {
    p = zhash[i];
    while (p != (ZSTRING *) NULL) {
      fprintf(f,"[%d] %s\n",p->ref_count,p->string);
      p = p->next;
    }
  }
  return;
}

ZSTRING *
dup_zstring(z)
     ZSTRING *z;
{
  z->ref_count++;
  return(z);
}
