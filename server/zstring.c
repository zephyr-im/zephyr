/*
 * Copyright (C) 1991 by the Massachusetts Institute of Technology.
 * For copying and distribution information, see the file "mit-copyright.h".
 *
 *	$Source$
 *	$Id$
 *	$Author$
 */

#include <mit-copyright.h>

#include <ctype.h>
#ifdef __STDC__
#include <stdlib.h>
#endif
#include <string.h>
#include "zstring.h"

static ZSTRING *zhash[ZSTRING_HASH_TABLE_SIZE];

#ifdef __STDC__
# define        P(s) s
#else
# define P(s) ()
#endif

extern unsigned long hash P((const char *s));
extern char *strsave P((const char *s));
#undef P

ZSTRING *
make_zstring(s, downcase)
     char *s;
     int downcase;
{
  char *new_s,*p;
  ZSTRING *new_z,*hp;
  int hash_val;

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
  new_z = malloc(sizeof(ZSTRING));
  new_z->string = new_s;
  new_z->len = strlen(new_s);
  new_z->ref_count = 1;
  
  /* Add to beginning of hash table */
  hash_val = hash(new_s) % ZSTRING_HASH_TABLE_SIZE;
  hp = zhash[hash_val];
  new_z->next = hp;
  if (hp != NULL)
    hp->prev = new_z;
  new_z->prev = NULL;
  zhash[hash_val] = new_z;

  return(new_z);
}

void
free_zstring(z)
     ZSTRING *z;
{
  ZSTRING *hp;
  int hash_val;

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
eq_zstring(a,b)
     ZSTRING *a, *b;
{
  return(a == b);
}
