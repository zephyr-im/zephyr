/*
 * Copyright (C) 1991 by the Massachusetts Institute of Technology.
 * For copying and distribution information, see the file "mit-copyright.h".
 *
 *	$Source$
 *	$Id$
 *	$Author$
 */

#include <mit-copyright.h>

#ifndef __zstring_h
#define __zstring_h __FILE__

#define ZSTRING_HASH_TABLE_SIZE	1031

typedef struct t_zstring
{
  char *string;			/* the string itself */
  int len;			/* string length, for speed */
  int ref_count;		/* for gc */
  struct t_zstring *next;	/* for linking in hash table */
  struct t_zstring *prev;	/* for linking in hash table */
} ZSTRING;

#ifdef __STDC__
# define        P(s) s
#else
# define P(s) ()
#endif

ZSTRING *make_zstring P((char *s, int downcase));
void free_zstring P((ZSTRING *z));
ZSTRING *find_zstring P((char *s, int downcase));
int eq_zstring P((ZSTRING *a, ZSTRING *b));


#undef P


#endif /* __zstring_h */
