/* This file is part of the Project Athena Zephyr Notification System.
 * It is one of the source files comprising zwgc, the Zephyr WindowGram
 * client.
 *
 *      Created by:     Marc Horowitz <marc@athena.mit.edu>
 *
 *      $Source$
 *      $Author$
 *
 *      Copyright (c) 1989 by the Massachusetts Institute of Technology.
 *      For copying and distribution information, see the file
 *      "mit-copyright.h".
 */

#if (!defined(lint) && !defined(SABER))
static char rcsid_xrevstack_c[] = "$Id$";
#endif

#include <zephyr/mit-copyright.h>

#ifdef REVSTACK
#include "X_gram.h"
#include <stdio.h>

x_gram *bottom_gram = NULL;
int reverse_stack = 0;

void add_to_bottom(gram)
     x_gram *gram;
{
   if (bottom_gram) {
      bottom_gram->below = gram;
      gram->below = NULL;
      gram->above = bottom_gram;
      bottom_gram = gram;
   } else {
      gram->above = NULL;
      gram->below = NULL;
      bottom_gram = gram;
   }
}

/*ARGSUSED*/
void pull_to_top(gram)
     x_gram *gram;
{}

/*ARGSUSED*/
void push_to_bottom(gram)
     x_gram *gram;
{}

void delete_gram(gram)
     x_gram *gram;
{
   if (gram == bottom_gram) {
      if (gram->above) {
	 bottom_gram = gram->above;
	 bottom_gram->below = NULL;
      } else {
	 bottom_gram = NULL;
      }
   } else {
      if (gram->above)
	gram->above->below = gram->below;
      gram->below->above = gram->above;     
   }
}

#endif

#ifdef TRUEREVSTACK

#include "X_gram.h"
#include "zwgc.h"
#include <stdio.h>

x_gram *bottom_gram=NULL;
static x_gram *top_gram=NULL;

#ifdef DEBUG
void print_gram_list(str)
char *str;
{
   x_gram *gram;
   char buf[80];

   if (zwgc_debug) {
      printf("----- From function %s: Top of tree\n",str);
      if (top_gram) 
	if (top_gram->above) 
	  printf("Tree munged: something above top_gram\n");
      for (gram=top_gram;gram;gram=gram->below) {
	 strncpy(buf,gram->text,63);
	 buf[63]='\0';
	 printf("wid %lx txt: %s\n",(long) gram->w,buf);
      }
      if (bottom_gram) 
	if (bottom_gram->below) 
	  printf("Tree munged: something below bottom_gram\n");
      printf("----- Bottom of tree\n");
   }
}
#endif

void pull_to_top(gram)
x_gram *gram;
{
   if (gram==top_gram) {
      /* already here */
      return;
   } else if (top_gram==NULL) {
      /* no grams at all.  Make gram both top and bottom */
      top_gram=gram;
      bottom_gram=gram;
   } else if (gram==bottom_gram) {
      /* bottom gram is special case */
      bottom_gram=bottom_gram->above;
      bottom_gram->below=NULL;
      top_gram->above=gram;
      gram->below=top_gram;
      top_gram=gram;
   } else {
      /* normal case of a gram in the middle */
      gram->above->below=gram->below;
      gram->below->above=gram->above;
      top_gram->above=gram;
      gram->below=top_gram;
      gram->above=NULL;
      top_gram=gram;
   }
#ifdef DEBUG
   print_gram_list("pull_to_top");
#endif
}

void push_to_bottom(gram)
x_gram *gram;
{
   if (gram==bottom_gram) {
      /* already here */
      return;
   } else if (bottom_gram==NULL) {
      /* no grams at all.  Make gram both top and bottom */
      gram->above=NULL;
      gram->below=NULL;
      top_gram=gram;
      bottom_gram=gram;
   } else if (gram==top_gram) {
      /* top gram is special case */
      top_gram=top_gram->below;
      top_gram->above=NULL;
      bottom_gram->below=gram;
      gram->above=bottom_gram;
      bottom_gram=gram;
   } else {
      /* normal case of a gram in the middle */
      gram->above->below=gram->below;
      gram->below->above=gram->above;
      bottom_gram->below=gram;
      gram->above=bottom_gram;
      gram->below=NULL;
      bottom_gram=gram;
   }
#ifdef DEBUG
   print_gram_list("push_to_bottom");
#endif
}

void unlink_gram(gram)
x_gram *gram;
{
   if (top_gram==bottom_gram) {
      /* the only gram in the stack */
      top_gram=NULL;
      bottom_gram=NULL;
   } else if (gram==top_gram) {
      top_gram=gram->below;
      top_gram->above=NULL;
   } else if (gram==bottom_gram) {
      bottom_gram=gram->above;
      bottom_gram->below=NULL;
   } else {
      gram->above->below=gram->below;
      gram->below->above=gram->above;
   }
#ifdef DEBUG
   print_gram_list("unlink_gram");
#endif
}

#ifdef notdef
void add_to_top(gram)
x_gram *gram;
{
   if (top_gram==NULL) {
      gram->above=NULL;
      gram->below=NULL;
      top_gram=gram;
      bottom_gram=gram;
   } else {
      top_gram->above=gram;
      gram->above=NULL;
      gram->below=top_gram;
      top_gram=gram;
   }
#ifdef DEBUG
   print_gram_list("add_to_top");
#endif
}
#endif

void add_to_bottom(gram)
x_gram *gram;
{
   if (bottom_gram==NULL) {
      gram->above=NULL;
      gram->below=NULL;
      top_gram=gram;
      bottom_gram=gram;
   } else {
      bottom_gram->below=gram;
      gram->above=bottom_gram;
      gram->below=NULL;
      bottom_gram=gram;
   }
#ifdef DEBUG
   print_gram_list("add_to_bottom");
#endif
}

#endif /* TRUEREVSTACK */
