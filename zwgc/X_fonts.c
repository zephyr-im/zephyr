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
static char rcsid_X_fonts_c[] = "$Id$";
#endif

#include <zephyr/mit-copyright.h>

/****************************************************************************/
/*                                                                          */
/*                          Code dealing with X fonts:                      */
/*                                                                          */
/****************************************************************************/

#include <stdio.h>
#include "X_fonts.h"
#include "new_memory.h"
#include "new_string.h"
#include "error.h"
#include "pointer_dictionary.h"
#include "zwgc.h"

/*
 * font_dict - Lookup cache for fonts (the value pointers are XFontStruct *'s)
 */

static pointer_dictionary family_dict = NULL;
static pointer_dictionary fontname_dict = NULL;
static pointer_dictionary fontst_dict = NULL;
static pointer_dictionary fidst_dict = NULL;

/*
 * {face,size}_to_string - lookup tables for converting {face,size} int
 *                         constants to ascii strings:
 */

static string face_to_string[] = { "roman", "bold", "italic", "bolditalic" };
static string size_to_string[] = { "small", "medium", "large" };

extern char *get_string_resources();

static char *get_family(style,substyle)
     char *style;
     char *substyle;
{
   char *desc;
   pointer_dictionary_binding *binding;
   int exists;
   char *family;

   desc=string_Concat("style.",style);
   desc=string_Concat2(desc,".substyle.");
   desc=string_Concat2(desc,substyle);
   desc=string_Concat2(desc,".fontfamily");

   if (!family_dict)
      family_dict = pointer_dictionary_Create(37);
   binding = pointer_dictionary_Define(family_dict,desc,&exists);

   if (exists) {
      free(desc);
      return((string) binding->value);
   } else {
#define STYLE_CLASS "StyleKey.Style1.Style2.Style3.SubstyleKey.Substyle.FontfamilyKey"
      family=get_string_resource(desc,STYLE_CLASS);
#undef STYLE_CLASS
      free(desc);
      if (family==NULL)
	 pointer_dictionary_Delete(family_dict,binding);
      else
	 binding->value=(pointer) family;
      return(family);  /* If resource returns NULL, return NULL also */
   }
}

static char *get_specific_fontname(family,size,face)
     char *family;
     int size;
     int face;
{
   char *desc;
   pointer_dictionary_binding *binding;
   int exists;
   char *fontname;

   desc = string_Concat("fontfamily.",family);
   desc = string_Concat2(desc, ".");
   desc = string_Concat2(desc, size_to_string[size]);
   desc = string_Concat2(desc, ".");
   desc = string_Concat2(desc, face_to_string[face]);

   if (!fontname_dict)
      fontname_dict = pointer_dictionary_Create(37);
   binding = pointer_dictionary_Define(fontname_dict,desc,&exists);

   if (exists) {
      free(desc);
      return((string) binding->value);
   } else {
#define FAMILY_CLASS "FontfamilyKey.Fontfamily.Size.Face"
      fontname=get_string_resource(desc,FAMILY_CLASS);
      free(desc);
      if (fontname==NULL)
	 pointer_dictionary_Delete(fontname_dict,binding);
      else
	 binding->value=(pointer) fontname;
      return(fontname);  /* If resource returns NULL, return NULL also */
   }
}

/* fast function to convert Font to hex.  Return value
 * is on the heap and must be freed.  I'm cheating in
 * that I know that Font us really an unsigned long. */

static char hexdigits[] = {"0123456789ABCDEF"};
static char *Font_to_hex(num)
     Font num;
{
   char *temp;
   int i;

   temp=(char *) malloc((sizeof(Font)<<1)+1);

   for (i=0;i<((sizeof(Font)<<1)+1);i++)
      temp[i] = hexdigits[(num>>(i*4))&0x0f];
   temp[i] = '\0';

   return(temp);
}

void add_fid(font)
     XFontStruct *font;
{
   
   char *fidstr;
   pointer_dictionary_binding *binding;
   int exists;

   if (!fidst_dict)
      fidst_dict = pointer_dictionary_Create(37);
   fidstr=Font_to_hex(font->fid);
   binding = pointer_dictionary_Define(fidst_dict,fidstr,&exists);
   free(fidstr);

   if (!exists)
      binding->value=(pointer) font;
}

/* requires that the font already be cached. */
XFontStruct *get_fontst_from_fid(fid)
     Font fid;
{
   char *fidstr;
   pointer_dictionary_binding *binding;
   int exists;

   fidstr=Font_to_hex(fid);

   binding = pointer_dictionary_Define(fidst_dict,fidstr,&exists);
   free(fidstr);
#ifdef DEBUG
   if (exists) {
      return((XFontStruct *) binding->value);
   } else {
      printf("Font fid=0x%s not cached.  Oops.\n",fidstr);
      abort();
   }
#else
   return((XFontStruct *) binding->value);
#endif
}

static XFontStruct *get_fontst(dpy,fontname)
     Display *dpy;
     char *fontname;
{
   pointer_dictionary_binding *binding;
   int exists;
   XFontStruct *fontst;

   if (!fontst_dict)
      fontst_dict = pointer_dictionary_Create(37);
   binding = pointer_dictionary_Define(fontst_dict,fontname,&exists);

   if (exists) {
      return((XFontStruct *) binding->value);
   } else {
      fontst=XLoadQueryFont(dpy,fontname);
      if (fontst==NULL) {
	 pointer_dictionary_Delete(fontst_dict,binding);
      } else {
	 binding->value=(pointer) fontst;
	 add_fid(fontst);
      } return(fontst);  /* If resource returns NULL, return NULL also */
   }
}

static char *get_fontname(family,size,face)
     char *family;
     int size;
     int face;
{
   char *fontname;

   if (!(fontname=get_specific_fontname(family,size,face)))
    if (!(fontname=get_specific_fontname(family,size,ROMAN_FACE)))
     if (!(fontname=get_specific_fontname(family,MEDIUM_SIZE,face)))
      fontname=get_specific_fontname(family,MEDIUM_SIZE,ROMAN_FACE);
   return(fontname);
}

static XFontStruct *complete_get_fontst(dpy,style,substyle,size,face)
     Display *dpy;
     string style;
     string substyle;
     int size;
     int face;
{
   char *family,*fontname;
   XFontStruct *fontst;

   if (family=get_family(style,substyle))
     if (fontname=get_fontname(family,size,face))
       if (fontst=get_fontst(dpy,fontname))
	 return(fontst);
   /* If any part fails, */
   return(NULL);
}

/*
 *    XFontStruct *get_font(string style, substyle; int size, face)
 *         Requires: size is one of SMALL_SIZE, MEDIUM_SIZE, LARGE_SIZE and
 *                   face is one of ROMAN_FACE, BOLD_FACE, ITALIC_FACE,
 *                   BOLDITALIC_FACE.
 *          Effects: unknown
 */

XFontStruct *get_font(dpy,style,substyle,size,face)
     Display *dpy;
     string style;
     string substyle;
     int size;
     int face;
{
   char *family,*fontname;
   XFontStruct *fontst;

   if (size == SPECIAL_SIZE) {
      /* attempt to process @font explicitly */
      if (fontst=get_fontst(dpy,substyle))
	return(fontst);
   } else {
      if (family=get_family(style,substyle)) {
	 if (fontname=get_fontname(family,size,face))
	   if (fontst=get_fontst(dpy,fontname))
	     return(fontst);
      } else {
	 if (fontname=get_fontname(substyle,size,face))
	   if (fontst=get_fontst(dpy,fontname))
	     return(fontst);
      }

      /* At this point, the no-failure case didn't happen, and the case
      of substyle being the fontfamily didn't happen, either. */

      fontst=NULL;
      if (!(fontst=complete_get_fontst(dpy,style,"text",size,face)))
	if (!(fontst=complete_get_fontst(dpy,"default",substyle,size,face)))
	  if (!(fontst=complete_get_fontst(dpy,"default","text",size,face)))
	    if (fontname=get_fontname("default",size,face))
	      fontst=get_fontst(dpy,fontname);
      if (fontst) return(fontst);
   }

   /* If all else fails, try fixed */

   if (fontst=get_fontst(dpy,"fixed")) return(fontst);

   /* No fonts available.  Die. */

   ERROR("Unable to open font \"fixed\".  Aborting...");
#ifdef DEBUG
   abort();
#else
   exit(1);
#endif
}
