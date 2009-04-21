/* This file is part of the Project Athena Zephyr Notification System.
 * It is one of the source files comprising zwgc, the Zephyr WindowGram
 * client.
 *
 *      Created by:     Marc Horowitz <marc@athena.mit.edu>
 *
 *      $Id$
 *
 *      Copyright (c) 1989 by the Massachusetts Institute of Technology.
 *      For copying and distribution information, see the file
 *      "mit-copyright.h".
 */

#include <sysdep.h>

#if (!defined(lint) && !defined(SABER))
static const char rcsid_X_fonts_c[] = "$Id$";
#endif

#include <zephyr/mit-copyright.h>

/****************************************************************************/
/*                                                                          */
/*                          Code dealing with X fonts:                      */
/*                                                                          */
/****************************************************************************/

#ifndef X_DISPLAY_MISSING

#include "X_fonts.h"
#include "new_memory.h"
#include "new_string.h"
#include "error.h"
#include "pointer_dictionary.h"
#include "zwgc.h"

/*
 * font_dict - Lookup cache for fonts (the value pointers are XFontSet's)
 */

static pointer_dictionary family_dict = NULL;
static pointer_dictionary fontname_dict = NULL;
static pointer_dictionary fontst_dict = NULL;

/*
 * {face,size}_to_string - lookup tables for converting {face,size} int
 *                         constants to ascii strings:
 */

static string face_to_string[] = { "roman", "bold", "italic", "bolditalic" };
static string size_to_string[] = { "small", "medium", "large" };

static char *
get_family(char *style, char *substyle)
{
    char *desc;
    pointer_dictionary_binding *binding;
    int exists;
    char *family;
    
    desc=string_Concat("style.", style);
    desc=string_Concat2(desc, ".substyle.");
    desc=string_Concat2(desc, substyle);
    desc=string_Concat2(desc, ".fontfamily");
    
    if (!family_dict)
	family_dict = pointer_dictionary_Create(37);
    binding = pointer_dictionary_Define(family_dict, desc, &exists);
    
    if (exists) {
	free(desc);
	return((string) binding->value);
    } else {
        family = get_string_resource(desc,
                 "StyleKey.Style1.Style2.Style3.SubstyleKey.Substyle.FontfamilyKey");
	free(desc);
	if (family == NULL)
	    pointer_dictionary_Delete(family_dict, binding);
	else
	    binding->value = (pointer)family;
	return(family);  /* If resource returns NULL, return NULL also */
    }
}

static char *
get_specific_fontname(char *family,
                      int size,
                      int face)
{
    char *desc;
    pointer_dictionary_binding *binding;
    int exists;
    char *fontname;

    desc = string_Concat("fontfamily.", family);
    desc = string_Concat2(desc, ".");
    desc = string_Concat2(desc, size_to_string[size]);
    desc = string_Concat2(desc, ".");
    desc = string_Concat2(desc, face_to_string[face]);
    
    if (!fontname_dict)
	fontname_dict = pointer_dictionary_Create(37);
    binding = pointer_dictionary_Define(fontname_dict, desc, &exists);
    
    if (exists) {
	free(desc);
	return (string)binding->value;
    } else {
      fontname = get_string_resource(desc, "FontfamilyKey.Fontfamily.Size.Face");
      free(desc);
      if (fontname == NULL)
         pointer_dictionary_Delete(fontname_dict, binding);
      else
         binding->value = (pointer)fontname;
      return fontname;  /* If resource returns NULL, return NULL also */
   }
}

static XFontSet
get_fontst(Display *dpy, char *fontname)
{
   pointer_dictionary_binding *binding;
   int exists;
   XFontSet fontst;
   char **missing_list;
   int missing_count;
   char *def_string;

   if (!fontst_dict)
       fontst_dict = pointer_dictionary_Create(37);
   binding = pointer_dictionary_Define(fontst_dict, fontname, &exists);

   if (exists)
       return((XFontSet)binding->value);

   fontst = XCreateFontSet(dpy, fontname, &missing_list, &missing_count,
			   &def_string);
   XFreeStringList(missing_list);

   if (fontst == NULL)
       pointer_dictionary_Delete(fontst_dict,binding);
   else
       binding->value = (pointer)fontst;
   
   return(fontst);  /* If resource returns NULL, return NULL also */
}

static char *
get_fontname(char *family, int size, int face)
{
    char *fontname;

    fontname = get_specific_fontname(family, size, face);
    if (!fontname)
	fontname = get_specific_fontname(family, size, ROMAN_FACE);
    if (!fontname)
	fontname = get_specific_fontname(family, MEDIUM_SIZE, face);
    if (!fontname)
	fontname = get_specific_fontname(family, MEDIUM_SIZE, ROMAN_FACE);
    return(fontname);
}

static XFontSet
complete_get_fontst(Display *dpy,
                    string style,
                    string substyle,
                    int size,
                    int face)
{
    char *family, *fontname;
    XFontSet fontst;

    family = get_family(style, substyle);
    if (!family)
	return NULL;
    fontname = get_fontname(family, size, face);
    if (!fontname)
	return NULL;
    fontst = get_fontst(dpy, fontname);
    if (!fontst)
	return NULL;

    return fontst;
}

/*
 *    XFontSet get_font(string style, substyle; int size, face)
 *         Requires: size is one of SMALL_SIZE, MEDIUM_SIZE, LARGE_SIZE and
 *                   face is one of ROMAN_FACE, BOLD_FACE, ITALIC_FACE,
 *                   BOLDITALIC_FACE.
 *          Effects: unknown
 */

XFontSet
get_font(Display *dpy,
         string style,
         string substyle,
         int size,
         int face)
{
   char *family,*fontname;
   XFontSet fontst = NULL;

   if (size == SPECIAL_SIZE) {
       /* attempt to process @font explicitly */
       fontst = get_fontst(dpy, substyle);
   } else {
       family = get_family(style, substyle);

       if (family)
	   fontname = get_fontname(family, size, face);
       else
	   fontname = get_fontname(substyle, size, face);

       if (fontname) {
	   fontst = get_fontst(dpy, fontname);
	   if (fontst)
	       return fontst;
       }
       
       /* At this point, the no-failure case didn't happen, and the case
	  of substyle being the fontfamily didn't happen, either. */
       
       fontst = complete_get_fontst(dpy, style, "text", size, face);
       if (!fontst)
	   fontst = complete_get_fontst(dpy, "default", substyle, size, face);
       if (!fontst)
	   fontst = complete_get_fontst(dpy, "default", "text", size, face);
       if (!fontst) {
	   fontname = get_fontname("default", size, face);
	   if (fontname)
	       fontst = get_fontst(dpy, fontname);
       }
   }
   if (fontst)
       return fontst;
   
   /* If all else fails, try fixed */

   fontst = get_fontst(dpy, "fixed");
   
   if (fontst)
       return fontst;
   
   /* No fonts available.  Die. */
   
   ERROR("Unable to open font \"fixed\".  Aborting...");
#ifdef DEBUG
   abort();
#else
   exit(1);
#endif
}

#endif /* X_DISPLAY_MISSING */
