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
static char rcsid_X_fonts_h[] = "$Header$";
#endif

#include <zephyr/mit-copyright.h>

#ifndef x_fonts_MODULE
#define x_fonts_MODULE

#include "X_driver.h"

#define  SPECIAL_FACE     -1
#define  ROMAN_FACE        0
#define  BOLD_FACE         1
#define  ITALIC_FACE       2
#define  BOLD_ITALIC_FACE  3

#define  SPECIAL_SIZE     -1
#define  SMALL_SIZE        0
#define  MEDIUM_SIZE       1
#define  LARGE_SIZE        2

/*
 *    XFontStruct *get_font(string family; int size, face)
 *         Requires: size is one of SMALL_SIZE, MEDIUM_SIZE, LARGE_SIZE and
 *                   face is one of ROMAN_FACE, BOLD_FACE, ITALIC_FACE,
 *                   BOLDITALIC_FACE.
 *         Effects: Looks up the font specified by the above in the
 *                  X resources.  If that font is not specified by in
 *                  the X resources or it can't be loaded, the font
 *                  specified by default.medium.roman is used. <<<>>>
 */

extern XFontStruct *get_font();
extern XFontStruct *get_fontst_from_fid();

#endif
