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
