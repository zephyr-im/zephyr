/* This file is part of the Project Athena Zephyr Notification System.
 * It contains source for the ZGetCharset function.
 *
 *	Created by:	Karl Ramm
 *
 *	$Id$
 *
 *	Copyright (c) 2009 by the Massachusetts Institute of Technology.
 *	For copying and distribution information, see the file
 *	"mit-copyright.h". 
 */

#ifndef lint
static const char rcsid_charset_c[] = "$Id$";
#endif /* lint */

#include <internal.h>
#include <string.h>
#include <locale.h>
#include <langinfo.h>
#include <ctype.h>

unsigned short
ZGetCharset(char *charset)
{
    char *p;
    short retval;
    static int once = 1;
	
    if (charset == NULL)
	charset = getenv("ZEPHYR_CHARSET");

    if (charset == NULL) {
	if (once) {
	    setlocale(LC_ALL, "");
	    once = 0;
	}
	charset = nl_langinfo(CODESET);
    }

    if (charset == NULL)
	return ZCHARSET_UNKNOWN;

    charset = strdup(charset);

    for (p = charset; *p; p++)
	*p = toupper(*p);

    if (!strcmp(charset, "NONE") || !strcmp(charset, "UNKNOWN"))
	retval = ZCHARSET_UNKNOWN;
    else if (!strcmp(charset, "ANSI_X3.4-1968"))
	retval = ZCHARSET_ISO_8859_1; /* A hack. */
    else if (!strcmp(charset, "ISO-8859-1"))
	retval = ZCHARSET_ISO_8859_1;
    else if (!strcmp(charset, "UTF-8"))
	retval = ZCHARSET_UTF_8;
    else
	retval = ZCHARSET_UNKNOWN;

    free(charset);
    return retval;
}

const char *
ZCharsetToString(unsigned short charset)
{
    if (charset == ZCHARSET_UNKNOWN)
	return "UNKNOWN";
    else if (charset == ZCHARSET_ISO_8859_1)
	return "ISO-8859-1";
    else if (charset == ZCHARSET_UTF_8)
	return "UTF-8";
}
	
