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
#include <iconv.h>
#include <errno.h>

const char *
ZGetCharsetString(char *charset)
{
    char *p;
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

    return charset;
}

unsigned short
ZGetCharset(char *charset)
{
    short retval;
	
    charset = (char *)ZGetCharsetString(charset);
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
    return "UNKNOWN";
}

Code_t
ZTransliterate(char *in, int inlen, char *inset, char *outset, char **out, int *outlen)
{
    iconv_t ih;
    char *outset_t, *inp, *outp;
    int retval;
    size_t size, inleft, outleft;

    *out = NULL;
    *outlen = 0;

    outset_t = malloc(strlen(outset) + 11);
    if (outset_t == NULL)
	return errno;
    sprintf(outset_t, "%s//TRANSLIT", outset);

    ih = iconv_open(outset_t, inset);

    free(outset_t);

    if (ih != (iconv_t)-1) {
	size = inlen; /* doubling this should be enough, but.. */
	do {
	    size = size * 2;
	    
	    *out = malloc(size);
	    if (*out == NULL) {
		iconv_close(ih);
		return errno;
	    }
	    
	    inleft = inlen;
	    outleft = size;
	    
	    inp = in;
	    outp = *out;
	    
	    retval = iconv(ih, &inp, &inleft, &outp, &outleft);
	    if (retval < 0)
		free(*out);
	} while (retval < 0 && errno == E2BIG);

	iconv_close(ih);
    }

    if (ih == (iconv_t)-1 || retval < 0)
	return errno;

    *outlen = size - outleft;

    return ZERR_NONE;
}
