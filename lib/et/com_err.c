/*
 * Copyright 1987, 1988 by MIT Student Information Processing Board.
 *
 * For copyright info, see mit-sipb-copyright.h.
 */

#include <stdio.h>
#include <sysdep.h>
#include "mit-sipb-copyright.h"
#include "error_table.h"

#ifndef HAVE_VPRINTF
/* We don't have the v*printf routines... */
#define vfprintf(stream,fmt,args) _doprnt(fmt,args,stream)
#endif

/*
 * Protect us from header version (externally visible) of com_err, so
 * we can survive in a <varargs.h> environment.  I think.
 */
#define com_err com_err_external
#include "com_err.h"
#undef com_err

#if ! lint
static const char rcsid[] =
    "$Header$";
#endif	/* ! lint */

static void
default_com_err_proc (whoami, code, fmt, args)
    const char *whoami;
    long code;
    const char *fmt;
    va_list args;
{
    char buf[25];

    if (whoami) {
	fputs(whoami, stderr);
	fputs(": ", stderr);
    }
    if (code) {
	fputs(error_message_r(code, buf), stderr);
	fputs(" ", stderr);
    }
    if (fmt) {
        vfprintf (stderr, fmt, args);
    }
    /* should do \r only on a tty in raw mode, but it won't hurt */
    putc('\r', stderr);
    putc('\n', stderr);
    fflush(stderr);
}

error_handler_t com_err_hook = default_com_err_proc;

void com_err_va (whoami, code, fmt, args)
    const char *whoami;
    long code;
    const char *fmt;
    va_list args;
{
    (*com_err_hook) (whoami, code, fmt, args);
}

#ifdef __STDC__
void com_err (const char *whoami,
	      long code,
	      const char *fmt, ...)
{
#else
void com_err (whoami, code, fmt, va_alist)
    const char *whoami, *fmt;
    long code;
    va_dcl
{
#endif
    va_list pvar;

    VA_START(pvar, fmt);
    com_err_va (whoami, code, fmt, pvar);
    va_end(pvar);
}

error_handler_t set_com_err_hook (new_proc)
    error_handler_t new_proc;
{
    error_handler_t x = com_err_hook;

    if (new_proc)
	com_err_hook = new_proc;
    else
	com_err_hook = default_com_err_proc;

    return x;
}

error_handler_t reset_com_err_hook () {
    error_handler_t x = com_err_hook;
    com_err_hook = default_com_err_proc;
    return x;
}
