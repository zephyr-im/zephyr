/*
 * Copyright 1987, 1988, 1989 by MIT Student Information Processing
 * Board
 *
 * For copyright information, see copyright.h.
 */

#ifndef __STDC__
#define ss_error ss_error_external
#endif

#include "copyright.h"
#include "ss_internal.h"
#include <com_err.h>

#undef ss_error

char * ss_name(sci_idx)
    int sci_idx;
{
    register char *ret_val;
    register ss_data *infop;
    
    infop = ss_info(sci_idx);
    if (infop->current_request == (char const *)NULL) {
	ret_val = malloc((unsigned)
			 (strlen(infop->subsystem_name)+1)
			 * sizeof(char));
	if (ret_val == (char *)NULL)
	    return((char *)NULL);
	strcpy(ret_val, infop->subsystem_name);
	return(ret_val);
    }
    else {
	register char *cp;
	register char const *cp1;
	ret_val = malloc((unsigned)sizeof(char) * 
			 (strlen(infop->subsystem_name)+
			  strlen(infop->current_request)+
			  4));
	cp = ret_val;
	cp1 = infop->subsystem_name;
	while (*cp1)
	    *cp++ = *cp1++;
	*cp++ = ' ';
	*cp++ = '(';
	cp1 = infop->current_request;
	while (*cp1)
	    *cp++ = *cp1++;
	*cp++ = ')';
	*cp = '\0';
	return(ret_val);
    }
}

#ifdef __STDC__
void ss_error (int sci_idx, long code, const char * fmt, ...)
#else
void ss_error (sci_idx, code, fmt, va_alist)
    int sci_idx;
    long code;
    const char *fmt;
    va_dcl
#endif
{
    register char *whoami;
    va_list pvar;
    VA_START (pvar, fmt);
    whoami = ss_name (sci_idx);
    com_err_va (whoami, code, fmt, pvar);
    free (whoami);
    va_end(pvar);
}

void ss_perror (sci_idx, code, msg) /* for compatibility */
    int sci_idx;
    long code;
    char const *msg;
{
    ss_error (sci_idx, code, "%s", msg);
}
