/* This file is part of the Project Athena Zephyr Notification System.
 * It contains source for the ZGetVariable, ZSetVariable, and ZUnsetVariable
 * functions.
 *
 *	Created by:	Robert French
 *
 *	$Id$
 *
 *	Copyright (c) 1987 by the Massachusetts Institute of Technology.
 *	For copying and distribution information, see the file
 *	"mit-copyright.h". 
 */

#ifndef lint
static const char rcsid_ZVariables_c[] = "$Id$";
#endif

#include <internal.h>

#include <ctype.h>
#include <pwd.h>

Code_t get_localvarfile(char *bfr);
static char *get_varval(char *fn, char *val);
static int varline(char *bfr, char *var);

char *
ZGetVariable(char *var)
{
    char varfile[128], *ret;
    Code_t code;

    code = get_localvarfile(varfile);
    if (code)
	return ((char *)0);

    if ((ret = get_varval(varfile, var)) != ZERR_NONE)
	return (ret);

    sprintf(varfile, "%s/zephyr/zephyr.vars", SYSCONFDIR);
    return (get_varval(varfile, var));
}

Code_t
ZSetVariable(char *var, char *value)
{
    int written;
    FILE *fpin, *fpout;
    char varfile[128], varfilebackup[128], varbfr[512];
    Code_t code;

    written = 0;

    code = get_localvarfile(varfile);
    if (code)
	return code;

    (void) strcpy(varfilebackup, varfile);
    (void) strcat(varfilebackup, ".backup");
	
    if (!(fpout = fopen(varfilebackup, "w")))
	return (errno);
    if ((fpin = fopen(varfile, "r")) != NULL) {
	while (fgets(varbfr, sizeof varbfr, fpin) != (char *) 0) {
	    if (varbfr[strlen(varbfr)-1] < ' ')
		varbfr[strlen(varbfr)-1] = '\0';
	    if (varline(varbfr, var)) {
		fprintf(fpout, "%s = %s\n", var, value);
		written = 1;
	    }
	    else
		fprintf(fpout, "%s\n", varbfr);
	}
	(void) fclose(fpin);		/* don't care about errs on input */
    } 
    if (!written)
	fprintf(fpout, "%s = %s\n", var, value);
    if (fclose(fpout) == EOF)
	    return(EIO);		/* can't rely on errno */
    if (rename(varfilebackup, varfile))
	return (errno);
    return (ZERR_NONE);
}	

Code_t
ZUnsetVariable(char *var)
{
    FILE *fpin, *fpout;
    char varfile[128], varfilebackup[128], varbfr[512];
    Code_t code;

    code = get_localvarfile(varfile);
    if (code)
	return code;

    (void) strcpy(varfilebackup, varfile);
    (void) strcat(varfilebackup, ".backup");
	
    if (!(fpout = fopen(varfilebackup, "w")))
	return (errno);
    if ((fpin = fopen(varfile, "r")) != NULL) {
	while (fgets(varbfr, sizeof varbfr, fpin) != (char *) 0) {
	    if (varbfr[strlen(varbfr)-1] < ' ')
		varbfr[strlen(varbfr)-1] = '\0';
	    if (!varline(varbfr, var))
		fprintf(fpout, "%s\n", varbfr);
	}
	(void) fclose(fpin);		/* don't care about read close errs */
    } 
    if (fclose(fpout) == EOF)
	    return(EIO);		/* errno isn't reliable */
    if (rename(varfilebackup, varfile))
	return (errno);
    return (ZERR_NONE);
}	

Code_t
get_localvarfile(char *bfr)
{
    char *envptr;
    struct passwd *pwd;

    envptr = getenv("ZEPHYR_VARS");
    if (envptr)
    	(void) strcpy(bfr, envptr);
    else {
    	envptr = getenv("HOME");
	if (envptr)
	    (void) strcpy(bfr, envptr);
	else {
	    if (!(pwd = getpwuid((int) getuid())))
		return errno;
	    (void) strcpy(bfr, pwd->pw_dir);
	}

	(void) strcat(bfr, "/");
	(void) strcat(bfr, ".zephyr.vars");
    }
    return (0);
} 
	
static char *
get_varval(char *fn, char *var)
{
    FILE *fp;
    static char varbfr[512];
    int i;
	
    fp = fopen(fn, "r");
    if (!fp)
	return ((char *)0);

    while (fgets(varbfr, sizeof varbfr, fp) != (char *) 0) {
	if (varbfr[strlen(varbfr)-1] < ' ')
	    varbfr[strlen(varbfr)-1] = '\0';
	if (!(i = varline(varbfr, var)))
	    continue;
	(void) fclose(fp);		/* open read-only, don't care */
	return (varbfr+i);
    }
    (void) fclose(fp);			/* open read-only, don't care */
    return ((char *)0);
}

/* If the variable in the line bfr[] is the same as var, return index to
   the variable value, else return 0. */
static int
varline(char *bfr, char *var)
{
    register char *cp;
	

    if (!bfr[0] || bfr[0] == '#')	/* comment or null line */
	return (0);
	
    cp = bfr;
    while (*cp && !isspace(*cp) && (*cp != '='))
	cp++;

#define max(a,b) ((a > b) ? (a) : (b))

    if (strncasecmp(bfr, var, max(strlen(var),cp - bfr)))
	return(0);			/* var is not the var in
					   bfr ==> no match */

    cp = strchr(bfr, '=');
    if (!cp)
	return(0);
    cp++;
    while (*cp && isspace(*cp))		/* space up to variable value */
	cp++;

    return (cp - bfr);			/* return index */
}
