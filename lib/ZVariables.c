/* This file is part of the Project Athena Zephyr Notification System.
 * It contains source for the ZGetVariable, ZSetVariable, and ZUnsetVariable
 * functions.
 *
 *	Created by:	Robert French
 *
 *	$Source$
 *	$Author$
 *
 *	Copyright (c) 1987 by the Massachusetts Institute of Technology.
 *	For copying and distribution information, see the file
 *	"mit-copyright.h". 
 */
/* $Header$ */

#ifndef lint
static char rcsid_ZVariables_c[] = "$Header$";
#endif

#include <zephyr/mit-copyright.h>

#include <zephyr/zephyr_internal.h>

#include <ctype.h>
#include <pwd.h>

extern char *getenv();
extern uid_t getuid();

static int get_localvarfile();
static char *get_varval();
static int varline();

char *ZGetVariable(var)
    char *var;
{
    char varfile[128], *ret;
    char *get_varval();

    if (get_localvarfile(varfile))
	return ((char *)0);

    if (ret = get_varval(varfile, var))
	return (ret);

    return (get_varval(DEFAULT_VARS_FILE, var));
}

Code_t ZSetVariable(var, value)
    char *var;
    char *value;
{
    int written;
    FILE *fpin, *fpout;
    char varfile[128], varfilebackup[128], varbfr[512];

    written = 0;
	
    if (get_localvarfile(varfile))
	return (ZERR_INTERNAL);

    (void) strcpy(varfilebackup, varfile);
    (void) strcat(varfilebackup, ".backup");
	
    if (!(fpout = fopen(varfilebackup, "w")))
	return (errno);
    if (fpin = fopen(varfile, "r")) {
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

Code_t ZUnsetVariable(var)
    char *var;
{
    FILE *fpin, *fpout;
    char varfile[128], varfilebackup[128], varbfr[512];

    if (get_localvarfile(varfile))
	return (ZERR_INTERNAL);

    (void) strcpy(varfilebackup, varfile);
    (void) strcat(varfilebackup, ".backup");
	
    if (!(fpout = fopen(varfilebackup, "w")))
	return (errno);
    if (fpin = fopen(varfile, "r")) {
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

static get_localvarfile(bfr)
    char *bfr;
{
    char *envptr;
    struct passwd *pwd;

    envptr = getenv("HOME");
    if (envptr)
	(void) strcpy(bfr, envptr);
    else {
	if (!(pwd = getpwuid((int) getuid()))) {
	    fprintf(stderr, "Zephyr internal failure: Can't find your entry in /etc/passwd\n");
	    return (1);
	}
	(void) strcpy(bfr, pwd->pw_dir);
    }

    (void) strcat(bfr, "/");
    (void) strcat(bfr, ".zephyr.vars");
    return (0);
} 
	
static char *get_varval(fn, var)
    char *fn;
    char *var;
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
static int varline(bfr, var)
    char *bfr;
    char *var;
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
