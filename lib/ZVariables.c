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
#endif lint

#include <zephyr/mit-copyright.h>

#include <zephyr/zephyr_internal.h>

#include <ctype.h>
#include <pwd.h>

#define _toupper(c) (islower(c)?toupper(c):c)

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

    strcpy(varfilebackup, varfile);
    strcat(varfilebackup, ".backup");
	
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
	fclose(fpin);
    } 
    if (!written)
	fprintf(fpout, "%s = %s\n", var, value);
    fclose(fpout);
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

    strcpy(varfilebackup, varfile);
    strcat(varfilebackup, ".backup");
	
    if (!(fpout = fopen(varfilebackup, "w")))
	return (errno);
    if (fpin = fopen(varfile, "r")) {
	while (fgets(varbfr, sizeof varbfr, fpin) != (char *) 0) {
	    if (varbfr[strlen(varbfr)-1] < ' ')
		varbfr[strlen(varbfr)-1] = '\0';
	    if (!varline(varbfr, var))
		fprintf(fpout, "%s\n", varbfr);
	}
	fclose(fpin);
    } 
    fclose(fpout);
    if (rename(varfilebackup, varfile))
	return (errno);
    return (ZERR_NONE);
}	

static get_localvarfile(bfr)
    char *bfr;
{
    char *envptr;
    struct passwd *pwd;

    envptr = (char *)getenv("HOME");
    if (envptr)
	strcpy(bfr, envptr);
    else {
	if (!(pwd = getpwuid(getuid()))) {
	    fprintf(stderr, "Zephyr internal failure: Can't find your entry in /etc/passwd\n");
	    return (1);
	}
	strcpy(bfr, pwd->pw_dir);
    }

    strcat(bfr, "/");
    strcat(bfr, ".zephyr.vars");
    return (0);
} 
	
static char *get_varval(fn, var)
    char *fn;
    char *var;
{
    FILE *fp;
    char varbfr[512];
    int i;
	
    fp = fopen(fn, "r");
    if (!fp)
	return ((char *)0);

    while (fgets(varbfr, sizeof varbfr, fp) != (char *) 0) {
	if (varbfr[strlen(varbfr)-1] < ' ')
	    varbfr[strlen(varbfr)-1] = '\0';
	if (!(i = varline(varbfr, var)))
	    continue;
	fclose(fp);
	return (varbfr+i);
    }
    fclose(fp);
    return ((char *)0);
}

static int varline(bfr, var)
    char *bfr;
    char *var;
{
    int i;
	
    if (!bfr[0] || bfr[0] == '#')
	return (0);
	
    for (i = 0; bfr[i] && !isspace(bfr[i]) &&
	 bfr[i] != '='; i++)
	if (_toupper(bfr[i]) != _toupper(var[i]))
	    break;
    if ((!bfr[i] || !isspace(bfr[i])) && bfr[i] != '=')
	return (0);
    while (bfr[i] && isspace(bfr[i]))
	i++;
    if (bfr[i++] != '=')
	return (0);
    while (bfr[i] && isspace(bfr[i]))
	i++;
    return (i);
}
