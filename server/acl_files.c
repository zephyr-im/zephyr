/* This file is part of the Project Athena Zephyr Notification System.
 * It contains functions for maintaining Access Control Lists.
 *
 *	Created by:	John T. Kohl
 *
 *	$Id$
 *
 *	Copyright (c) 1987,1988 by the Massachusetts Institute of Technology.
 *	For copying and distribution information, see the file
 *	"mit-copyright.h". 
 */

/* Define this if you really want the ACL-writing code included.  */

/*
 * Stolen from lib/acl_files.c because acl_load needs to be externally
 * declared and not statically declared.
 */

#include <zephyr/mit-copyright.h>
#include "zserver.h"
#include <fnmatch.h>

#ifndef SABER
#ifndef lint
static const char rcsid_acl_files_c[] = "$Id$";
#endif /* lint */
#endif /* SABER */

/*** Routines for manipulating access control list files ***/

#define REALM_SEP '@'
#define ESCAPE '\\'

#define CACHED_ACLS 256		/* How many acls to cache */
#define ACL_LEN 256		/* Twice a reasonable acl length */

/* Eliminate all whitespace character in buf */
/* Modifies its argument */
static void
nuke_whitespace(char *buf)
{
    char *pin, *pout;

    for (pin = pout = buf; *pin != '\0'; pin++)
	if (!isspace(*pin)) *pout++ = *pin;
    *pout = '\0';		/* Terminate the string */
}

struct host_ace {
    struct host_ace *next;
    unsigned long addr, mask;
};

static int
add_host(struct host_ace **list,
	 char *buf)
{
    struct host_ace *e;
    struct in_addr addr;
    unsigned long mask = 0;
    long i;
    char *m, *x;

    m = strchr(buf, '/');
    if (m) {
	*(m++) = 0;
	if (!*m)
            return;
	i = strtol(m, &x, 10);
	if (*x || i < 0 || i > 32)
            return;
	while (i--)
	    mask = (mask >> 1) | 0x80000000;
    } else {
	mask = 0xffffffff;
    }

    if (!inet_aton(buf, &addr))
	return;

    e = (struct host_ace *)malloc(sizeof(struct host_ace));
    if (e == NULL)
        return errno;
    memset(e, 0, sizeof(struct host_ace));
    e->addr = addr.s_addr;
    e->mask = htonl(mask);
    e->next = *list;
    *list = e;

    return 0;
}

static void
destroy_hosts(struct host_ace **list)
{
    struct host_ace *e;

    while ((e = *list)) {
	*list = e->next;
	free(e);
    }
}

static char *
split_name(char *princ) {
    int i;
    int len = strlen(princ);

    for (i = 0; i < len && princ[i] != REALM_SEP; i++)
        if (princ[i] == ESCAPE && (i + 1) < len)
            i++;
    if (i != len) { /* yay found an @ */
        princ[i] = 0;
        return &princ[i + 1];
    }
    return &princ[i]; /* failure, just return a pointer empty string */
}

struct user_ace {
    struct user_ace *next;
    char *princ;
    char *realm;
};

static int
add_user(struct user_ace **list, char *princ) {
    struct user_ace *e;
    char *realm = split_name(princ);

    e = (struct user_ace *)malloc(sizeof(struct user_ace));
    if (e == NULL)
        return errno;
    memset(e, 0, sizeof(struct user_ace));

    if (!strcmp(princ, "*.*"))     /* #ifdef KRB4_COMPAT */
        e->princ = strdup("*");
    else                           /* #endif */
        e->princ = strdup(princ);
    if (e->princ == NULL) {
        free(e);
        return errno;
    }

    e->realm = strdup(realm);
    if (e->realm == NULL) {
        free(e->princ);
        free(e);
        return errno;
    }
    e->next = *list;
    *list = e;

    return 0;
}

static void
destroy_user(struct user_ace **list) {
    struct user_ace *e;
    while ((e = *list)) {
        *list = e->next;
        free(e->princ);
        free(e->realm);
        free(e);
    }
}

static int
check_user(struct user_ace *list, char *princ, char *realm) {
    struct user_ace *e;

    e = list;
    while (e) {
        if (fnmatch(e->princ, princ, 0) == 0
            && fnmatch(e->realm, realm, 0) == 0)
            return 1;
        e = e->next;
    }

    return 0;
}

struct acl {
    String *filename;	        /* Name of acl file */
    int loaded;
    struct user_ace *acl;       /* Positive acl entries */
    struct user_ace *negacl;    /* Negative acl entries */
    struct host_ace *hosts;     /* Positive host entries */
    struct host_ace *neghosts;  /* Negative host entries */
};

static struct acl acl_cache[CACHED_ACLS];

static int acl_cache_count = 0;
static int acl_cache_next = 0;

/* wipe an entry in the acl cache */
static void
destroy_acl(int i) {
    if (acl_cache[i].filename)
        free_string(acl_cache[i].filename);
    if (acl_cache[i].acl)
        destroy_user(&acl_cache[i].acl);
    if (acl_cache[i].negacl)
        destroy_user(&acl_cache[i].negacl);
    if (acl_cache[i].hosts)
        destroy_hosts(&acl_cache[i].hosts);
    if (acl_cache[i].neghosts)
        destroy_hosts(&acl_cache[i].neghosts);
    acl_cache[i].filename = NULL;
    acl_cache[i].acl = (struct user_ace *) 0;
    acl_cache[i].negacl = (struct user_ace *) 0;
    acl_cache[i].hosts = (struct host_ace *) 0;
    acl_cache[i].neghosts = (struct host_ace *) 0;
    acl_cache[i].loaded = 0;
}

/* Returns < 0 if unsuccessful in loading acl */
/* Returns index into acl_cache otherwise */
/* Note that if acl is already loaded, this is just a lookup */
int acl_load(char *name)
{
    int i;
    FILE *f;
    char buf[BUFSIZ];
    int ret = 0;
    String *interned_name;

    syslog(LOG_DEBUG, "acl_load(%s)", name);
    /* See if it's there already */
    interned_name = make_string(name, 0);
    for (i = 0; i < acl_cache_count; i++) {
	if (acl_cache[i].filename == interned_name)
	    goto got_it;
    }

    /* It isn't, load it in */
    /* maybe there's still room */
    if (acl_cache_count < CACHED_ACLS) {
	i = acl_cache_count++;
    } else {
	/* No room, clean one out */
	i = acl_cache_next;
	acl_cache_next = (acl_cache_next + 1) % CACHED_ACLS;
        destroy_acl(i);
    }

    /* Set up the acl */
    acl_cache[i].filename = interned_name;
    /* Force reload */
    acl_cache[i].loaded = 0;

  got_it:
    /*
     * See if we need to reload the ACL
     */
    if (!acl_cache[i].loaded) {
        syslog(LOG_DEBUG, "acl_load(%s) actually loading", name);
	/* Gotta reload */
	if ((f = fopen(name, "r")) == NULL) {
	    syslog(LOG_ERR, "Error loading acl file %s: %m", name);
	    return -errno;
	}
	if (acl_cache[i].acl)
            destroy_user(&acl_cache[i].acl);
	if (acl_cache[i].negacl)
            destroy_user(&acl_cache[i].negacl);
	acl_cache[i].acl = (struct user_ace *)0;
	acl_cache[i].negacl = (struct user_ace *)0;
	while(fgets(buf, sizeof(buf), f) != NULL && ret == 0) {
	    nuke_whitespace(buf);
            if (!buf[0])
                continue;
	    if (buf[0] == '!' && buf[1] == '@')
		ret = add_host(&acl_cache[i].neghosts, buf + 2);
	    else if (buf[0] == '@')
		ret = add_host(&acl_cache[i].hosts, buf + 1);
	    else if (buf[0] == '!')
		ret = add_user(&acl_cache[i].negacl, buf + 1);
	    else
		ret = add_user(&acl_cache[i].acl, buf);
	}
	fclose(f);
        if (ret) {
            destroy_acl(i);
            return -ret;
        }
        acl_cache[i].loaded = 1;
    }
    return i;
}

/*
 * This destroys all cached ACL's so that new ones will be loaded in
 * the next time they are requested.
 */
void
acl_cache_reset(void)
{
    int	i;

    syslog(LOG_DEBUG, "acl_cache_reset()");
    for (i = 0; i < acl_cache_count; i++)
        destroy_acl(i);
    acl_cache_count = 0;
    acl_cache_next = 0;
}

/* Returns nonzero if it can be determined that acl contains principal */
/* Principal is not canonicalized, and no wildcarding is done */
/* If neg is nonzero, we look for negative entries */
static int
acl_match(char *acl, char *princ, char *realm, int neg)
{
    int idx;

    if ((idx = acl_load(acl)) < 0)
        return 0;
    if (neg)
        return check_user(acl_cache[idx].negacl, princ, realm);
    else
        return check_user(acl_cache[idx].acl, princ, realm);
}

/* Returns nonzero if it can be determined that acl contains who */
/* If neg is nonzero, we look for negative entries */
static int
acl_host_match(char *acl,
               unsigned long who,
               int neg)
{
    int idx;
    struct host_ace *e;

    if ((idx = acl_load(acl)) < 0)
        return 0;
    e = neg ? acl_cache[idx].neghosts : acl_cache[idx].hosts;
    while (e) {
	if ((e->addr & e->mask) == (who & e->mask))
            return 1;
	e = e->next;
    }
    return 0;
}

/* Returns nonzero if it can be determined that acl contains principal */
/* Recognizes wildcards in acl. */
/* Also checks for IP address entries and applies negative ACL's */
static int
acl_check_internal(char *acl, char *princ, struct sockaddr_in *who)
{
    char *realm;
    int p, i, r, result = 0;

    if (princ) {
        realm = split_name(princ);

        if (acl_match(acl, princ, realm, 1))
            return 0;
        if (acl_match(acl, princ, realm, 0))
            result = 1;
    }

    if (who) {
	if (acl_host_match(acl, who->sin_addr.s_addr, 1))
            return 0;
	if (acl_host_match(acl, who->sin_addr.s_addr, 0))
            result = 1;
    }

    return result;
}

int acl_check(char *acl, char *name, struct sockaddr_in *who) {
    char *pname = strdup(name);
    int result;

    if (pname == NULL)
        return 0; /* oops */

    result = acl_check_internal(acl, pname, who);
    syslog(LOG_DEBUG, "acl_check(%s, %s, ?) = %d", acl, name, result);

    free(pname);

    return result;
}
