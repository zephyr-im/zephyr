/* This file is part of the Project Athena Zephyr Notification System.
 * It contains functions for dealing with acl's.
 *
 *	Created by:	John T. Kohl
 *
 *	$Source$
 *	$Author$
 *
 *	Copyright (c) 1987 by the Massachusetts Institute of Technology.
 *	For copying and distribution information, see the file
 *	"mit-copyright.h". 
 */

#include <zephyr/mit-copyright.h>

#if !defined (lint) && !defined (SABER)
static char rcsid_access_c[] =
    "$Id$";
#endif

/*
 *
 * External routines:
 *
 * int access_check(notice, acl, accesstype)
 *    ZNotice_t *notice;
 *    ZAcl_t *acl;
 *    ZAccess_t accesstype;
 *
 * void access_init();
 *
 * void access_reinit();
 */

/*
 * Each restricted class has four ACL's associated with it,
 * governing subscriptions, transmission, and instance restrictions.
 * This module provides the 'glue' between the standard Athena ACL
 * routines and the support needed by the Zephyr server.
 */

#include <sys/param.h>

#include "zserver.h"

/*
 * Our private types for the acl_types field in the ZAcl_t structure.
 * 	-TYT 8/14/90
 */
#define ACL_XMT		1
#define ACL_SUB		2
#define ACL_IWS		4
#define ACL_IUI		8

#ifdef __STDC__
# define        P(s) s
#else
# define P(s) ()
#endif

static void check_acl P((ZAcl_t *acl));
static void check_acl_type P((ZAcl_t *acl, ZAccess_t accesstype,
			      int typeflag));
static void access_setup P((int first));

#undef P

/*
 * check access.  return 1 if ok, 0 if not ok.
 */

int
access_check(sender, acl, accesstype)
     char *sender;
     ZAcl_t *acl;
     ZAccess_t accesstype;
{
	char buf[MAXPATHLEN];		/* holds the real acl name */
	char *prefix;
	int	flag;
	int retval;

	switch (accesstype) {
	case TRANSMIT:
		prefix = "xmt";
		flag = ACL_XMT;
		break;
	case SUBSCRIBE:
		prefix = "sub";
		flag = ACL_SUB;
		break;
	case INSTWILD:
		prefix = "iws";
		flag = ACL_IWS;
		break;
	case INSTUID:
		prefix = "iui";
		flag = ACL_IUI;
		break;
	default:
		syslog(LOG_ERR, "unknown access type %d", (int) accesstype);
		return(0);
	}
	if (!(acl->acl_types) & flag) /* no acl ==> no restriction
				        ==> thumbs up */
		return (1);
	(void) sprintf(buf, "%s%s-%s.acl", 
		       ZEPHYR_ACL_DIR,
		       prefix,
		       acl->acl_filename);
	/*
	 * If we can't load it (because it probably doesn't exist),
	 * we deny access.
	 */
#if 0
	zdbug ((LOG_DEBUG, "checking %s for %s", buf, sender));
#endif
	
	retval = acl_load(buf);
	if (retval < 0) {
	  syslog(LOG_DEBUG, "Error in acl_load of %s for %s", buf, sender);
	  return(0);
	}
	return (acl_check(buf, sender));
}

static void
check_acl(acl)
     ZAcl_t *acl;
{
  acl->acl_types = 0;
  check_acl_type (acl, TRANSMIT, ACL_XMT);
  check_acl_type (acl, SUBSCRIBE, ACL_SUB);
  check_acl_type (acl, INSTWILD, ACL_IWS);
  check_acl_type (acl, INSTUID, ACL_IUI);
}

static void
check_acl_type(acl, accesstype, typeflag)
     ZAcl_t *acl;
     ZAccess_t accesstype;
     int typeflag;
{
  char 	buf[MAXPATHLEN];		/* holds the real acl name */
  char	*prefix;

  switch (accesstype) {
  case TRANSMIT:
    prefix = "xmt";
    break;
  case SUBSCRIBE:
    prefix = "sub";
    break;
  case INSTWILD:
    prefix = "iws";
    break;
  case INSTUID:
    prefix = "iui";
    break;
  default:
    syslog(LOG_ERR, "unknown access type %d", (int) accesstype);
    return;
  }
  (void) sprintf(buf, "%s%s-%s.acl", 
		 ZEPHYR_ACL_DIR,
		 prefix,
		 acl->acl_filename);
  if (!access(buf, F_OK))
    acl->acl_types |= typeflag;
}
  

/*
 * Re-init code written by TYT, 8/14/90.
 *
 * General plan of action; we reread the registry list, and add any
 * new restricted classes.  If any restricted classes disappear (this
 * should be rarely) the ZAcl_t structure is not deallocated; rather,
 * the acl_types field will be left at zero, since there will be no
 * acl files for the (non-)restricted class.
 */

static void
access_setup (int first)
{
	char buf[MAXPATHLEN];
	char class_name[512];		/* assume class names <= 511 bytes */
	FILE *registry;
	ZAcl_t *acl;
	register int len;
	register char *colon_idx;
	Code_t retval = 0;

	(void) sprintf(buf, "%s%s", ZEPHYR_ACL_DIR, ZEPHYR_CLASS_REGISTRY);
	
	if ((registry = fopen(buf, "r")) == (FILE *) NULL) {
		syslog(LOG_ERR, "no registry available, all classes are free");
		return;
	}
	while (fgets(class_name, 512, registry) != NULL) {
		if ((colon_idx = (char *) index(class_name, ':')) != NULL)
		    *colon_idx = '\0';
		else if ((len = strlen(class_name)) != 0)
		    class_name[len - 1] = '\0';
		acl = 0;
		if (!first) {
		  ZSTRING *z;
		  z = make_zstring(class_name,1);
		  acl = class_get_acl(z);
		  free_zstring(z);
		}
		if (!acl) {
		    acl = (ZAcl_t *) xmalloc(sizeof(ZAcl_t));
		    if (!acl) {
			syslog(LOG_ERR, "no mem acl alloc");
			abort();
		    }
		    acl->acl_filename = strsave(class_name);
		    check_acl(acl);
		    
		    if (!first) {
			/* Try to restrict already existing class */
			retval = class_restrict (class_name, acl);
			if (retval == ZSRV_NOCLASS)
			    retval = class_setup_restricted (class_name, acl);
		    }
		    else
			retval = class_setup_restricted (class_name, acl);
		}
		if (retval) {
		    syslog(LOG_ERR, "can't restrict %s: %s",
			   class_name, error_message(retval));
		    continue;
		}
		zdbug((LOG_DEBUG, "restricted %s", class_name));
	}
	(void) fclose(registry);

	return;
}

void
access_init (void)
{
    access_setup (1);
}

void
access_reinit (void)
{
    acl_cache_reset ();
    access_setup (0);
}
