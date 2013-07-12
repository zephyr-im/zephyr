/* This file is part of the Project Athena Zephyr Notification System.
 * It contains source for the ZGetSender.c function.
 *
 *	Created by:	Robert French
 *
 *	$Id$
 *
 *	Copyright (c) 1987, 1991 by the Massachusetts Institute of Technology.
 *	For copying and distribution information, see the file
 *	"mit-copyright.h". 
 */

#include <internal.h>

#ifndef lint
static const char rcsid_ZGetSender_c[] =
    "$Id$";
#endif

#include <pwd.h>

char *
ZGetSender(void)
{
    struct passwd *pw;
    static char *sender = NULL;
#ifdef HAVE_KRB5
    krb5_ccache ccache;
    krb5_principal principal;
    char *prname;
    int result;
#else    
#ifdef HAVE_KRB4
    char pname[ANAME_SZ], pinst[INST_SZ], prealm[REALM_SZ];
#endif 
#endif

    /* Return it if already cached */
    if (sender)
	return (sender);

#ifdef HAVE_KRB5
    result = krb5_cc_default(Z_krb5_ctx, &ccache);
    if (!result) {
      result = krb5_cc_get_principal(Z_krb5_ctx, ccache, &principal);
      if (!result) {
	krb5_unparse_name(Z_krb5_ctx, principal, &prname);
	sender = strdup(prname);
	krb5_free_unparsed_name(Z_krb5_ctx, prname);
	krb5_free_principal(Z_krb5_ctx, principal);
	return sender;
      }
      krb5_cc_close(Z_krb5_ctx, ccache);
    } 
#else
#ifdef HAVE_KRB4
    if (krb_get_tf_fullname((char *)TKT_FILE, pname, pinst, prealm) == KSUCCESS)
    {
        sender = malloc(ANAME_SZ+INST_SZ+REALM_SZ+3);
	if (sender)
	  (void) sprintf(sender, "%s%s%s@%s", pname, (pinst[0]?".":""),
			 pinst, prealm);
	return (sender);
    }
#endif
#endif

    /* XXX a uid_t is a u_short (now),  but getpwuid
     * wants an int. AARGH! */
    pw = getpwuid((int) getuid());
    if (!pw)
	return ("unknown");
    sender = malloc(strlen(pw->pw_name) + strlen(__Zephyr_realm) + 2);
    if (sender)
      (void) sprintf(sender, "%s@%s", pw->pw_name, __Zephyr_realm);
    return (sender);
}
