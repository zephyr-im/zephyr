/* This file is part of the Project Athena Zephyr Notification System.
 * It contains source for the ZInitialize function.
 *
 *	Created by:	Robert French
 *
 *	$Source$
 *	$Author$
 *
 *	Copyright (c) 1987, 1991 by the Massachusetts Institute of Technology.
 *	For copying and distribution information, see the file
 *	"mit-copyright.h". 
 */
/* $Header$ */

#ifndef lint
static char rcsid_ZInitialize_c[] =
    "$Zephyr: /afs/athena.mit.edu/astaff/project/zephyr/src/lib/RCS/ZInitialize.c,v 1.17 89/05/30 18:11:25 jtkohl Exp $";
#endif

#include <internal.h>

#include <sys/socket.h>
#ifdef ZEPHYR_USES_KERBEROS
#include <krb_err.h>
#endif

Code_t ZInitialize()
{
    struct servent *hmserv;
    char addr[4];
#ifdef ZEPHYR_USES_KERBEROS
    Code_t code;
    ZNotice_t notice;
    char *krealm;
    int krbval;
    char d1[ANAME_SZ], d2[INST_SZ];

    initialize_krb_error_table();
#endif

    initialize_zeph_error_table();
    
    (void) memset((char *)&__HM_addr, 0, sizeof(__HM_addr));

    __HM_addr.sin_family = AF_INET;

    /* Set up local loopback address for HostManager */
    addr[0] = 127;
    addr[1] = 0;
    addr[2] = 0;
    addr[3] = 1;

    hmserv = (struct servent *)getservbyname(HM_SVCNAME, "udp");
    __HM_addr.sin_port = (hmserv) ? hmserv->s_port : HM_SVC_FALLBACK;

    (void) memcpy((char *)&__HM_addr.sin_addr, addr, 4);

    __HM_set = 0;

    /* Initialize the input queue */
    __Q_Tail = NULL;
    __Q_Head = NULL;
    
#ifdef ZEPHYR_USES_KERBEROS
    if ((code = ZOpenPort(NULL)) != ZERR_NONE)
       return(code);

    if ((code = ZhmStat(NULL, &notice)) != ZERR_NONE)
       return(code);

    ZClosePort();

    /* the first field, which is NUL-terminated, is the server name.
       If this code ever support a multiplexing zhm, this will have to
       be made smarter, and probably per-message */

    krealm = krb_realmofhost(notice.z_message);

    ZFreeNotice(&notice);

    if (krealm) {
	strcpy(__Zephyr_realm, krealm);
    } else if ((krb_get_tf_fullname(TKT_FILE, d1, d2, __Zephyr_realm)
		!= KSUCCESS) &&
	       ((krbval = krb_get_lrealm(__Zephyr_realm, 1)) != KSUCCESS)) {
	return (krbval);
    }
#endif

    /* Get the sender so we can cache it */
    (void) ZGetSender();

    return (ZERR_NONE);
}

