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
#include <krb.h>
#include <krb_err.h>
#endif

Code_t ZInitialize()
{
    struct servent *hmserv;
    char addr[4];
    char *def;
#ifdef ZEPHYR_USES_KERBEROS
    Code_t code;
    ZNotice_t notice;
    char *mp;
    int i, krbval;
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

    /* Initialize the input queue */
    __Q_Tail = NULL;
    __Q_Head = NULL;
    
    /* if the application is a server, there might not be a zhm.  The
       code will fall back to something which might not be "right",
       but this is is ok, since none of the servers call krb_rd_req. */

    if (! __Zephyr_server) {
	char *mp;

	if ((code = ZOpenPort(NULL)) != ZERR_NONE)
	    return(code);

	if ((code = ZhmStat(NULL, &notice)) != ZERR_NONE)
	    return(code);

	ZClosePort();

	/* the first field, which is NUL-terminated, is the server name.
	   If this code ever support a multiplexing zhm, this will have to
	   be made smarter, and probably per-message */

       for (i=0, mp = notice.z_message;
	    mp<notice.z_message+notice.z_message_len;
	    i++, mp += strlen(mp)+1)
	   ;

       __nrealms = i/12;	/* XXX should be a constant */
       __realm_list = (Z_RealmList *) malloc(sizeof(Z_RealmList)*__nrealms);

       for (i=0, mp = notice.z_message;
	    mp<notice.z_message+notice.z_message_len;
	    i++, mp += strlen(mp)+1) {
	   if (i%12 == 11) {
	       if ((code =
		    Z_ParseRealmConfig(mp,&__realm_list[i/12].realm_config))
		   != ZERR_NONE) {
		   __nrealms = i/12;
		   for (i=0; i<__nrealms; i++)
		       Z_FreeRealmConfig(&__realm_list[i].realm_config);
		   free(__realm_list);
		   return(code);
	       }

#ifdef ZEPHYR_USES_KERBEROS
	       strcpy(__realm_list[i/12].krealm,
		      krb_realmofhost(__realm_list[i/12].realm_config.server_list[0].name));
	       __realm_list[i/12].last_authent_time = 0;
#endif
	   }
       }

       ZFreeNotice(&notice);

       __default_realm = 0;

       if (def = ZGetVariable("defaultrealm")) {
	   for (i=0; i<__nrealms; i++) {
	       if (strcasecmp(__realm_list[i].realm_config.realm, def) == 0) {
		   __default_realm = i;
		   break;
	       }
	   }
       }
    }

    /* Get the sender so we can cache it */
    (void) ZGetSender();

    return (ZERR_NONE);
}

