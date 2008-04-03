/* This file is part of the Project Athena Zephyr Notification System.
 * It contains source for the ZInitialize function.
 *
 *	Created by:	Robert French
 *
 *	$Id$
 *
 *	Copyright (c) 1987, 1991 by the Massachusetts Institute of Technology.
 *	For copying and distribution information, see the file
 *	"mit-copyright.h". 
 */

#ifndef lint
static char rcsid_ZInitialize_c[] =
    "$Zephyr: /afs/athena.mit.edu/astaff/project/zephyr/src/lib/RCS/ZInitialize.c,v 1.17 89/05/30 18:11:25 jtkohl Exp $";
#endif

#include <internal.h>

#include <sys/socket.h>
#ifdef HAVE_KRB4
#include <krb_err.h>
#endif
#ifdef HAVE_KRB5
#include <krb5.h>
#endif
#ifdef HAVE_KRB5_ERR_H
#include <krb5_err.h>
#endif

#ifndef INADDR_NONE
#define INADDR_NONE 0xffffffff
#endif

Code_t ZInitialize()
{
    struct servent *hmserv;
    struct hostent *hostent;
    char addr[4], hostname[MAXHOSTNAMELEN];
    struct in_addr servaddr;
    struct sockaddr_in sin;
    int s, sinsize = sizeof(sin);
    Code_t code;
    ZNotice_t notice;
#ifdef HAVE_KRB5
    char **krealms = NULL;
#else
#ifdef HAVE_KRB4
    char *krealm = NULL;
    int krbval;
    char d1[ANAME_SZ], d2[INST_SZ];
#endif
#endif

#ifdef HAVE_KRB4
    initialize_krb_error_table();
#endif
#ifdef HAVE_KRB5
    initialize_krb5_error_table();
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
    
#ifdef HAVE_KRB5
    if ((code = krb5_init_context(&Z_krb5_ctx)))
        return(code);
#endif

    /* if the application is a server, there might not be a zhm.  The
       code will fall back to something which might not be "right",
       but this is is ok, since none of the servers call krb_rd_req. */

    servaddr.s_addr = INADDR_NONE;
    if (! __Zephyr_server) {
       if ((code = ZOpenPort(NULL)) != ZERR_NONE)
	  return(code);

       if ((code = ZhmStat(NULL, &notice)) != ZERR_NONE)
	  return(code);

       ZClosePort();

       /* the first field, which is NUL-terminated, is the server name.
	  If this code ever support a multiplexing zhm, this will have to
	  be made smarter, and probably per-message */

#ifdef HAVE_KRB5
       code = krb5_get_host_realm(Z_krb5_ctx, notice.z_message, &krealms);
       if (code)
	 return(code);
#else
#ifdef HAVE_KRB4
       krealm = krb_realmofhost(notice.z_message);
#endif
#endif
       hostent = gethostbyname(notice.z_message);
       if (hostent && hostent->h_addrtype == AF_INET)
	   memcpy(&servaddr, hostent->h_addr, sizeof(servaddr));

       ZFreeNotice(&notice);
    }

#ifdef HAVE_KRB5
    if (krealms) {
      strcpy(__Zephyr_realm, krealms[0]);
      krb5_free_host_realm(Z_krb5_ctx, krealms);
    } else {
      char *p; /* XXX define this somewhere portable */
      /* XXX check ticket file here */
      code = krb5_get_default_realm(Z_krb5_ctx, &p);
      strcpy(__Zephyr_realm, p);
#ifdef HAVE_KRB5_FREE_DEFAULT_REALM
      krb5_free_default_realm(Z_krb5_ctx, p);
#else
      free(p);
#endif
      if (code)
	return code;
    }
#else
#ifdef HAVE_KRB4
    if (krealm) {
	strcpy(__Zephyr_realm, krealm);
    } else if ((krb_get_tf_fullname(TKT_FILE, d1, d2, __Zephyr_realm)
		!= KSUCCESS) &&
	       ((krbval = krb_get_lrealm(__Zephyr_realm, 1)) != KSUCCESS)) {
	return (krbval);
    }
#else
    strcpy(__Zephyr_realm, "local-realm");
#endif
#endif

    __My_addr.s_addr = INADDR_NONE;
    if (servaddr.s_addr != INADDR_NONE) {
	/* Try to get the local interface address by connecting a UDP
	 * socket to the server address and getting the local address.
	 * Some broken operating systems (e.g. Solaris 2.0-2.5) yield
	 * INADDR_ANY (zero), so we have to check for that. */
	s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s != -1) {
	    memset(&sin, 0, sizeof(sin));
	    sin.sin_family = AF_INET;
	    memcpy(&sin.sin_addr, &servaddr, sizeof(servaddr));
	    sin.sin_port = HM_SRV_SVC_FALLBACK;
	    if (connect(s, (struct sockaddr *) &sin, sizeof(sin)) == 0
		&& getsockname(s, (struct sockaddr *) &sin, &sinsize) == 0
		&& sin.sin_addr.s_addr != 0)
		memcpy(&__My_addr, &sin.sin_addr, sizeof(__My_addr));
	    close(s);
	}
    }
    if (__My_addr.s_addr == INADDR_NONE) {
	/* We couldn't figure out the local interface address by the
	 * above method.  Try by resolving the local hostname.  (This
	 * is a pretty broken thing to do, and unfortunately what we
	 * always do on server machines.) */
	if (gethostname(hostname, sizeof(hostname)) == 0) {
	    hostent = gethostbyname(hostname);
	    if (hostent && hostent->h_addrtype == AF_INET)
		memcpy(&__My_addr, hostent->h_addr, sizeof(__My_addr));
	}
    }
    /* If the above methods failed, zero out __My_addr so things will
     * sort of kind of work. */
    if (__My_addr.s_addr == INADDR_NONE)
	__My_addr.s_addr = 0;

    /* Get the sender so we can cache it */
    (void) ZGetSender();

    return (ZERR_NONE);
}

