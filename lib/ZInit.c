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
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <config.h>
#ifdef HAVE_SYS_SOCKIO_H
#include <sys/sockio.h>
#endif
#ifdef HAVE_IFADDRS_H
#include <ifaddrs.h>
#endif
#ifdef HAVE_NET_IF_H
#include <net/if.h>
#endif
#ifdef HAVE_KRB4
#include <krb_err.h>
#endif

#ifndef INADDR_NONE
#define INADDR_NONE 0xffffffff
#endif

Code_t ZInitialize()
{
    struct servent *hmserv;
    struct hostent *hostent;
    char hostname[MAXHOSTNAMELEN], *def;
    struct sockaddr_in sin;
    int s, sinsize = sizeof(sin);
    Code_t code;
    ZNotice_t notice;
    char *mp;
    int i;
#ifdef HAVE_KRB4
    char *krealm;
    initialize_krb_error_table();
#endif

    initialize_zeph_error_table();
    
    (void) memset((char *)&__HM_addr, 0, sizeof(__HM_addr));

    __HM_addr.sin_family = AF_INET;
#ifdef HAVE_SA_LEN
    __HM_addr.sin_len = sizeof (struct sockaddr_in);
#endif
    __HM_addr.sin_addr.s_addr = htonl (0x7f000001L);

    hmserv = (struct servent *)getservbyname(HM_SVCNAME, "udp");
    __HM_addr.sin_port = (hmserv) ? hmserv->s_port : HM_SVC_FALLBACK;

    /* Initialize the input queue */
    __Q_Tail = NULL;
    __Q_Head = NULL;
    
    /* if the application is a server, there might not be a zhm.  The
       code will fall back to something which might not be "right",
       but this is is ok, since none of the servers call krb_rd_req. */

    if (! __Zephyr_server) {
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

       /* if this is an old zhm, i will be 10, and __ngalaxies will be 0 */

       __ngalaxies = i/12;	/* XXX should be a defined constant */

       if (__ngalaxies == 0) {
	   char galaxy_config[1024];

	   __ngalaxies = 1;
	   __galaxy_list = (Z_GalaxyList *) malloc(sizeof(Z_GalaxyList)*1);

	   /* we're talking to an old zhm.  Use the one server name we get
	      to figure out the krealm.  ZReceiveNotice() knows this case,
	      and will always assume the current/only galaxy. */

	   strcpy(galaxy_config, "local-galaxy hostlist ");
	   strcat(galaxy_config, notice.z_message);

	   if ((code =
		Z_ParseGalaxyConfig(galaxy_config,
				    &__galaxy_list[0].galaxy_config))
	       != ZERR_NONE) {
	       __ngalaxies = 0;
	       free(__galaxy_list);
	       return(code);
	   }

#ifdef HAVE_KRB4
	   krealm = krb_realmofhost(__galaxy_list[0].galaxy_config.server_list[0].name);
	   if (!krealm)
	       krealm = "";

	   strcpy(__galaxy_list[0].krealm, krealm);
		  
	   __galaxy_list[0].last_authent_time = 0;
#endif
       } else {
	   __galaxy_list = (Z_GalaxyList *) malloc(sizeof(Z_GalaxyList)*__ngalaxies);
	   for (i=0, mp = notice.z_message;
		mp<notice.z_message+notice.z_message_len;
		i++, mp += strlen(mp)+1) {
	       if (i%12 == 11) {
		   if ((code =
			Z_ParseGalaxyConfig(mp,
					    &__galaxy_list[i/12].galaxy_config))
		       != ZERR_NONE) {
		       __ngalaxies = i/12;
		       for (i=0; i<__ngalaxies; i++)
			   Z_FreeGalaxyConfig(&__galaxy_list[i].galaxy_config);
		       free(__galaxy_list);
		       return(code);
		   }

#ifdef HAVE_KRB4
		   krealm = krb_realmofhost(__galaxy_list[i/12].galaxy_config.server_list[0].name);
		   if (!krealm)
		       krealm = "";

		   strcpy(__galaxy_list[i/12].krealm, krealm);

		   __galaxy_list[i/12].last_authent_time = 0;
#endif
	       }
	   }
       }

       ZFreeNotice(&notice);

       __default_galaxy = 0;

       if (def = ZGetVariable("defaultgalaxy")) {
	   for (i=0; i<__ngalaxies; i++) {
	       if (strcasecmp(__galaxy_list[i].galaxy_config.galaxy,
			      def) == 0) {
		   __default_galaxy = i;
		   break;
	       }
	   }
       }
    } else {
	__galaxy_list = 0;
	__ngalaxies = 0;
	__default_galaxy = 0;
    }

    /* Get the sender so we can cache it */
    (void) ZGetSender();

    return (ZERR_NONE);
}

