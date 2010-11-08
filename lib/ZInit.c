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
static const char rcsid_ZInitialize_c[] =
    "$Id$";
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

#if defined(HAVE_KRB5) && defined(KRB5_REFERRAL_REALM)
#include <profile.h>

static int z_get_host_realm_replacement(char *, char ***);
#endif

#if defined(HAVE_KRB5)
int Zauthtype = 5;
#elif defined(HAVE_KRB4)
int Zauthtype = 4;
#else
int Zauthtype = 0;
#endif

Code_t
ZInitialize(void)
{
    struct servent *hmserv;
    struct hostent *hostent;
    char addr[4], hostname[NS_MAXDNAME];
    struct in_addr servaddr;
    struct sockaddr_in sin;
    unsigned int s, sinsize = sizeof(sin);
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

    /* On OS X you don't need to initialize the Kerberos error tables
       as long as you link with -framework Kerberos */
#if !(defined(__APPLE__) && defined(__MACH__))
#ifdef HAVE_KRB4
    initialize_krb_error_table();
#endif
#ifdef HAVE_KRB5
    initialize_krb5_error_table();
#endif
#endif

#if defined(__APPLE__) && defined(__MACH__)
    add_error_table(&et_zeph_error_table);
#else
    initialize_zeph_error_table();
#endif

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
#ifndef KRB5_REFERRAL_REALM
       code = krb5_get_host_realm(Z_krb5_ctx, notice.z_message, &krealms);
       if (code)
	 return(code);
#else
       code = z_get_host_realm_replacement(notice.z_message, &krealms);
#endif
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
      if (code)
	return code;
      strcpy(__Zephyr_realm, p);
#ifdef HAVE_KRB5_FREE_DEFAULT_REALM
      krb5_free_default_realm(Z_krb5_ctx, p);
#else
      free(p);
#endif
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

const char * ZGetRealm (void) {
    return __Zephyr_realm;
}

int ZGetFD (void) {
    return __Zephyr_fd;
}

int ZQLength (void) {
    return __Q_CompleteLength;
}

struct sockaddr_in ZGetDestAddr (void) {
    return __HM_addr;
}

#if defined(HAVE_KRB5) && defined(KRB5_REFERRAL_REALM)
#include <ctype.h>
#include <netinet/in.h>
#include <resolv.h>

static int txt_lookup(char *qname, char **result) {
    int ret, buflen, left;
    void *buf = NULL;
    HEADER *hdr;
    unsigned char *p;
    char dname[NS_MAXDNAME];
    int queries, answers, stored;

    ret = res_init();
    if (ret < 0)
	return -1;

    buflen = 0;
    do {
	buflen = buflen ? buflen * 2 : 2048;
	buf = (buf == NULL) ? malloc(buflen) : realloc(buf, buflen);

	ret = res_search(qname, C_IN, T_TXT, buf, buflen);
    } while (ret > buflen);

    if (ret < 0)
	return -1;

    buflen = ret;
    left = ret;

    hdr = (HEADER *)buf;
    p = buf;
    queries = ntohs(hdr->qdcount);
    answers = ntohs(hdr->ancount);
    p += sizeof (HEADER);
    left -= sizeof (HEADER);

    while (queries--) {
	ret = dn_expand(buf, buf + buflen, p, dname, sizeof dname);
	if (ret < 0 || (ret + 4) > left)
	    return -1;
	p += ret + 4;
	left -= ret + 4;
    }

    if (!ret || !answers)
	return -1;

    stored = 0;
    while (answers--) {
	int class, type;

	ret = dn_expand(buf, buf + buflen, p, dname, sizeof dname);
	if (ret < 0 || ret > left)
	    return -1;
	p += ret;
	left -= ret;

	if (left < 10)
	    return -1;
	type = ntohs(*(uint16_t *)p);
	p += 2;
	class = ntohs(*(uint16_t *)p);
	p += 6;
	ret = ntohs(*(uint16_t *)p);
	p += 2;
	left -= 10;

	if (ret > left)
	    return -1;

	if (class == C_IN && type == T_TXT) {
	    *result = malloc(ret);
	    if (*result == NULL)
		return -1;
	    memcpy(*result, p + 1, ret - 1);
	    (*result)[ret - 1] = 0;
	    return 0;
	}

	p += ret;
    }
    return -1;
}

static int
z_get_host_realm_replacement(char *inhost, char ***krealms) {
    char *host, *p;
    char *realm = NULL;
    char *default_realm = NULL;
    char *tmp_realm;
    char *qname;
    profile_t prof;
    int ret;

    host = strdup(inhost);

    for (p = host; *p; p++)
	if (isupper(*p))
	    *p = tolower(*p);

    p = host;
    while (p && !default_realm) {
	if (*p == '.') {
	    p++;
	    if (default_realm == NULL) {
		default_realm = p;
	    }
	} else {
	    p = strchr(p, '.');
	}
    }

    p = host;
    tmp_realm = NULL;

    krb5_get_profile(Z_krb5_ctx, &prof);
    while(p) {
	ret = profile_get_string(prof, "domain_realm", p,
				 0, NULL, &tmp_realm);
	if (ret) {
	    profile_abandon(prof);
	    free(host);
	    return ret;
	}

	if (tmp_realm != NULL)
	    break;

	if (*p == '.')
	    p++;
	else
	    p = strchr(p, '.');
    }

    if (tmp_realm != NULL) {
	realm = strdup(tmp_realm);
	profile_release_string(tmp_realm);
	if (realm == NULL) {
	    free(host);
	    return errno;
	}
    }
    profile_abandon(prof);

    if (realm == NULL) {
	p = host;
	do {
	    qname = malloc(strlen(p) + strlen("_kerberos..") + 1);
	    if (qname == NULL) {
		free(host);
		return errno;
	    }
	    sprintf(qname, "_kerberos.%s.", p);
	    ret = txt_lookup(qname, &realm);
	    free(qname);

	    p = strchr(p,'.');
	    if (p)
		p++;
	} while (ret && p && p[0]);
    }

    if (realm == NULL) {
	if (default_realm != NULL) {
	    realm = strdup(default_realm);
	    if (realm == NULL) {
		free(host);
		return errno;
	    }

	    for (p = realm; *p; p++)
		if (islower(*p))
		    *p = toupper(*p);
	} else {
	    ret = krb5_get_default_realm(Z_krb5_ctx, &realm);
	    if (ret) {
		free(host);
		return ret;
	    }
	}
    }

    free(host);

    if ((*krealms = calloc(2, sizeof(*krealms))) == NULL) {
	if (realm)
	    free(realm);
	return errno;
    }

    (*krealms)[0] = realm;
    (*krealms)[1] = NULL;

    return 0;
}
#endif
