/*
 *	$Source$
 *	$Header$
 */

#ifndef lint
static char *rcsid_kstuff_c = "$Header$";
#endif lint

#include "zserver.h"

#include <krb.h>
#include <netinet/in.h>
#include <ctype.h>
#include <netdb.h>

char *index();


/*
 * GetKerberosData
 *
 * get ticket from file descriptor and decode it.
 * Return KFAILURE if we barf on reading the ticket, else return
 * the value of rd_ap_req() applied to the ticket.
 */
int
GetKerberosData(fd, haddr, kdata, service, srvtab)
	int fd;				/* file descr. to read from */
	struct in_addr haddr;		/* address of foreign host on fd */
	AUTH_DAT *kdata;		/* kerberos data (returned) */
	char *service;			/* service principal desired */
	char *srvtab;			/* file to get keys from */
{

	char p[20];
	KTEXT_ST ticket;	/* will get Kerberos ticket from client */
	int i;
	char instance[INST_SZ];

	/*
	 * Get the Kerberos ticket.  The first few characters, terminated
	 * by a blank, should give us a length; then get than many chars
	 * which will be the ticket proper.
	 */
	for (i=0; i<20; i++) {
		if (read(fd, &p[i], 1) != 1) {
		    return(KFAILURE);
		}
		if (p[i] == ' ') {
		    p[i] = '\0';
		    break;
		}
	}
	ticket.length = atoi(p);
	if ((i==20) || (ticket.length<=0) || (ticket.length>MAX_KTXT_LEN)) {
	    return(KFAILURE);
	}
	for (i=0; i<ticket.length; i++) {
	    if (read(0, &(ticket.dat[i]), 1) != 1) {
		return(KFAILURE);
	    }
	}
	/*
	 * now have the ticket.  use it to get the authenticated
	 * data from Kerberos.
	 */
	strcpy(instance,"*");	/* let Kerberos fill it in */

	return(rd_ap_req(&ticket,service,instance,haddr,kdata, srvtab ? srvtab : ""));
}

/*
 * The convention established by the Kerberos-authenticated rcmd
 * services (rlogin, rsh, rcp) is that the principal host name is
 * all lower case characters.  Therefore, we can get this name from
 * an alias by taking the official, fully qualified hostname, stripping off
 * the domain info (ie, take everything up to but excluding the
 * '.') and translating it to lower case.  For example, if "menel" is an
 * alias for host officially named "menelaus" (in /etc/hosts), for 
 * the host whose official name is "MENELAUS.MIT.EDU", the user could
 * give the command "menel echo foo" and we will resolve it to "menelaus".
 */

char *
PrincipalHostname( alias )
char *alias;
{
    struct hostent *h;
    char *phost = alias;
    if ( (h=gethostbyname(alias)) != (struct hostent *)NULL ) {
	char *p = index( h->h_name, '.' );
	if (p) *p = NULL;
	p = phost = h->h_name;
	do {
	    if (isupper(*p)) *p=tolower(*p);
	} while (*p++);
    }
    return( phost );
}

/*
 * SendKerberosData
 * 
 * create and transmit a ticket over the file descriptor for service.host
 * return Kerberos failure codes if appropriate, or KSUCCESS if we
 * get the ticket and write it to the file descriptor
 */

SendKerberosData(fd, ticket, service, host)
int fd;					/* file descriptor to write onto */
KTEXT ticket;				/* where to put ticket (return) */
char *service, *host;			/* service name, foreign host */
{
    int rem, serv_length;
    char p[32];
    char krb_realm[REALM_SZ];

    /* send service name, then authenticator */
    serv_length = htonl(strlen(service));
    write(fd, &serv_length, sizeof(long));
    write(fd, service, strlen(service));

    rem=KSUCCESS;

    rem = get_krbrlm(krb_realm,1);
    if (rem != KSUCCESS)
      return(rem);

    rem = mk_ap_req( ticket, service, host, krb_realm, (u_long)0 );
    if (rem != KSUCCESS)
      return(rem);

    (void) sprintf(p,"%d ",ticket->length);
    (void) write(fd, p, strlen(p));
    (void) write(fd, ticket->dat, ticket->length);
    return(rem);
}

static char tkt_file[] = ZEPHYR_TKFILE;

/* Hack to replace the kerberos library's idea of the ticket file with
   our idea */
char *
tkt_string()
{
	return(tkt_file);
}
