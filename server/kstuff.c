/*
 *	$Source$
 *	$Header$
 */

#ifndef lint
static char *rcsid_kstuff_c = "$Header$";
#endif lint

#include "zserver.h"

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
			syslog(LOG_WARNING,"bad read tkt len");
			return(KFAILURE);
		}
		if (p[i] == ' ') {
		    p[i] = '\0';
		    break;
		}
	}
	ticket.length = atoi(p);
	if ((i==20) || (ticket.length<=0) || (ticket.length>MAX_KTXT_LEN)) {
		syslog(LOG_WARNING,"bad tkt len %d",ticket.length);
	    return(KFAILURE);
	}
	for (i=0; i<ticket.length; i++) {
	    if (read(fd, (caddr_t) &(ticket.dat[i]), 1) != 1) {
		syslog(LOG_WARNING,"bad tkt read");
		return(KFAILURE);
	    }
	}
	/*
	 * now have the ticket.  use it to get the authenticated
	 * data from Kerberos.
	 */
	(void) strcpy(instance,"*");	/* let Kerberos fill it in */

	return(rd_ap_req(&ticket,service,instance,haddr,kdata, srvtab ? srvtab : ""));
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
    int rem;
    char p[32];
    char krb_realm[REALM_SZ];
    int written;

    rem=KSUCCESS;

    rem = get_krbrlm(krb_realm,1);
    if (rem != KSUCCESS)
      return(rem);

    rem = mk_ap_req( ticket, service, host, krb_realm, (u_long)0 );
    if (rem != KSUCCESS)
      return(rem);

    (void) sprintf(p,"%d ",ticket->length);
    if ((written = write(fd, p, strlen(p))) != strlen(p))
	    if (written < 0)
		    return(written);
	    else
		    return(ZSRV_PKSHORT);
    if ((written = write(fd, (caddr_t) (ticket->dat), ticket->length)) != ticket->length)
	    if (written < 0)
		    return(written);
	    else
		    return(ZSRV_PKSHORT);
	    
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
