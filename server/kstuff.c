/*
 *	$Source$
 *	$Header$
 */

#ifndef lint
static char *rcsid_getkdata_c = "$Header$";
#endif lint

#include <krb.h>
#include <sys/types.h>
#include <netinet/in.h>

/*
 * GetKerberosData
 *
 * get ticket from file descriptor and decode it.
 * Return KFAILURE if we barf on reading the ticket, else return
 * the value of rd_ap_req() applied to the ticket.
 */
int
GetKerberosData(fd, haddr, kdata, service)
	int fd;				/* file descr. to read from */
	struct in_addr haddr;		/* address of foreign host on fd */
	AUTH_DAT *kdata;		/* kerberos data (returned) */
	char *service;			/* service principal desired */
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

	return(rd_ap_req(&ticket,service,instance,haddr,kdata,""));
}
