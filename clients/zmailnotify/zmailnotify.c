/* This file is part of the Project Athena Zephyr Notification System.
 * It contains code for the "zmailnotify" command.
 *
 *	Created by:	Robert French
 *
 *	$Source$
 *	$Author$
 *
 *	Copyright (c) 1987,1988 by the Massachusetts Institute of Technology.
 *	For copying and distribution information, see the file
 *	"mit-copyright.h". 
 */

#include <zephyr/mit-copyright.h>

#include <zephyr/zephyr.h>

#ifndef lint
static char rcsid_zwmnotify_c[] =
    "$Header$";
#endif

#include <sys/uio.h>
#include <sys/socket.h>
#include <sys/file.h>
#include <pwd.h>
#include <stdio.h>
#include <errno.h>
#include <netdb.h>
#include <hesiod.h>
#include <string.h>

#ifdef KPOP
#include <krb.h>
#endif

#define NOTOK (-1)
#define OK 0
#define DONE 1

FILE *sfi;
FILE *sfo;
char Errmsg[80];
#ifdef KPOP
char *PrincipalHostname(), *index();
#endif

extern uid_t getuid();
char *getenv(), *malloc(), *realloc();
void get_message(), pop_close(), mail_notify(), fatal_pop_err ();
#define MAXMAIL 4

struct _mail {
	char *from;
	char *to;
	char *subj;
} maillist[MAXMAIL];

char *mailptr = NULL;

char *prog = "zmailnotify";

/* This entire program is a kludge - beware! */

main()
{
	FILE *lock;
	int nmsgs;
	char *user,response[512],lockfile[100];
	char *host,*dir;
	char *auth_cmd;
	int i,nbytes,retval,uselock;
	struct passwd *pwd;
	struct _mail mymail;
#ifdef HESIOD
	struct hes_postoffice *p;
#endif

	if (argv[0] && *argv[0])
	    prog = argv[0];
	
	if ((retval = ZInitialize()) != ZERR_NONE) {
		com_err(prog,retval,"while initializing");
		exit(1);
	}

	dir = getenv("HOME");
	user = getenv("USER");
	if (!user || !dir) {
		pwd = (struct passwd *)getpwuid((int) getuid());
		if (!pwd) {
			fprintf(stderr,"%s: Can't figure out who you are!\n",
				prog);
			exit(1);
		}
		if (!user)
			user = pwd->pw_name;
		if (!dir)
			dir = pwd->pw_dir;
	}

	(void) sprintf(lockfile,"%s/.maillock",dir);
	
	host = getenv("MAILHOST");
#ifdef HESIOD
	if (host == NULL) {
		p = hes_getmailhost(user);
		if (p != NULL && strcmp(p->po_type, "POP") == 0)
			host = p->po_host;
		else {
			fprintf(stderr,
				"%s: no POP server listed in Hesiod for %s\n",
				prog, user);
			exit(1);
		} 
	}
#endif
	if (host == NULL) {
		fprintf(stderr,"%s: no MAILHOST defined\n", prog);
		exit(1);
	}

	lock = fopen(lockfile,"r");
	if (lock)
		(void) flock(fileno(lock),LOCK_EX);
	
	if (pop_init(host) == NOTOK) {
		fprintf(stderr,"%s: %s\n",prog, Errmsg);
		exit(1);
	}

	if ((getline(response, sizeof response, sfi) != OK) ||
	    (*response != '+')) {
		fprintf(stderr,"%s: %s\n",prog,response);
		exit(1);
	}

#ifdef KPOP
	auth_cmd = "PASS %s";
#else
	auth_cmd = "RPOP %s";
#endif
	if (pop_command("USER %s", user) == NOTOK
	    || pop_command(auth_cmd, user) == NOTOK)
	    fatal_pop_err ();

	if (pop_stat(&nmsgs, &nbytes) == NOTOK)
	    fatal_pop_err ();

	if (!nmsgs) {
		if (lock) {
			(void) flock(fileno(lock),LOCK_UN);
			(void) fclose(lock);
		} 
		(void) unlink(lockfile);
		(void) pop_command("QUIT");
		pop_close();
		exit (0);
	}

	uselock = 0;
        if (lock) {
		uselock = 1;
		mymail.to = malloc(BUFSIZ);
		mymail.from = malloc(BUFSIZ);
		mymail.subj = malloc(BUFSIZ);
		if (fgets(mymail.from,BUFSIZ,lock) != NULL)
		    mymail.from[strlen(mymail.from)-1] = 0;
		else
		    mymail.from[0]=0;
		if (fgets(mymail.to,BUFSIZ,lock) != NULL)
		    mymail.to[strlen(mymail.to)-1] = 0;
		else
		    mymail.to[0] = 0;
		if (fgets(mymail.subj,BUFSIZ,lock) != NULL)
		    mymail.subj[strlen(mymail.subj)-1] = 0;
		else
		    mymail.subj[0] = 0;
	}
	else {
		lock = fopen(lockfile,"w");
		if (lock)
			(void) flock(fileno(lock),LOCK_EX);
		uselock = 0;
	}
	
	for (i=nmsgs;i>0;i--) {
		if (nmsgs-i == MAXMAIL)
			break;
		if (get_mail(i,&maillist[nmsgs-i]))
			exit (1);
		if (uselock && (!strcmp(maillist[nmsgs-i].to,mymail.to) &&
				!strcmp(maillist[nmsgs-i].from,mymail.from) &&
				!strcmp(maillist[nmsgs-i].subj,mymail.subj)))
			break;
	}

	(void) pop_command("QUIT");
	pop_close();

	i++;
	for (;i<=nmsgs;i++)
		mail_notify(&maillist[nmsgs-i]);
	i--;
	if (lock) {
		(void) flock(fileno(lock),LOCK_UN);
		(void) fclose(lock);
	} 
	lock = fopen(lockfile,"w");
	if (!lock)
		exit (1);
	fprintf(lock,"%s\n%s\n%s\n",
		maillist[nmsgs-i].from,
		maillist[nmsgs-i].to,
		maillist[nmsgs-i].subj);
	(void) fclose(lock);

	exit(0);
}

void fatal_pop_err ()
{
    fprintf (stderr, "%s: %s\n", prog, Errmsg);
    (void) pop_command ("QUIT");
    pop_close ();
    exit (1);
}

void get_message(i)
	int i;
{
	int mbx_write();
	if (pop_retr(i, mbx_write, 0) != OK)
	    fatal_pop_err ();
}

/* Pop stuff */

void pop_close()
{
	if (sfi)
		(void) fclose(sfi);
	if (sfo)
		(void) fclose(sfo);
}

get_mail(i,mail)
	int i;
	struct _mail *mail;
{
	char from[512],to[512],subj[512];
	char *c,*ptr,*ptr2;
	
	*from = 0;
	*to = 0;
	*subj = 0;

	if (mailptr)
		free(mailptr);

	mailptr = 0;
	
	get_message(i);

	ptr = mailptr;
	while (ptr) {
		ptr2 = index(ptr,'\n');
		if (ptr2)
			*ptr2++ = 0;
		if (*ptr == '\0')
			break;
		if (!strncmp(ptr, "From: ", 6))
			(void) strcpy(from, ptr+6);
		else if (!strncmp(ptr, "To: ", 4))
			(void) strcpy(to, ptr+4);
		else if (!strncmp(ptr, "Subject: ", 9))
			(void) strcpy(subj, ptr+9);
		ptr = ptr2;
	}

	/* add elipsis at end of "To:" field if it continues onto */
	/* more than one line */
	i = strlen(to) - 2;
	c = to+i;
	if (*c++ == ',') {
		*c++ = ' ';
		*c++ = '.';
		*c++ = '.';
		*c++ = '.';
		*c++ = '\n';
		*c = 0;
	}

	mail->from = malloc((unsigned)(strlen(from)+1));
	(void) strcpy(mail->from,from);
	mail->to = malloc((unsigned)(strlen(to)+1));
	(void) strcpy(mail->to,to);
	mail->subj = malloc((unsigned)(strlen(subj)+1));
	(void) strcpy(mail->subj,subj);

	return (0);
}

void
mail_notify(mail)
	struct _mail *mail;
{
	int retval;
	char *fields[3];
	ZNotice_t notice;

	(void) bzero((char *)&notice, sizeof(notice));
	notice.z_kind = UNACKED;
	notice.z_port = 0;
	notice.z_class = "MAIL";
	notice.z_class_inst = "POPRET";
	notice.z_opcode = "NEW_MAIL";
	notice.z_sender = 0;
	notice.z_recipient = ZGetSender();
	notice.z_default_format = "You have new mail:\n\nFrom: $1\nTo: $2\nSubject: $3";

	fields[0] = mail->from;
	fields[1] = mail->to;
	fields[2] = mail->subj;
      
	if ((retval = ZSendList(&notice,fields,3,ZNOAUTH)) != ZERR_NONE)
		com_err(prog,retval,"while sending notice");
}

/*
 * These are the necessary KPOP routines snarfed from
 * the GNU movemail program.
 */

pop_init(host)
char *host;
{
    register struct hostent *hp;
    register struct servent *sp;
    int lport = IPPORT_RESERVED - 1;
    struct sockaddr_in sin;
    register int s;
#ifdef KPOP
    KTEXT ticket = (KTEXT)NULL;
    int rem;
    long authopts;
#endif
    char *get_errmsg();
    char *svc_name;

    hp = gethostbyname(host);
    if (hp == NULL) {
	(void) sprintf(Errmsg, "MAILHOST unknown: %s", host);
	return(NOTOK);
    }


#ifdef KPOP
#ifdef ATHENA_COMPAT
    svc_name = "knetd";
#else
    svc_name = "kpop";
#endif
#else
    svc_name = "pop";
#endif

    sp = getservbyname (svc_name, "tcp");
    if (sp == 0) {
	(void) sprintf (Errmsg, "%s/tcp: unknown service");
	return NOTOK;
    }
    sin.sin_family = hp->h_addrtype;
    bcopy(hp->h_addr, (char *)&sin.sin_addr, hp->h_length);
    sin.sin_port = sp->s_port;
#ifdef KPOP
    s = socket(AF_INET, SOCK_STREAM, 0);
#else
    s = rresvport(&lport);
#endif
    if (s < 0) {
	(void) sprintf(Errmsg, "error creating socket: %s", get_errmsg());
	return(NOTOK);
    }

    if (connect(s, (struct sockaddr *)&sin, sizeof sin) < 0) {
	(void) sprintf(Errmsg, "error during connect: %s", get_errmsg());
	(void) close(s);
	return(NOTOK);
    }
#ifdef KPOP
    ticket = (KTEXT)malloc( sizeof(KTEXT_ST) );
    rem=KSUCCESS;
#ifdef ATHENA_COMPAT
    authopts = KOPT_DO_OLDSTYLE;
    rem = krb_sendsvc(s,"pop");
    if (rem != KSUCCESS) {
	(void) sprintf(Errmsg, "kerberos error: %s", krb_err_txt[rem]);
	(void) close(s);
	return(NOTOK);
    }
#else
    authopts = 0L;
#endif
    rem = krb_sendauth(authopts, s, ticket, "pop", hp->h_name, (char *)0,
		       0, (MSG_DAT *) 0, (CREDENTIALS *) 0,
		       (bit_64 *) 0, (struct sockaddr_in *)0,
		       (struct sockaddr_in *)0,"ZMAIL0.0");
    if (rem != KSUCCESS) {
	(void) sprintf(Errmsg, "kerberos error: %s",krb_err_txt[rem]);
	(void) close(s);
	return(NOTOK);
    }
#endif

    sfi = fdopen(s, "r");
    sfo = fdopen(s, "w");
    if (sfi == NULL || sfo == NULL) {
	(void) sprintf(Errmsg, "error in fdopen: %s", get_errmsg());
	(void) close(s);
	return(NOTOK);
    }

    return(OK);
}

/*VARARGS1*/
pop_command(fmt, a, b, c, d)
char *fmt;
{
    char buf[4096];

    (void) sprintf(buf, fmt, a, b, c, d);

    if (putline(buf, Errmsg, sfo) == NOTOK) return(NOTOK);

    if (getline(buf, sizeof buf, sfi) != OK) {
	(void) strcpy(Errmsg, buf);
	return(NOTOK);
    }

    if (*buf != '+') {
	(void) strcpy(Errmsg, buf);
	return(NOTOK);
    } else {
	return(OK);
    }
}

    
pop_stat(nmsgs, nbytes)
int *nmsgs, *nbytes;
{
    char buf[4096];

    if (putline("STAT", Errmsg, sfo) == NOTOK) return(NOTOK);

    if (getline(buf, sizeof buf, sfi) != OK) {
	(void) strcpy(Errmsg, buf);
	return(NOTOK);
    }

    if (*buf != '+') {
	(void) strcpy(Errmsg, buf);
	return(NOTOK);
    } else {
	if (sscanf(buf, "+OK %d %d", nmsgs, nbytes) != 2)
	    return(NOTOK);
	return(OK);
    }
}

pop_retr(msgno, action, arg)
int (*action)();
{
    char buf[4096];

    (void) sprintf(buf, "RETR %d", msgno);
    if (putline(buf, Errmsg, sfo) == NOTOK) return(NOTOK);

    if (getline(buf, sizeof buf, sfi) != OK) {
	(void) strcpy(Errmsg, buf);
	return(NOTOK);
    }

    while (1) {
	switch (multiline(buf, sizeof buf, sfi)) {
	case OK:
	    (*action)(buf, arg);
	    break;
	case DONE:
	    return (OK);
	case NOTOK:
	    (void) strcpy(Errmsg, buf);
	    return (NOTOK);
	}
    }
}

getline(buf, n, f)
char *buf;
register int n;
FILE *f;
{
    register char *p;

    p = fgets(buf, n, f);

    if (ferror(f)) {
	(void) strcpy(buf, "error on connection");
	return (NOTOK);
    }

    if (p == NULL) {
	(void) strcpy(buf, "connection closed by foreign host\n");
	return (DONE);
    }

    p = buf + strlen(buf);
    if (*--p == '\n') *p = '\0';
    if (*--p == '\r') *p = '\0';
    return(OK);
}

multiline(buf, n, f)
char *buf;
register int n;
FILE *f;
{
    if (getline(buf, n, f) != OK) return (NOTOK);
    if (*buf == '.') {
	if (*(buf+1) == '\0') {
	    return (DONE);
	} else {
	    (void) strcpy(buf, buf+1);
	}
    } else if (*buf == '\0') {
      /* suck up all future lines, since this is after all only for headers */
	while(! ((buf[0]=='.') && (buf[1] == '\0')) ) {
	    if (getline(buf, n, f) != OK) return (NOTOK);
	}
	return DONE;
    }
    return(OK);
}

char *
get_errmsg()
{
    extern int errno, sys_nerr;
    extern char *sys_errlist[];
    char *s;

    if (errno < sys_nerr)
      s = sys_errlist[errno];
    else
      s = "unknown error";
    return(s);
}

putline(buf, err, f)
char *buf;
char *err;
FILE *f;
{
    fprintf(f, "%s\r\n", buf);
    (void) fflush(f);
    if (ferror(f)) {
	(void) strcpy(err, "lost connection");
	return(NOTOK);
    }
    return(OK);
}

/*ARGSUSED*/
mbx_write(line, dummy)
char *line;
int dummy;				/* for consistency with pop_retr */
{
	if (mailptr) {
		mailptr = realloc(mailptr,(unsigned)(strlen(mailptr)+strlen(line)+2));
		(void) strcat(mailptr,line);
	} 
	else {
		mailptr = malloc((unsigned)(strlen(line)+2));
		(void) strcpy(mailptr,line);
	}
	(void) strcat(mailptr,"\n");
	return(0);
}
