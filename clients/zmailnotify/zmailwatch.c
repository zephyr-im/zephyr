/*
 *	$Source$
 *	$Header$
 */

#ifndef lint
static char *rcsid_mailwatch_c = "$Header$";
#endif	lint

#include <sys/types.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <signal.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdio.h>

#define NOTOK (-1)
#define OK 0
#define DONE 1

#define DEF_INTERVAL 300
#define DEF_DEBUG 0

int	Pfd;
FILE	*sfi;
FILE	*sfo;
char	Errmsg[128];

struct	mailsav {
    struct iovec m_iov[3];
    int m_iovcnt;
    int m_seen;
} *Mailsav[64];
    
int MailIndex;
int MailSize;
int Debug = DEF_DEBUG;
int Interval = DEF_INTERVAL;
int List = 0;
int Shutdown = 0;

int check_mail(), cleanup();
uid_t getuid();
char *strcpy(), *getenv(), index();

main(argc,argv)
    int argc;
    char *argv[];
{
    char *str_index;
    register int i;
    int readfds = 0;
    int maxfds = 0;
    struct timeval timeout;

    for (i = 1; i < argc; i++) {
	str_index = index(argv[i], '-');
	if (str_index == (char *)NULL) syntax(argv[0]);
	if (strncmp(argv[i], "-d", 2) == 0) {
	    Debug = 1;
	    continue;
	}
	if (strncmp(argv[i], "-i", 2) == 0) {
	    if (++i >= argc) syntax(argv[0]);
	    Interval = atoi(argv[i]);
	    continue;
	}
	if (strncmp(argv[i], "-l", 2) == 0) {
	    List = 1;
	    continue;
	}
	if (strncmp(argv[i], "-help", 5) == 0) {
	    syntax(argv[0]);
	}
	syntax(argv[0]);
    }
    
    if (!Debug && !List) background();

    signal(SIGHUP, cleanup);
    signal(SIGTERM, cleanup);

    check_mail();

    if (List) {
	exit(0);
    }

    /*
     * Initialize select's maximum file descriptor number to
     * be one more than the file descriptor number of the
     * Zephyr socket.
     */
    maxfds = ZGetFD() + 1;

    /*
     * Initialize the select timeout structure.
     */
    timeout.tv_sec = Interval;
    timeout.tv_usec = 0;

    while (1) {
	/*
	 * Use select on the Zephyr port to determine if there
	 * is new mail.  If not block untill timeout.  Remember 
	 * to reset the file descriptor before each select.
	 */
	readfds = 1 << ZGetFD();
	if (select(maxfds, &readfds, NULL, NULL, &timeout) == -1)
	  fatal("select failed on Zephyr socket");
	/*
	 * Check for mail.
	 */
	check_mail(host, user);
	/*
	 * Shutdown if requested.
	 */
	if (Shutdown) {
	    exit(0);
	}
    }
}

background()
{
    register int i;

    if (fork()) exit(0);
    for (i = 0; i < 10; i++) close(i);
    open("/", 0);
    dup2(0, 1);
    dup2(0, 2);
    i = open("/dev/tty", 2);
    if (i >= 0) {
	ioctl(i, TIOCNOTTY, 0);
	close(i);
    }
}

check_mail()
{
    static int LastNmsgs = -1;
    static int LastNbytes = -1;
    int nmsgs;
    int nbytes;
    static char tempname[40];
    static FILE *mbf = NULL;
    register int mbfi;
    register int i;
    register int next_msg;
    struct mailsav *ms;
    struct mailsav *build_mailsav();

    if (pop_init(host) == NOTOK) {
	if (Debug) printf("zmailwatch(pop_init): %s\n", Errmsg);
	error(Errmsg);
	return(1);
    }

    if (pop_command("USER %s", user) == NOTOK || 
            pop_command("RPOP %s", user) == NOTOK) {
	error(Errmsg);
	if (Debug) printf("zmailwatch(USER|RPOP): %s\n", Errmsg);
	pop_command("QUIT");
	pop_close();
	return(1);
    }

    if (pop_stat(&nmsgs, &nbytes) == NOTOK) {
	error(Errmsg);
	if (Debug) printf("zmailwatch(pop_stat): %s\n", Errmsg);
	pop_command("QUIT");
	pop_close();
	return(1);
    }

    if (nmsgs == 0) {
	pop_command("QUIT");
	pop_close();
	return(0);
    }

    if (mbf == NULL) {
	strcpy(tempname, "/tmp/pmXXXXXX");
	mbfi = mkstemp(tempname);
	if (mbfi < 0) {
	    if (Debug) printf("zmailwatch: mkstemp\n");
	    pop_command("QUIT");
	    pop_close();
	    return(1);
        }
	mbf = fdopen(mbfi, "w+");
    }

    next_msg = 1;
    if (nmsgs == LastNmsgs && nbytes == LastNbytes) {
	if (get_message(1, mbf) != 0) return(1);
	ms = build_mailsav(mbf);
	if (mail_compare(ms, Mailsav[0]) == 0) {
	    pop_command("QUIT");
	    pop_close();
	    return(0);
	}
	else {
	    display_mail_header(ms, 0);
	    rewind(mbf);
	    next_msg = 2;
	}
    }

    for (i = next_msg; i <= nmsgs; i++) {
	if (get_message(i, mbf) != 0) return(1);
	ms = build_mailsav(mbf);
	display_mail_header(ms, i-1);
	rewind(mbf);
    }

    LastNmsgs = nmsgs;
    LastNbytes = nbytes;

    pop_command("QUIT");
    pop_close();
    if (Shutdown) {
	fclose(mbf);
	unlink(tempname);
    }

    return(0);
}

cleanup()
{
    Shutdown = 1;
}

get_message(i, mbf)
    int i;
    FILE *mbf;
{
    int mbx_write();

    if (pop_retr(i, mbx_write, mbf) != OK) {
	error(Errmsg);
	if (Debug) printf("zmailwatch(pop_retr): %s\n", Errmsg);
	pop_command("QUIT");
	pop_close();
	return(1);
    }
    ftruncate(fileno(mbf), ftell(mbf));
    return(0);
}

free_all_mailsav()
{
    register struct mailsav **msp;
    register struct mailsav *ms;
    register struct iovec *iov;
    register int iovcnt;

    for (msp = Mailsav; ms = *msp; msp++) {
	iov = ms->m_iov;
	iovcnt = ms->m_iovcnt;
	while (--iovcnt >= 0) {
	    free(iov->iov_base);
	    iov++;
	}
	free(ms);
	*msp = NULL;
    }
}

free_mailsav(ms)
    register struct mailsav *ms;
{
    register struct iovec *iov;
    register int iovcnt;

    iov = ms->m_iov;
    iovcnt = ms->m_iovcnt;
    while (--iovcnt >= 0) {
	free(iov->iov_base);
	iov++;
    }
    free(ms);
}

/* Pop stuff */

pop_close()
{
    if (sfi != NULL) fclose(sfi);
    if (sfi != NULL) fclose(sfo);
    close(Pfd);
}

struct mailsav *
build_mailsav(mbf)
    register FILE *mbf;
{
    char line[128];
    char from[80];
    char to[80];
    char subj[80];
    register struct mailsav *ms;
    register int i;
    register char *c;
    register struct iovec *iov;

    ms = (struct mailsav *)malloc(sizeof (struct mailsav));
    ms->m_seen = 0;

    from[0] = 0;
    to[0] = 0;
    subj[0] = 0;

    rewind(mbf);
    while (fgets(line, 128, mbf) != NULL) {
	if (*line == '\n') break;
	if (!strncmp(line, "From:", 5))
	    strcpy(from, line);
	else if (!strncmp(line, "To:", 3))
	    strcpy(to, line);
	else if (!strncmp(line, "Subject:", 8))
	    strcpy(subj, line);
    }

    /* add elipsis at end of "To:" field if it continues onto */
    /* more than one line */
    i = strlen(to) - 2;
    c = &to[i];
    if (*c++ == ',') {
	*c++ = ' ';
	*c++ = '.';
	*c++ = '.';
	*c++ = '.';
	*c++ = '\n';
	*c = 0;
    }

    i = 0;
    if (from[0] != 0) {
	iov = &ms->m_iov[i];
	iov->iov_len = strlen(from);
	iov->iov_base = (char *)malloc(iov->iov_len);
	bcopy(from, iov->iov_base, iov->iov_len);
	iov->iov_base[--iov->iov_len] = 0; /* remove LF */
	i++;
    }

    if (to[0] != 0) {
	iov = &ms->m_iov[i];
	iov->iov_len = strlen(to);
	iov->iov_base = (char *)malloc(iov->iov_len);
	bcopy(to, iov->iov_base, iov->iov_len);
	iov->iov_base[--iov->iov_len] = 0; /* remove LF */
	i++;
    }

    if (subj[0] != 0) {
	iov = &ms->m_iov[i];
	iov->iov_len = strlen(subj);
	iov->iov_base = (char *)malloc(iov->iov_len);
	bcopy(subj, iov->iov_base, iov->iov_len);
	iov->iov_base[--iov->iov_len] = 0; /* remove LF */
	i++;
    }

    ms->m_iovcnt = i;
    return(ms);
}

display_mail_header(ms, mi)
    register struct mailsav *ms;
    register int mi;
{
    /* This is a little tricky.  If the current mail number (mi) is greater */
    /* than the last saved mail index (MailIndex), then this is new mail and */
    /* mi = MailIndex + 1.  (MailIndex is incremented each time new mail is */
    /* saved.)  Similarly, if mi is less than or equal to MailIndex and the */
    /* mail is different, then it is new mail, and MailIndex is set back to */
    /* mi. */

    if (mi > MailIndex || mail_compare(ms, Mailsav[mi])) {
	if (Mailsav[mi] != NULL) free_mailsav(Mailsav[mi]);
	MailIndex = mi;
	Mailsav[mi] = ms;
	if (Debug) printf("zmailwatch: new mail\n");
    }
    else {
	free_mailsav(ms);
	ms = Mailsav[mi];
    }
    if (!ms->m_seen) {
	if (notify_user(ms->m_iov, ms->m_iovcnt) == 0) ms->m_seen = 1;
    }
}

display_unseen()
{
    register int i;
    register struct mailsav *ms;

    for (i = 0; i <= MailIndex; i++) {
	ms = Mailsav[i];
	if (ms->m_seen == 0) {
	    if (notify_user(ms->m_iov, ms->m_iovcnt) != 0) return;
	    ms->m_seen = 1;
	}
    }
}

mail_compare(m1, m2)
    register struct mailsav *m1, *m2;
{
    register struct iovec *iov1, *iov2;
    register int iovcnt;

    if (m1->m_iovcnt != m2->m_iovcnt) return(1);
    iov1 = m1->m_iov;
    iov2 = m2->m_iov;
    iovcnt = m1->m_iovcnt;
    while (--iovcnt >= 0) {
	if (strcmp(iov1->iov_base, iov2->iov_base)) return(1);
	iov1++;
	iov2++;
    }
    return(0);
}

error(msg)
{
    fprintf(stderr, "mailwatch: %s\n");
}

fatal(msg)
{
    error(msg);
    exit(1);
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

/*
 * Report the syntax for calling zmailwatch.
 */
syntax(call)
    char *call;
{
    printf ("Usage: %s [-dl] [-i <interval>] [-help]\n", call);
    exit(0);
}

/*
 * These are the necessary KPOP routines snarfed from
 * the GNU movemail program.
 */

/* Interface from movemail to Athena's post-office protocol.
   Copyright (C) 1986 Free Software Foundation, Inc.

This file is part of GNU Emacs.

GNU Emacs is distributed in the hope that it will be useful,
but without any warranty.  No author or distributor
accepts responsibility to anyone for the consequences of using it
or for whether it serves any particular purpose or works at all,
unless he says so in writing.

Everyone is granted permission to copy, modify and redistribute
GNU Emacs, but only under the conditions described in the
document "GNU Emacs copying permission notice".   An exact copy
of the document is supposed to have been given to you along with
GNU Emacs so that you can know how you may redistribute it all.
It should be in a file named COPYING.  Among other things, the
copyright notice and this notice must be preserved on all copies.  */

#include <sys/types.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdio.h>
#include "../src/config.h"
#ifdef KPOP
#include <krb.h>
#endif KPOP

#ifdef USG
#include <fcntl.h>
/* Cancel substitutions made by config.h for Emacs.  */
#undef open
#undef read
#undef write
#endif /* USG */

#define NOTOK (-1)
#define OK 0
#define DONE 1

char *progname;
FILE *sfi;
FILE *sfo;
char Errmsg[80];
#ifdef KPOP
char *PrincipalHostname(), *index();
#endif KPOP

static int debug = 0;

popmail(user, outfile)
char *user;
char *outfile;
{
    char *host;
    int nmsgs, nbytes;
    char response[128];
    register int i;
    int mbfi;
    FILE *mbf;
    char *getenv();
    int mbx_write();
    char *get_errmsg();
#ifdef HESIOD
    struct hes_postoffice *p;
#endif HESIOD

    host = getenv("MAILHOST");
#ifdef HESIOD
    if (host == NULL) {
    	p = hes_getmailhost(user);
    	if (p != NULL && strcmp(p->po_type, "POP") == 0)
		host = p->po_host;
	else
		fatal("no POP server listed in Hesiod");
    }
#endif HESIOD
    if (host == NULL) {
	fatal("no MAILHOST defined");
    }

    if (pop_init(host) == NOTOK) {
	error(Errmsg);
	return(1);
    }

    if ((getline(response, sizeof response, sfi) != OK) || (*response != '+')){
	error(response);
	return(1);
    }

#ifdef KPOP
    if (pop_command("USER %s", user) == NOTOK || 
	pop_command("PASS %s", user) == NOTOK) {
#else !KPOP
    if (pop_command("USER %s", user) == NOTOK || 
	pop_command("RPOP %s", user) == NOTOK) {
#endif KPOP
	error(Errmsg);
	pop_command("QUIT");
	return(1);
    }

    if (pop_stat(&nmsgs, &nbytes) == NOTOK) {
	error(Errmsg);
	pop_command("QUIT");
	return(1);
    }

    if (!nmsgs)
      {
	pop_command("QUIT");
	return(0);
      }

    setuid (getuid());

    mbfi = open (outfile, O_WRONLY | O_CREAT | O_EXCL, 0666);
    if (mbfi < 0)
      {
	pop_command("QUIT");
	error("Error in open: %s, %s", get_errmsg(), outfile);
	return(1);
      }

    if ((mbf = fdopen(mbfi, "w")) == NULL)
      {
	pop_command("QUIT");
	error("Error in fdopen: %s", get_errmsg());
	close(mbfi);
	unlink(outfile);
	return(1);
      }

    for (i = 1; i <= nmsgs; i++) {
	mbx_delimit_begin(mbf);
	if (pop_retr(i, mbx_write, mbf) != OK) {
	    error(Errmsg);
	    pop_command("QUIT");
	    close(mbfi);
	    return(1);
	}
	mbx_delimit_end(mbf);
	fflush(mbf);
    }

    for (i = 1; i <= nmsgs; i++) {
	if (pop_command("DELE %d", i) == NOTOK) {
	    error(Errmsg);
	    pop_command("QUIT");
	    close(mbfi);
	    return(1);
	}
    }

    pop_command("QUIT");
    close(mbfi);
    return(0);
}

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
#endif KPOP
    char *get_errmsg();

    hp = gethostbyname(host);
    if (hp == NULL) {
	sprintf(Errmsg, "MAILHOST unknown: %s", host);
	return(NOTOK);
    }

#ifdef KPOP
    sp = getservbyname("knetd", "tcp");
    if (sp == 0) {
	strcpy(Errmsg, "tcp/knetd: unknown service");
	return(NOTOK);
    }
#else !KPOP
    sp = getservbyname("pop", "tcp");
    if (sp == 0) {
	strcpy(Errmsg, "tcp/pop: unknown service");
	return(NOTOK);
    }
#endif KPOP

    sin.sin_family = hp->h_addrtype;
    bcopy(hp->h_addr, (char *)&sin.sin_addr, hp->h_length);
    sin.sin_port = sp->s_port;
#ifdef KPOP
    s = socket(AF_INET, SOCK_STREAM, 0);
#else !KPOP
    s = rresvport(&lport);
#endif KPOP
    if (s < 0) {
	sprintf(Errmsg, "error creating socket: %s", get_errmsg());
	return(NOTOK);
    }

    if (connect(s, (char *)&sin, sizeof sin) < 0) {
	sprintf(Errmsg, "error during connect: %s", get_errmsg());
	close(s);
	return(NOTOK);
    }
#ifdef KPOP
    ticket = (KTEXT)malloc( sizeof(KTEXT_ST) );
    rem=KSUCCESS;
    rem = SendKerberosData(s, ticket, "pop", hp->h_name);
    if (rem != KSUCCESS) {
	sprintf(Errmsg, "kerberos error: %s",krb_err_txt[rem]);
	close(s);
	return(NOTOK);
    }
#endif KPOP

    sfi = fdopen(s, "r");
    sfo = fdopen(s, "w");
    if (sfi == NULL || sfo == NULL) {
	sprintf(Errmsg, "error in fdopen: %s", get_errmsg());
	close(s);
	return(NOTOK);
    }

    return(OK);
}

pop_command(fmt, a, b, c, d)
char *fmt;
{
    char buf[4096];
    char errmsg[64];

    sprintf(buf, fmt, a, b, c, d);

    if (debug) fprintf(stderr, "---> %s\n", buf);
    if (putline(buf, Errmsg, sfo) == NOTOK) return(NOTOK);

    if (getline(buf, sizeof buf, sfi) != OK) {
	strcpy(Errmsg, buf);
	return(NOTOK);
    }

    if (debug) fprintf(stderr, "<--- %s\n", buf);
    if (*buf != '+') {
	strcpy(Errmsg, buf);
	return(NOTOK);
    } else {
	return(OK);
    }
}

    
pop_stat(nmsgs, nbytes)
int *nmsgs, *nbytes;
{
    char buf[4096];

    if (debug) fprintf(stderr, "---> STAT\n");
    if (putline("STAT", Errmsg, sfo) == NOTOK) return(NOTOK);

    if (getline(buf, sizeof buf, sfi) != OK) {
	strcpy(Errmsg, buf);
	return(NOTOK);
    }

    if (debug) fprintf(stderr, "<--- %s\n", buf);
    if (*buf != '+') {
	strcpy(Errmsg, buf);
	return(NOTOK);
    } else {
	sscanf(buf, "+OK %d %d", nmsgs, nbytes);
	return(OK);
    }
}

pop_retr(msgno, action, arg)
int (*action)();
{
    char buf[4096];

    sprintf(buf, "RETR %d", msgno);
    if (debug) fprintf(stderr, "%s\n", buf);
    if (putline(buf, Errmsg, sfo) == NOTOK) return(NOTOK);

    if (getline(buf, sizeof buf, sfi) != OK) {
	strcpy(Errmsg, buf);
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
	    strcpy(Errmsg, buf);
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
    int c;

    p = buf;
    while (--n > 0 && (c = fgetc(f)) != EOF)
      if ((*p++ = c) == '\n') break;

    if (ferror(f)) {
	strcpy(buf, "error on connection");
	return (NOTOK);
    }

    if (c == EOF && p == buf) {
	strcpy(buf, "connection closed by foreign host");
	return (DONE);
    }

    *p = NULL;
    if (*--p == '\n') *p = NULL;
    if (*--p == '\r') *p = NULL;
    return(OK);
}

multiline(buf, n, f)
char *buf;
register int n;
FILE *f;
{
    if (getline(buf, n, f) != OK) return (NOTOK);
    if (*buf == '.') {
	if (*(buf+1) == NULL) {
	    return (DONE);
	} else {
	    strcpy(buf, buf+1);
	}
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
    fflush(f);
    if (ferror(f)) {
	strcpy(err, "lost connection");
	return(NOTOK);
    }
    return(OK);
}

mbx_write(line, mbf)
char *line;
FILE *mbf;
{
    fputs(line, mbf);
    fputc(0x0a, mbf);
}

mbx_delimit_begin(mbf)
FILE *mbf;
{
    fputs("\f\n0,unseen,,\n", mbf);
}

mbx_delimit_end(mbf)
FILE *mbf;
{
    putc('\037', mbf);
}
