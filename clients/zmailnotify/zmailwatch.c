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

int	Pfd;
FILE	*sfi;
FILE	*sfo;
char	Errmsg[128];
FILE	*logf;

struct	mailsav {
    struct iovec m_iov[3];
    int m_iovcnt;
    int m_seen;
} *Mailsav[64];
    
int MailIndex;
int MailSize;
int Debug = 0;
int Interval = 0;
int List = 0;
int Shutdown = 0;

main(argc,argv)
    int argc;
    char *argv[];
{
    char *host;
    char *user;
    char *str_index;
    int readfds;
    struct timeval timeout;
    register int curtime;
    register int i;
    char *getenv();
    int cleanup();

    user = getenv("USER");
    host = getenv("MAILHOST");
    if (user == NULL)
	fatal("No USER envariable defined");
    if (host == NULL)
	fatal("No MAILHOST envariable defined");

    for (i = 1; i < argc; i++) {
	str_index = (char *)index(argv[i], '-');
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
    
    if (!Debug || !Interval || !List) background();

    logf = fopen("/usr/adm/zmailwatch.log", "a");
    setlinebuf(logf);
    log("startup");
    /* Initialize Notify */
    timeout.tv_usec = 0;

    signal(SIGHUP, cleanup);
    signal(SIGTERM, cleanup);

    check_mail(host, user);
    i = 59 - (time(0) % 60);
    while (1) {
	check_mail(host, user);
	if (Shutdown) {
	    log("shutdown");
	    fclose(logf);
	    /* Shutdown Notify */
	    exit(0);
	}
	i = 60 - (time(0) % 60);
	sleep(i);
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

check_mail(host, user)
    char *host;
    char *user;
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
	log("pop_init: %s", Errmsg);
	error(Errmsg);
	return(1);
    }

    if (pop_command("USER %s", user) == NOTOK || 
            pop_command("RPOP %s", user) == NOTOK) {
	error(Errmsg);
	log("USER|RPOP: %s", Errmsg);
	pop_command("QUIT");
	pop_close();
	return(1);
    }

    if (pop_stat(&nmsgs, &nbytes) == NOTOK) {
	error(Errmsg);
	log("pop_stat: %s", Errmsg);
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
	    log("mkstemp");
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
	log("pop_retr: %s", Errmsg);
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

pop_init(host)
    char *host;
{
    static struct hostent *hp = NULL;
    static struct servent *sp = NULL;
    static struct sockaddr_in sin;
    static int initialized = 0;
    int lport = IPPORT_RESERVED - 1;
    char response[128];
    char *get_errmsg();

    if (!initialized) {
	hp = gethostbyname(host);
	if (hp == NULL) {
	    sprintf(Errmsg, "MAILHOST unknown: %s", host);
	    return(NOTOK);
	}

	sp = getservbyname("pop", "tcp");
	if (sp == 0) {
	    strcpy(Errmsg, "tcp/pop: unknown service");
	    return(NOTOK);
	}

	sin.sin_family = hp->h_addrtype;
	bcopy(hp->h_addr, (char *)&sin.sin_addr, hp->h_length);
	sin.sin_port = sp->s_port;

	initialized = 1;
    }

    Pfd = rresvport(&lport);
    if (Pfd < 0) {
	sprintf(Errmsg, "error creating socket: %s", get_errmsg());
	return(NOTOK);
    }

    if (connect(Pfd, (char *)&sin, sizeof sin) < 0) {
	sprintf(Errmsg, "error during connect: %s", get_errmsg());
	close(Pfd);
	return(NOTOK);
    }

    sfi = fdopen(Pfd, "r");
    sfo = fdopen(Pfd, "w");
    if (sfi == NULL || sfo == NULL) {
	sprintf(Errmsg, "error in fdopen: %s", get_errmsg());
	close(Pfd);
	return(NOTOK);
    }

    if (getline(response, sizeof response, sfi) != OK || (*response != '+')) {
	strcpy(Errmsg, response);
	return(NOTOK);
    }

    return(OK);
}

pop_close()
{
    if (sfi != NULL) fclose(sfi);
    if (sfi != NULL) fclose(sfo);
    close(Pfd);
}

pop_command(fmt, a, b, c, d)
    char *fmt;
{
    char buf[128];

    sprintf(buf, fmt, a, b, c, d);

    if (Debug) fprintf(stderr, "---> %s\n", buf);
    if (putline(buf, Errmsg, sfo) == NOTOK) return(NOTOK);

    if (getline(buf, sizeof buf, sfi) != OK) {
	strcpy(Errmsg, buf);
	return(NOTOK);
    }

    if (Debug) fprintf(stderr, "<--- %s\n", buf);
    if (*buf != '+') {
	strcpy(Errmsg, buf);
	return(NOTOK);
    }
    else {
	return(OK);
    }
}

    
pop_stat(nmsgs, nbytes)
    int *nmsgs, *nbytes;
{
    char buf[128];

    if (Debug) fprintf(stderr, "---> STAT\n");
    if (putline("STAT", Errmsg, sfo) == NOTOK) return(NOTOK);

    if (getline(buf, sizeof buf, sfi) != OK) {
	strcpy(Errmsg, buf);
	return(NOTOK);
    }

    if (Debug) fprintf(stderr, "<--- %s\n", buf);
    if (*buf != '+') {
	strcpy(Errmsg, buf);
	return(NOTOK);
    }
    else {
	sscanf(buf, "+OK %d %d", nmsgs, nbytes);
	return(OK);
    }
}

pop_retr(msgno, action, arg)
    int (*action)();
{
    char buf[128];
    int end_of_header;

    sprintf(buf, "RETR %d", msgno);
    if (Debug) fprintf(stderr, "%s\n", buf);
    if (putline(buf, Errmsg, sfo) == NOTOK) return(NOTOK);

    if (getline(buf, sizeof buf, sfi) != OK) {
	strcpy(Errmsg, buf);
	return(NOTOK);
    }

    end_of_header = 0;
    while (1) {
	switch (multiline(buf, sizeof buf, sfi)) {
	case OK:
	    if (!end_of_header) {
		(*action)(buf, arg);
		if (*buf == 0) end_of_header = 1;
	    }
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
    register int c;

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
    register char *buf;
    register int n;
    FILE *f;
{
    if (getline(buf, n, f) != OK) return (NOTOK);
    if (*buf == '.') {
	if (*(buf+1) == NULL) {
	    return (DONE);
	}
	else {
	    strcpy(buf, buf+1);
	}
    }
    return(OK);
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
	log("new mail");
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

char *Months[] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun",
		 "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};

log(message, a1, a2)
char *message;
{
    struct tm *tm;
    int clock;
    char buf[64];

    clock = time(0);
    tm = localtime(&clock);
    sprintf(buf, message, a1, a2);
    fprintf(logf, "%s %2d %02d:%02d:%02d -- %s\n",
	    Months[tm->tm_mon], tm->tm_mday, 
	    tm->tm_hour, tm->tm_min, tm->tm_sec,
	    buf);
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
