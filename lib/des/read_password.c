/*
 * $Source$
 * $Author$
 *
 * Copyright 1985, 1986, 1987, 1988 by the Massachusetts Institute
 * of Technology.
 *
 * For copying and distribution information, please see the file
 * <mit-copyright.h>.
 *
 * This routine prints the supplied string to standard
 * output as a prompt, and reads a password string without
 * echoing.
 */

#ifndef	lint
static char rcsid_read_password_c[] =
    "$Id$";
#endif

#include <mit-copyright.h>
#include <des.h>

#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <setjmp.h>

#ifdef	POSIX
#include <termios.h>
#else
#include <sys/ioctl.h>
#endif

#ifdef POSIX
typedef void sigtype;
static sigjmp_buf env;
#else
typedef int sigtype;
static jmp_buf env;
#endif

static sigtype sig_restore();
static push_signals(), pop_signals();
int des_read_pw_string();

/*** Routines ****************************************************** */
int
des_read_password(k,prompt,verify)
    des_cblock *k;
    char *prompt;
    int	verify;
{
    int ok;
    char key_string[BUFSIZ];

#ifdef POSIX
    if (sigsetjmp(env, 1)) {
	ok = -1;
	goto lose;
    }
#else
    if (setjmp(env)) {
	ok = -1;
	goto lose;
    }
#endif

    ok = des_read_pw_string(key_string, BUFSIZ, prompt, verify);
    if (ok == 0)
	des_string_to_key(key_string, k);

lose:
    memset(key_string, 0, sizeof (key_string));
    return ok;
}

/*
 * This version just returns the string, doesn't map to key.
 *
 * Returns 0 on success, non-zero on failure.
 */

int
des_read_pw_string(s,max,prompt,verify)
    char *s;
    int	max;
    char *prompt;
    int	verify;
{
    int ok = 0;
    char *ptr;
    char key_string[BUFSIZ];
#ifdef POSIX
    sigjmp_buf old_env;
    struct termios tty_state;
#else
    jmp_buf old_env;
    struct sgttyb tty_state;
#endif

    if (max > BUFSIZ) {
	return -1;
    }

#ifdef POSIX
    /* save terminal state */
    if (tcgetattr(0, &tty_state) == -1)
	return -1;
    /* Turn off echo */
    tty_state.c_lflag &= ~ECHO;
    if (tcsetattr(0, TCSANOW, &tty_state) == -1)
	return -1;

    memcpy((char *)env, (char *)old_env, sizeof(env));
    if (sigsetjmp(env, 1))
	goto lose;
#else
    /* save terminal state*/
    if (ioctl(0,TIOCGETP,(char *)&tty_state) == -1) 
	return -1;
    /* Turn off echo */
    tty_state.sg_flags &= ~ECHO;
    if (ioctl(0,TIOCSETP,(char *)&tty_state) == -1)
	return -1;
    memcpy((char *)env, (char *)old_env, sizeof(env));
    if (setjmp(env))
	goto lose;
#endif
    push_signals();

    while (!ok) {
	(void) printf(prompt);
	(void) fflush(stdout);
#ifdef	CROSSMSDOS
	h19line(s,sizeof(s),0);
	if (!strlen(s))
	    continue;
#else
	if (!fgets(s, max, stdin)) {
	    clearerr(stdin);
	    continue;
	}
	if ((ptr = strchr(s, '\n')))
	    *ptr = '\0';
#endif
	if (verify) {
	    printf("\nVerifying, please re-enter %s",prompt);
	    (void) fflush(stdout);
#ifdef CROSSMSDOS
	    h19line(key_string,sizeof(key_string),0);
	    if (!strlen(key_string))
		continue;
#else
	    if (!fgets(key_string, sizeof(key_string), stdin)) {
		clearerr(stdin);
		continue;
	    }
            if ((ptr = strchr(key_string, '\n')))
	    *ptr = '\0';
#endif
	    if (strcmp(s,key_string)) {
		printf("\n\07\07Mismatch - try again\n");
		(void) fflush(stdout);
		continue;
	    }
	}
	ok = 1;
    }

lose:
    if (!ok)
	memset(s, 0, max);
    printf("\n");
#ifdef POSIX
    /* turn echo back on */
    tty_state.c_lflag |= ECHO;
    if (tcsetattr(0, TCSANOW, &tty_state))
	ok = 0;
#else
    /* turn echo back on */
    tty_state.sg_flags |= ECHO;
    if (ioctl(0,TIOCSETP,(char *)&tty_state))
	ok = 0;
#endif
    pop_signals();
    memcpy((char *)old_env, (char *)env, sizeof(env));

    if (verify)
	memset(key_string, 0, sizeof (key_string));
    s[max-1] = 0;		/* force termination */
    return !ok;			/* return nonzero if not okay */
}

#ifdef POSIX
/* This can be static since we should never have more than one set saved... */
static struct sigaction osa[NSIG];

static push_signals()
{
    register int i;
    struct sigaction nsa;

    sigemptyset(&nsa.sa_mask);
    nsa.sa_flags = 0;
    nsa.sa_handler = sig_restore;
    
    for (i=0; i<NSIG; i++)
	sigaction(i, &nsa, &osa[i]);
}

static pop_signals()
{
    register int i;
    for (i=0; i<NSIG; i++)
	sigaction(i, &osa[i], (struct sigaction *)0);
}

static sigtype sig_restore()
{
    siglongjmp(env, 1);
}

#else /* !POSIX */

/* This can be static since we should never have more than one set saved... */
static sigtype (*old_sigfunc[NSIG])();

static push_signals()
{
    register int i;
    for (i = 0; i < NSIG; i++)
	old_sigfunc[i] = signal(i,sig_restore);
}

static pop_signals()
{
    register int i;
    for (i = 0; i < NSIG; i++)
	(void) signal(i,old_sigfunc[i]);
}

static sigtype
sig_restore()
{
    longjmp(env,1);
}

#endif /* POSIX */
