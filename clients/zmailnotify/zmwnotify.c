/*
 *	$Source$
 *	$Header$
 */

#ifndef lint
static char *rcsid_mwnotify_c = "$Header$";
#endif	lint

#include <sys/types.h>
#include <sys/uio.h>
#include <sys/syslog.h>
#include <sys/wait.h>
#include <ttyent.h>
#include <pwd.h>
#include <netinet/in.h>
#include <stdio.h>
#include <sgtty.h>
#include <signal.h>
#include <errno.h>
#include <netdb.h>
#include <X/Xlib.h>

extern char **environ;

short cursor[] = {0x0000, 0x7ffe, 0x4fc2, 0x4ffe, 0x7ffe,
		  0x7ffe, 0x781e, 0x7ffe , 0x7ffe, 0x0000};

#define NW_TOP 5
#define DEFAULT_WINDOWS 16
#define MAX_WINDOWS 32

WindowInfo Winfo;
FontInfo Finfo;
Font NoteFont;
int Timeout = 0;
int Bwidth = 2;
int Inner = 2;
int Volume = 0;
int Forepix = BlackPixel;
int Backpix = WhitePixel;
int Brdrpix = BlackPixel;
int Mouspix = BlackPixel;
int Offset = NW_TOP;
int VPos = NW_TOP;
int WindowMask = 0;
int WindowCount;
int WindowMax = DEFAULT_WINDOWS;

struct wsav {
    Window w_window;
    struct iovec *w_iov;
    int w_iovcnt;
    int w_flags;
} Wsav[MAX_WINDOWS];

#define W_MAPPED 1

extern int errno;

notify_user(iov, iovcnt)
register struct iovec *iov;
register int iovcnt;
{
    register int i;
    register struct wsav *w;

    if (WindowCount == WindowMax)
	return(1);

    w = &Wsav[WindowCount];
    w->w_flags = 0;
    w->w_iov = (struct iovec *)malloc(sizeof (struct iovec) * iovcnt);
    w->w_iovcnt = iovcnt;
    for (i = iovcnt; --i >= 0; ) {
	w->w_iov[i].iov_base = (char *)malloc(iov[i].iov_len+1);
	bcopy(iov[i].iov_base, w->w_iov[i].iov_base, iov[i].iov_len+1);
	w->w_iov[i].iov_len = iov[i].iov_len;
    }
    w->w_window = XNotifySetup(iov, iovcnt, &VPos);
    WindowMask |= (1 << WindowCount);
    WindowCount++;
    return(0);
}

XProcessEvent()
{
    XEvent rep;
    register struct wsav *w;
    register int i;

    do {
	XNextEvent(&rep);

	/* find the window */
	w = Wsav;
	for (i = 0; i < WindowMax; w++, i++)
	    if (rep.window == w->w_window) break;
	if (i == WindowMax) return;

	/* process the event */
	switch (rep.type) {
	case ButtonPressed:
	    for (; i >= 0; w--, i--) {
		if (w->w_window != NULL) {
		    XDestroyWindow(w->w_window);
		    w->w_window = NULL;
		    free_iov(w->w_iov, w->w_iovcnt);
		    WindowMask &= ~(1 << i);
		}
	    }
	    if (WindowMask == 0) {
		VPos = Offset;
		WindowCount = 0;
	    }
	    break;

	case ExposeWindow:
	case ExposeRegion:
	    XClear(w->w_window);
	    display_notice(w->w_window, w->w_iov, w->w_iovcnt);
	    XFlush();
	    break;

	}
    } while (XPending() > 0);
}

free_iov(iov, iovcnt)
register struct iovec *iov;
register int iovcnt;
{
    register struct iovec *iovbase = iov;

    while (--iovcnt >= 0) {
	free(iov->iov_base);
	iov++;
    }
    free(iovbase);
}
	

XNotifyInit(dname)
char *dname;
{
    struct passwd *pwent;
    char *envbuf[2];
    char homebuf[280];
    int reverse = 0;
    char *option;
    char *font_name = "6x13";
    char *fore_color = NULL;
    char *back_color = NULL;
    char *brdr_color = NULL;
    char *mous_color = NULL;
    Color cdef;
    char *getlogin();

    if (!XOpenDisplay(dname))
	exit(0);
    if (pwent = getpwnam(getlogin())) {
	strcpy(homebuf, "HOME=");
	strcat(homebuf, pwent->pw_dir);
	envbuf[0] = homebuf;
	envbuf[1] = NULL;
	environ = envbuf;
	if (option = XGetDefault("mailwatch", "BodyFont"))
	    font_name = option;
	fore_color = XGetDefault("mailwatch", "Foreground");
	back_color = XGetDefault("mailwatch", "Background");
	brdr_color = XGetDefault("mailwatch", "Border");
	mous_color = XGetDefault("mailwatch", "Mouse");
	if (option = XGetDefault("mailwatch", "BorderWidth"))
	    Bwidth = atoi(option);
	if (option = XGetDefault("mailwatch", "InternalBorder"))
	    Inner = atoi(option);
	if (option = XGetDefault("mailwatch", "Timeout"))
	    Timeout = atoi(option);
	if (option = XGetDefault("mailwatch", "Volume"))
	    Volume = atoi(option);
	if (option = XGetDefault("mailwatch", "Offset"))
	    Offset = atoi(option);
	if ((option = XGetDefault("mailwatch", "ReverseVideo")) &&
	    strcmp(option, "on") == 0)
	    reverse = 1;
	if (option = XGetDefault("mailwatch", "MaxNotices"))
	    WindowMax = atoi(option);
    }
    if (reverse) {
	Brdrpix = Backpix;
	Backpix = Forepix;
	Forepix = Brdrpix;
	Mouspix = Forepix;
    }

    if ((NoteFont = XGetFont(font_name)) == NULL)
	exit(0);
    if (DisplayCells() > 2) {
	if (back_color && XParseColor(back_color, &cdef) &&
	    XGetHardwareColor(&cdef))
	    Backpix = cdef.pixel;
	if (fore_color && XParseColor(fore_color, &cdef) &&
	    XGetHardwareColor(&cdef))
	    Forepix = cdef.pixel;
	if (brdr_color && XParseColor(brdr_color, &cdef) &&
	    XGetHardwareColor(&cdef))
	    Brdrpix = cdef.pixel;
	if (mous_color && XParseColor(mous_color, &cdef) &&
	    XGetHardwareColor(&cdef))
	    Mouspix = cdef.pixel;
    }
    XQueryFont(NoteFont, &Finfo);
    XQueryWindow (RootWindow, &Winfo);
    VPos = Offset;
    return(dpyno());
}

XNotifyClose()
{
    register int i;
    register struct wsav *w;

    for (i = WindowMax, w = Wsav; --i >= 0; w++)
	if (w->w_window != NULL) XDestroyWindow(w->w_window);

}

XDisplayNewWindows()
{
    register int i;
    register struct wsav *w;
    register int feepcount = 0;

    for (i = 0, w = Wsav; i < WindowMax; w++, i++)
	if (w->w_window != NULL && !(w->w_flags & W_MAPPED)) {
	    XMapWindow(w->w_window);
	    feepcount++;
	    w->w_flags |= W_MAPPED;
	}
    XFlush();
    /* Now feep for each window, s l o w l y */
    while (--feepcount >= 0) {
	XFeep(Volume);
	XFlush();
    }
}

XNotifySetup (iov, iovcnt, vpos)
struct iovec *iov;
int iovcnt;
register int *vpos;
{
    register int i;
    register int n;
    register int width;
    register int height;
    int vertical;
    register Window w;
    
    width = 0;
    for (i = iovcnt; --i >= 0; ) {
	n = XQueryWidth (iov[i].iov_base, NoteFont);
	if (n > width) width = n;
    }

    width += Inner * 2;
    height = iovcnt * Finfo.height + (Inner * 2);
    vertical = *vpos;
    *vpos += height + (Finfo.height / 2);

    w = XCreateWindow(RootWindow, (Winfo.width - width - (Bwidth * 2)) / 2,
		      vertical, width, height, Bwidth,
		      XMakeTile(Brdrpix), XMakeTile(Backpix));
    XStoreName(w, "mail-notice");
    XSelectInput(w, ButtonPressed|ButtonReleased|ExposeWindow|ExposeRegion);
    XDefineCursor(w, XCreateCursor(16, 10, cursor, NULL, 7, 5,
				   Mouspix, Backpix, GXcopy));
    return(w);
}

display_notice(w, iov, iovcnt)
Window w;
register struct iovec *iov;
register int iovcnt;
{
    register int in;
    register int y;
    register int height;

    in = Inner - 1;
    if (in <= 0) in = 1;

    height = Finfo.height;
    y = in;
    while (--iovcnt >= 0) {
	XText(w, in, y, iov->iov_base, iov->iov_len,
	      NoteFont, Forepix, Backpix);
	y += height;
	iov++;
    }
}
