/*
 * This code has gone back and forth between myself and Jon Kamens
 * so many times that neither really knows who wrote it..
 */

#include <X11/Intrinsic.h>
#include <X11/StringDefs.h>

static void _initPopup();
void Popup(), PopupSafe(), PopupAtPointer();

static int	display_height, display_width;

static void _initPopup(w)
   Widget	w;
{
     Display	*dpy;
     int	screen;

     dpy = XtDisplay(w);
     screen = DefaultScreen(dpy);
     display_height = DisplayHeight(dpy, screen);
     display_width = DisplayWidth(dpy, screen);
}

/* ARGSUSED */
void Popup(shell, GrabType, pop_type)
   Widget shell;
   XtGrabKind GrabType;
   int pop_type;
{
     PopupAtPointer(shell, GrabType);
}

void PopupSafe(w, x, y, GrabType)
   Widget w;
   Dimension x, y;
   XtGrabKind GrabType;
{
     static int first_time = 1;
     Dimension width, height, border;

     if (first_time) {
	  _initPopup(w);
	  first_time = 0;
     }

     XtVaGetValues(w,
		   XtNwidth, &width,
		   XtNheight, &height,
		   XtNborderWidth, &border,
		   NULL);
     
     if (x + width + 2 * border > display_width)
	  x = display_width - width - 2 * border;
     if (y + height + 2 * border > display_height)
	  y = display_height - height - 2 * border;
     
     XtVaSetValues(w,
		   XtNx, x,
		   XtNy, y,
		   NULL);
     
     XtPopup(w, GrabType);
}

void PopupAtPointer(w, GrabType)
   Widget 	w;
   XtGrabKind 	GrabType;
{
     Window garbage1, garbage2, window;
     int root_x, root_y, x2, y2;
     unsigned int mask;
     Dimension width, height, border;
     Display *dpy;

     dpy = XtDisplay(w);
     window = XtWindow(XtParent(w));

     if (XQueryPointer(dpy, window, &garbage1, &garbage2,
		       &root_x, &root_y, &x2, &y2, &mask)) {

	  XtVaGetValues(w,
			XtNwidth, &width,
			XtNheight, &height,
			XtNborderWidth, &border,
			NULL);
	  
	  if (root_x >= width / 2 + border)
	       root_x -= width / 2 + border;
	  else
	       root_x = 0;
	  if (root_y >= height / 2 + border)
	       root_y -= height / 2 + border;
	  else
	       root_y = 0;

	  PopupSafe(w, (Dimension) root_x, (Dimension) root_y, GrabType);
     }
}
