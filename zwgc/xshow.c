/* This file is part of the Project Athena Zephyr Notification System.
 * It is one of the source files comprising zwgc, the Zephyr WindowGram
 * client.
 *
 *      Created by:     Marc Horowitz <marc@athena.mit.edu>
 *
 *      $Source$
 *      $Author$
 *
 *      Copyright (c) 1989 by the Massachusetts Institute of Technology.
 *      For copying and distribution information, see the file
 *      "mit-copyright.h".
 */

#if (!defined(lint) && !defined(SABER))
static char rcsid_xshow_c[] = "$Id$";
#endif

#include <zephyr/mit-copyright.h>

#include <stdio.h>
#include <X11/Xlib.h>
#include <X11/Xutil.h>
#include "pointer_dictionary.h"
#include "new_memory.h"
#include "formatter.h"
#include "variables.h"
#include "zwgc.h"
#include "X_fonts.h"
#include "X_gram.h"
#include "xmode_stack.h"

#define max(a,b)   ((a)>(b)?(a):(b))

XContext desc_context;
static pointer_dictionary colorname_dict = NULL;

extern int internal_border_width;
extern unsigned long default_bgcolor;
extern unsigned long default_fgcolor;
extern unsigned long x_string_to_color();

xshowinit()
{
    desc_context = XUniqueContext();
}

/*ARGSUSED*/
char *mode_to_colorname(dpy,style,mode)
     Display *dpy;
     char *style;
     xmode *mode;
{
   char *desc;
   int exists;
   char *name;
   pointer_dictionary_binding *binding;

   desc = string_Concat("style.",style);
   desc = string_Concat2(desc,"style");
   desc = string_Concat2(desc,".substyle.");
   desc = string_Concat2(desc,mode->substyle);
   desc = string_Concat2(desc,".foreground");

   if (!colorname_dict)
      colorname_dict = pointer_dictionary_Create(37);
   binding = pointer_dictionary_Define(colorname_dict,desc,&exists);

   if (exists) {
      free(desc);
      return((char *) binding->value);
   } else {
#define COLNAME_CLASS "StyleKey.Style1.Style2.Style3.SubstyleKey.Substyle.ForegroundKey"
      name=get_string_resource(desc,COLNAME_CLASS);
#undef COLNAME_CLASS
      free(desc);
      if (name==NULL)
	 pointer_dictionary_Delete(colorname_dict,binding);
      else
	 binding->value=(pointer) name;
      return(name);  /* If resource returns NULL, return NULL also */
   }
}

struct res_dict_type {
    pointer_dictionary	dict;
    char *		resname_suffix;
    char *		resclass;
};

static struct res_dict_type geometry_resources = {
    NULL, ".geometry", "StyleKey.Style1.Style2.Style3.GeometryKey",
};

static struct res_dict_type bgcolor_resources = {
    NULL, ".background", "StyleKey.Style1.Style2.Style3.BackgroundKey",
};

static char *xres_get_resource (restype, style)
    struct res_dict_type *restype;
    char *style;
{
   char *desc;
   pointer_dictionary_binding *binding;
   int exists;
   char *value;

   desc=string_Concat("style.", style);
   desc=string_Concat2(desc, restype->resname_suffix);

   if (!restype->dict)
      restype->dict = pointer_dictionary_Create(37);
   binding = pointer_dictionary_Define(restype->dict, desc, &exists);

   if (exists) {
      free(desc);
      return((string) binding->value);
   } else {
      value=get_string_resource(desc, restype->resclass);
      free(desc);
      if (value==NULL)
	 pointer_dictionary_Delete(restype->dict, binding);
      else
	 binding->value=(pointer) value;
      return value;  /* If resource returns NULL, return NULL also */
   }
}

#define xres_get_geometry(style) xres_get_resource(&geometry_resources,style)
#define xres_get_bgcolor(style)  xres_get_resource(&bgcolor_resources,style)

void fixup_and_draw(dpy, style, auxblocks, blocks, num, lines, numlines,
		    beepcount)
     Display *dpy;
     char *style;
     xblock *blocks;
     xauxblock *auxblocks;
     int num;
     xlinedesc *lines;
     int numlines;
     int beepcount;
{
    int gram_xalign = 1;
    int gram_yalign = 1;
    int gram_xpos, gram_ypos, gram_xsize, gram_ysize;

    x_gram *gram;
    int strindex = 0;

    int line, block=0;
    int maxwidth=0, chars=0, maxascent, maxdescent;
    int ssize,  lsize,csize, rsize, width;
    int i, ascent, descent;

    int yofs = internal_border_width;
    int lofs, cofs, rofs;
    int ystart,yend;

    char *bgstr, *geometry, xpos[10], ypos[10], xfrom, yfrom;

    gram = (x_gram *)malloc(sizeof(x_gram));

    /* Find total lengths of left, center, and right parts.  Also find the
       length of the longest line and the total number of characters. */

    for (line=0; line<numlines; line++) {
	lsize = csize = rsize = 0;
	maxascent = maxdescent = 0;
	
	/* add up sizes for each block, get max ascent and descent */
	
	for (i=0; i<lines[line].numblock; i++,block++) {
	    chars += auxblocks[block].len;
	    ssize = XTextWidth(auxblocks[block].font, auxblocks[block].str,
			       auxblocks[block].len);
	    auxblocks[block].width = ssize;
	    ascent = auxblocks[block].font->ascent;
	    descent = auxblocks[block].font->descent;
	    if (ascent>maxascent)
	      maxascent = ascent;
	    if (descent>maxdescent)
	      maxdescent = descent;
	    switch (auxblocks[block].align) {
	      case LEFTALIGN:
		lsize += ssize;
		break;
		
	      case CENTERALIGN:
		csize += ssize;
		break;
		
	      case RIGHTALIGN:
		rsize += ssize;
		break;
	    }
	}
	
	/* save what we need to do size fixups */
	
	if (maxascent>lines[line].ascent)
	  lines[line].ascent = maxascent;
	if (maxdescent>lines[line].descent)
	  lines[line].descent = maxdescent;
	lines[line].lsize = lsize;
	lines[line].csize = csize;
	lines[line].rsize = rsize;
	
	/* get width of line and see if it is bigger than the max width */
	
	switch ((lsize?1:0)+(csize?2:0)+(rsize?4:0)) {
#ifdef DEBUG
	  default:
	    abort();
#endif
	    
	  case 0:
	    width = 0;
	    break;
	    
	  case 1:
	    width = lsize;
	    break;
	    
	  case 2:
	    width = csize;
	    break;
	    
	  case 3:
	    /* in all these cases, we just want to add the width of *any*
	       space, so the first font will do just fine. */
	    /* XXX implicit assumption that a line must have at least one
	       block, so that there is indeed a reasonable font in
	       auxblocks[0].font */
	    width = lsize*2+csize+XTextWidth(auxblocks[0].font," ",1);
	    break;
	    
	  case 4:
	    width = rsize;
	    break;
	    
	  case 5:
	    width = lsize+rsize+XTextWidth(auxblocks[0].font, " ", 1);
	    break;
	    
	  case 6:
	    width = csize+rsize*2+XTextWidth(auxblocks[0].font, " ", 1);
	    break;
	    
	  case 7:
	    width = max(lsize,rsize)*2+csize+
	      XTextWidth(auxblocks[0].font," ",1)*2;
	    break;
	}
	if (width>maxwidth)
	  maxwidth = width;
    }

    /* fixup x,y for each block, create big string and indices into it */
    /* set x1,y1,x2,y2 of each block also. */

    gram->text = (char *)malloc(chars);
    block = 0;

    for (line=0; line<numlines; line++) {
	lofs = internal_border_width;
	cofs = ((maxwidth-lines[line].csize)>>1) + internal_border_width;
	rofs = maxwidth-lines[line].rsize + internal_border_width;
	ystart = yofs;
	yofs += lines[line].ascent;
	yend = yofs+lines[line].descent+1;   /* +1 because lines look scrunched
						without it. */

	for (i=0; i<lines[line].numblock; i++,block++) {
	    blocks[block].fid = auxblocks[block].font->fid;
	    switch (auxblocks[block].align) {
	      case LEFTALIGN:
		blocks[block].x = lofs;
		blocks[block].x1 = lofs;
		lofs += auxblocks[block].width;
		blocks[block].x2 = lofs;
		break;
		
	      case CENTERALIGN:
		blocks[block].x = cofs;
		blocks[block].x1 = cofs;
		cofs += auxblocks[block].width;
		blocks[block].x2 = cofs;
		break;

	      case RIGHTALIGN:
		blocks[block].x = rofs;
		blocks[block].x1 = rofs;
		rofs += auxblocks[block].width;
		blocks[block].x2 = rofs;
		break;
	    }
	    blocks[block].y = yofs;
	    blocks[block].y1 = ystart;
	    blocks[block].y2 = yend;
	    blocks[block].strindex = strindex;
	    blocks[block].strlen = auxblocks[block].len;
	    strncpy(gram->text+strindex, auxblocks[block].str,
		    auxblocks[block].len);
	    strindex += blocks[block].strlen;
	}

	yofs = yend;

    }

    if ((geometry = var_get_variable("X_geometry")),(geometry[0]=='\0')) 
      if ((geometry = xres_get_geometry(style))==NULL)
	if ((geometry = var_get_variable("default_X_geometry")),
	    (geometry[0]=='\0'))
	  geometry = "+0+0";
    sscanf(geometry, "%c%[0123456789c]%c%[0123456789c]", &xfrom, xpos,
	   &yfrom, ypos);

    if (xpos[0]=='c') {
      gram_xalign = 0;
      gram_xpos = 0;
    } else
      gram_xpos = atoi(xpos);
    if (xfrom=='-')
      gram_xalign *= -1;

    if (ypos[0]=='c') {
      gram_yalign = 0;
      gram_ypos = 0;
    } else
      gram_ypos = atoi(ypos);
    if (yfrom=='-')
      gram_yalign *= -1;

    if ((bgstr = var_get_variable("X_background")),(bgstr[0]=='\0'))
      if ((bgstr = xres_get_bgcolor(style))==NULL)
	if ((bgstr = var_get_variable("default_X_background")),
	    (bgstr[0]=='\0'))
	  gram->bgcolor = default_bgcolor;
    if (bgstr && bgstr[0])
      gram->bgcolor = x_string_to_color(bgstr,default_bgcolor);

    
    gram_xsize = maxwidth+(internal_border_width<<1);
    gram_ysize = yofs+internal_border_width;
    gram->numblocks = num;
    gram->blocks = blocks;
    
    x_gram_create(dpy, gram, gram_xalign, gram_yalign, gram_xpos,
		  gram_ypos, gram_xsize, gram_ysize, beepcount);
}

/* Silly almost-but-not-quite-useless helper function */
char *no_dots_downcase_var(str)
     char *str;
{
   register char *var, *var2;

   var = string_Downcase(var_get_variable(str));
   var2 = var;
   while (*var++)
      if (*var == '.')
	 *var = '_';
   return(var2);
}

#define MODE_TO_FONT(dpy,style,mode) \
  get_font((dpy),(style),(mode)->font?(mode)->font:(mode)->substyle, \
	   (mode)->size, (mode)->bold+(mode)->italic*2)
void xshow(dpy, desc, numstr, numnl)
     Display *dpy;
     desctype *desc;
     int numstr;
     int numnl;
{
    XFontStruct *font;
    xmode_stack modes = xmode_stack_create();
    xmode curmode;
    xlinedesc *lines;
    xblock *blocks;
    xauxblock *auxblocks;
    int nextblock=0;
    int line=0,linestart=0;
    char *style;
    int beepcount = 0;

    lines = (xlinedesc *)malloc(sizeof(xlinedesc)*(numnl+1));

    blocks = (xblock *)malloc(sizeof(xblock)*numstr);
    auxblocks = (xauxblock *)malloc(sizeof(xauxblock)*numstr);

    curmode.bold = 0;
    curmode.italic = 0;
    curmode.size = MEDIUM_SIZE;
    curmode.align = LEFTALIGN;
    curmode.expcolor = 0;
    curmode.substyle = string_Copy("default");
    curmode.font = NULL;

    style = var_get_variable("style");
    if (style[0] == '\0') {
       style = string_Concat(no_dots_downcase_var("class"),".");
       style = string_Concat2(style,no_dots_downcase_var("instance"));
       style = string_Concat2(style,".");
       style = string_Concat2(style,no_dots_downcase_var("sender"));
       string_Downcase(style);
    }

    for (; desc->code!=DT_EOF; desc=desc->next) {
	switch (desc->code) {
	  case DT_ENV:
	    xmode_stack_push(modes, curmode);
	    curmode.substyle = string_Copy(curmode.substyle);
	    if (curmode.font)
	      curmode.font = string_Copy(curmode.font);
	    
#define envmatch(string,length) ((desc->len==(length)) && (strncasecmp(desc->str,(string),(length))==0))

	    if (envmatch("roman",5)) {
		curmode.bold = 0;
		curmode.italic = 0;
	    } else if (envmatch("bold",4) || envmatch("b",1))
	      curmode.bold = 1;
	    else if (envmatch("italic",6)||envmatch("i",1))
	      curmode.italic = 1;
	    else if (envmatch("large",5))
	      curmode.size = LARGE_SIZE;
	    else if (envmatch("medium",6))
	      curmode.size = MEDIUM_SIZE;
	    else if (envmatch("small",5))
	      curmode.size = SMALL_SIZE;
	    else if (envmatch("left",4)||envmatch("l",1))
	      curmode.align = LEFTALIGN;
	    else if (envmatch("center",6)||envmatch("c",1))
	      curmode.align = CENTERALIGN;
	    else if (envmatch("right",5)||envmatch("r",1))
	      curmode.align = RIGHTALIGN;
	    else if (envmatch("beep",4))
	      beepcount++;
	    else if (envmatch("font",4)) {
	       /* lookahead needed.  desc->next->str should be the
		  font name, and desc->next->next->code should be
		  a DT_END*/
	       if ((desc->next) &&
		   (desc->next->next) &&
		   (desc->next->code == DT_STR) &&
		   (desc->next->next->code==DT_END)) {

		  /* Since @font mutates the current environment, we have
		     to pop the environment that this case usually pushes */
		  free(curmode.substyle);
		  curmode = xmode_stack_top(modes);
		  xmode_stack_pop(modes);

		  /* mutating... */
		  curmode.size=SPECIAL_SIZE; /* This is an @font() */
		  curmode.font=string_CreateFromData(desc->next->str,
						     desc->next->len);
		  /* skip over the rest of the @font */
		  desc=desc->next->next;
	       }
	    } else if (envmatch("color",5)) {
	       /* lookahead needed.  desc->next->str should be the
		  font name, and desc->next->next->code should be
		  a DT_END*/
	       if ((desc->next) &&
		   (desc->next->next) &&
		   (desc->next->code == DT_STR) &&
		   (desc->next->next->code==DT_END)) {
		  char *colorname;

		  /* Since @font mutates the current environment, we have
		     to pop the environment that this case usually pushes */
		  free(curmode.substyle);
		  curmode = xmode_stack_top(modes);
		  xmode_stack_pop(modes);

		  /* mutating... */
		  colorname=string_CreateFromData(desc->next->str,
						  desc->next->len);
		  curmode.color = x_string_to_color(colorname,default_fgcolor);
		  free(colorname);
		  curmode.expcolor = 1;
		  /* skip over the rest of the @font */
		  desc=desc->next->next;
	       }
	    } else if (desc->len > 0) { /* avoid @{...} */
	       free(curmode.substyle);
	       if (curmode.font) {
		  free(curmode.font);
		  curmode.font = NULL;
	       }
	       curmode.substyle = string_CreateFromData(desc->str, desc->len);
	    }
	    break;

	  case DT_STR:
	    auxblocks[nextblock].align = curmode.align;
	    auxblocks[nextblock].font = MODE_TO_FONT(dpy,style,&curmode);
	    auxblocks[nextblock].str = desc->str;
	    auxblocks[nextblock].len = desc->len;
	    if (curmode.expcolor)
	       blocks[nextblock].fgcolor = curmode.color;
	    else
	       blocks[nextblock].fgcolor =
		 x_string_to_color(mode_to_colorname(dpy,style,&curmode),
				   default_fgcolor);
	    nextblock++;
	    break;

	  case DT_END:
	    free(curmode.substyle);
	    curmode = xmode_stack_top(modes);
	    xmode_stack_pop(modes);
	    break;

	  case DT_NL:
	    lines[line].startblock = linestart;
	    lines[line].numblock = nextblock-linestart;
	    font = MODE_TO_FONT(dpy,style,&curmode);
	    lines[line].ascent = font->ascent;
	    lines[line].descent = font->descent;
	    line++;
	    linestart = nextblock;
	    break;
	}
    }

    /* case DT_EOF:    will drop through to here. */

    if (linestart != nextblock) {
       lines[line].startblock = linestart;
       lines[line].numblock = nextblock-linestart;
       font = MODE_TO_FONT(dpy,style,&curmode);
       lines[line].ascent = 0;
       lines[line].descent = 0;
       line++;
    }
    
    free(curmode.substyle);
    fixup_and_draw(dpy, style, auxblocks, blocks, nextblock, lines, line,
		   beepcount);
    free(lines);
    free(auxblocks);
}

static void xhandleevent(dpy, w, event)
     Display *dpy;
     Window w;
     XEvent *event;
{
    x_gram *gram;
    
    if (XFindContext(dpy, w, desc_context, (caddr_t *)&gram))
      return;

    if (event->type == Expose)
      x_gram_expose(dpy, w, gram,&(event->xexpose));
    else
      xcut(dpy, event, desc_context);

    XFlush(dpy);
}

void x_get_input(dpy)
     Display *dpy;
{
    XEvent event;
    
    dprintf1("Entering x_get_input(%x).\n",dpy);

    /*
     * Kludge to get around lossage in XPending:
     *
     * (the problem: XPending on a partial packet returns 0 without
     *  reading in the packet.  This causes a problem when the X server
     *  dies in the middle of sending a packet.)
     */
    if (XPending(dpy)==0)
      XNoOp(dpy);  /* Ensure server is still with us... */
    
    while (XPending(dpy)) {
	XNextEvent(dpy,&event);
	xhandleevent(dpy, event.xany.window, &event);
    }
}
