/****************************************************************************/
/*                                                                          */
/*                         The tty & plain filters:                         */
/*                                                                          */
/****************************************************************************/

#include <stdio.h>
#include "new_memory.h"
#include "new_string.h"
#include "string_dictionary_aux.h"
#include "formatter.h"
#include "zwgc.h"

/***************************************************************************/

extern int tgetent();
extern char *tgetstr(),*getenv();

/* Dictionary naming convention:

   B.xxx is the termcap sequence to begin environment xxx.
   E.xxx is the termcap sequence to end environment xxx.

   */

static string_dictionary termcap_dict;

/* Define the following commands:

   (Hopefully) shared with all devices:
   
   @center	Guess.
   
   @em		Emphasis.  User underline if available, else reverse video.
   @bold	Bold letters.  If not available, reverse video, else underline.
   @bell	"bl" termcap entry, else "^G"

   Other:

   @blink	"mb"/"me" termcap entry, else nothing.
   @rv		"so"/"se" termcap entry.
   @u		"us"/"ue" termcap entry.
 */

#define TD_SET(k,v) (string_dictionary_Define(termcap_dict,(k),&ex)->value = (v))

int tty_filter_init()
{
    static char st_buf[128];
    char tc_buf[1024], *p = st_buf, *tmp, *term;
    int ex;
    string_dictionary_binding *b;
    static int inited_once = 0;

    if (inited_once)
      return(0);
    else
      inited_once = 1;

    termcap_dict = string_dictionary_Create(7);

    if (!(term = getenv("TERM"))) {	/* Only use termcap if $TERM.	*/
	fputs("zwgc: $TERM not set.  tty mode not functional.\n",stderr);
	return(1);
    }
    tgetent(tc_buf, term);
    
    /* Step 1: get all of {rv,bold,u,bell,blink} that are available.	*/
    
    if (tmp = tgetstr("md",&p)) {	/* bold ? */
	TD_SET("B.bold",tmp);
	TD_SET("E.bold",tgetstr("me",&p));
    }
    if (tmp = tgetstr("mr",&p)) {	/* reverse video? */
	TD_SET("B.rv",tmp);
	TD_SET("E.rv",tgetstr("me",&p));
    }
    if (tmp = tgetstr("bl",&p)) {	/* Bell ? */
	TD_SET("B.bell",tmp);
	TD_SET("B.bell",NULL);
    }
    if (tmp = tgetstr("mb",&p)) {	/* Blink ? */
	TD_SET("B.blink",tmp);
	TD_SET("E.blink",tgetstr("me",&p));
    }
    if (tmp = tgetstr("us",&p))	{ /* Underline ? */
	TD_SET("B.u",tmp);
	TD_SET("E.u", tgetstr("ue",&p));
    }
    if (tmp = tgetstr("so",&p))	{ /* Standout ? */
	TD_SET("B.so",tmp);
	TD_SET("E.so", tgetstr("se",&p));
    }
    
    /* Step 2: alias others to the nearest substitute */
    
    /* Bold = so, else rv, else ul */
    if (NULL == string_dictionary_Lookup(termcap_dict,"B.bold")) {
	if(b = string_dictionary_Lookup(termcap_dict,"B.so")) {
	    TD_SET("B.bold",b->value);
	    TD_SET("E.bold",
		   string_dictionary_Lookup(termcap_dict,"E.so")->value);
	} else if (b = string_dictionary_Lookup(termcap_dict,"B.rv")) {
	    TD_SET("B.bold",b->value);
	    TD_SET("E.bold",
		   string_dictionary_Lookup(termcap_dict,"E.rv")->value);
	} else if (b = string_dictionary_Lookup(termcap_dict,"B.u")) {
	    TD_SET("B.bold",b->value);
	    TD_SET("E.bold",
		   string_dictionary_Lookup(termcap_dict,"E.u")->value);
	}
    }
    
    /* Bell = ^G */
    if (NULL == string_dictionary_Lookup(termcap_dict,"B.bell")) {
	TD_SET("B.bell","\007");
	TD_SET("E.bell",NULL);
    }
    
    /* Underline -> nothing */
    /* Blink -> nothing */
    
    return(0);
}

/***************************************************************************/




static int fixed_string_eq(pattern, text, text_length)
     string pattern;
     char *text;
     int text_length;
{
    while (*pattern && text_length>0 && *pattern == *text) {
	pattern++;
	text++;
	text_length--;
    }

    return(!*pattern && !text_length);
}

typedef struct _tty_str_info {
    struct _tty_str_info *next;

    char *str;
    int len;

    char alignment; /* 'l', 'c', 'r', or ' ' to indicate newline */
    int bold_p;
    int italic_p;
} tty_str_info;

static void free_info(info)
     tty_str_info *info;
{
    tty_str_info *next_info;

    while (info) {
	next_info = info->next;
	free(info);
	info = next_info;
    }
}

static void do_mode_change(current_mode_p, text, text_length)
     tty_str_info *current_mode_p;
     char *text;
     int text_length;
{
    /* alignment commands: */
    if (fixed_string_eq("left", text, text_length) ||
	fixed_string_eq("l", text, text_length))
      current_mode_p->alignment = 'l';
    else if (fixed_string_eq("center", text, text_length) ||
	fixed_string_eq("c", text, text_length))
      current_mode_p->alignment = 'c';
    else if (fixed_string_eq("right", text, text_length) ||
	fixed_string_eq("r", text, text_length))
      current_mode_p->alignment = 'r';

    /* font commands: */
    else if (fixed_string_eq("bold", text, text_length))
      current_mode_p->bold_p = 1;
    else if (fixed_string_eq("italic", text, text_length))
      current_mode_p->italic_p = 1;
    else if (fixed_string_eq("roman", text, text_length)) {
	current_mode_p->bold_p = 0;
	current_mode_p->italic_p = 0;
    }
}

static tty_str_info *convert_desc_to_tty_str_info(desc)
     desctype *desc;
{
#ifdef SABER  /* This is needed due to a bug in saber */
    tty_str_info current_mode;
#else
    tty_str_info current_mode = { NULL, "", 0, 'l', 0 , 0};
#endif
    tty_str_info *temp;
    tty_str_info *result = NULL;
    tty_str_info *last_result_block = NULL;

#ifdef SABER
    current_mode.next = NULL;
    current_mode.str = "";
    current_mode.len = 0;
    current_mode.alignment = 'l';
    current_mode.bold_p = 0;
    current_mode.italic_p = 0;
#endif

    for (; desc->code!=DT_EOF; desc=desc->next) {
	/* Handle environments: */
	if (desc->code == DT_ENV) {
	    /* PUSH! */
	    temp = (tty_str_info *)malloc(sizeof(struct _tty_str_info));
	    *temp = current_mode;
	    current_mode.next = temp;

	    do_mode_change(&current_mode, desc->str, desc->len);
	    continue;
	} else if (desc->code == DT_END) {
	    /* POP! */
	    temp = current_mode.next;
	    current_mode = *temp;
	    free(temp);
	    continue;
	}

	/* Add new block (call it temp) to result: */
	temp = (tty_str_info *)malloc(sizeof(struct _tty_str_info));
	if (last_result_block) {
	    last_result_block->next = temp;
	    last_result_block = temp;
	} else {
	    result = temp;
	    last_result_block = temp;
	}

	if (desc->code == DT_STR) {
	    /* just combine string info with current mode: */
	    *temp = current_mode;
	    temp->str = desc->str;
	    temp->len = desc->len;
	} else if (desc->code == DT_NL) {
	    /* make the new block a ' ' alignment block with an empty string */
	    temp->alignment = ' ';
	    temp->len = 0;
	}
    }

    if (last_result_block)
      last_result_block->next = NULL;

    return(result);
}

#define  max(a,b)                ((a)>(b)?(a):(b))

static int line_width(left_width, center_width, right_width)
     int left_width;
     int center_width;
     int right_width;
{
    if (center_width>0) {
	if (left_width==0 && right_width==0)
	  return(center_width);
	return(center_width+2+max(left_width,right_width)*2);
    } else {
	if (left_width && right_width)
	  return(1+left_width+right_width);
	else
	  return(left_width+right_width);
    }
}

static int calc_max_line_width(info)
     tty_str_info *info;
{
    int max_line_width = 0;
    int left = 0;
    int center = 0;
    int right = 0;

    for (; info; info=info->next) {
	switch (info->alignment) {
	  case 'l':
	    left += info->len;
	    break;

	  case 'c':
	    center += info->len;
	    break;

	  case 'r':
	    right += info->len;
	    break;

	  case ' ':
#ifdef DEBUG
	    if (zwgc_debug)
	      printf("width: %d %d %d = %d\n", left, center, right,
		     line_width(left, center, right));
#endif
	    max_line_width = max(max_line_width,
				 line_width(left, center, right));
	    left = center = right = 0;
	    break;
	}
    }

#ifdef DEBUG
    if (zwgc_debug)
      printf("width: %d %d %d = %d\n", left, center, right,
	     line_width(left, center, right));
#endif
    max_line_width = max(max_line_width,
			 line_width(left, center, right));

    return(max_line_width);
}

string tty_filter(text, use_fonts)
     string text;
     int use_fonts;
{
    string text_copy = string_Copy(text);
    string result_so_far = string_Copy("");
    desctype *desc;
    int number_of_strs;
    int number_of_lines;
    tty_str_info *info;
    int max_line_width;

    desc = disp_get_cmds(text_copy, &number_of_strs, &number_of_lines);
    info = convert_desc_to_tty_str_info(desc);
    free_desc(desc);

#ifdef DEBUG
    if (zwgc_debug)
      { tty_str_info *ptr;
	for (ptr=info; ptr; ptr=ptr->next) {
	    printf("%c: %s %s <%s>\n", ptr->alignment,
		   ptr->bold_p ? "(bold)" : "",
		   ptr->italic_p ? "(italic)" : "",
		   string_CreateFromData(ptr->str, ptr->len));
	}
    }
#endif

    max_line_width = calc_max_line_width(info);
    dprintf1("max width = %d\n", max_line_width);

    while (info) {
	string left, center, right;
	int left_width, center_width, right_width;
	char *temp;

	left_width = center_width = right_width = 0;
	left = string_Copy("");
	center = string_Copy("");
	right = string_Copy("");

	for (; info && info->alignment!=' '; info=info->next) {
	    string item = string_Copy("");
	    
	    if (info->bold_p && use_fonts) {
		if (temp = string_dictionary_Fetch(termcap_dict, "B.rv"))
		  item = string_Concat2(item, temp);
	    } else if (info->italic_p && use_fonts) {
		if (temp = string_dictionary_Fetch(termcap_dict, "B.u"))
		  item = string_Concat2(item, temp);
	    }

	    temp = string_CreateFromData(info->str, info->len);
	    item = string_Concat2(item, temp);
	    free(temp);

	    if (info->bold_p && use_fonts) {
		if (temp = string_dictionary_Fetch(termcap_dict, "E.rv"))
		  item = string_Concat2(item, temp);
	    } else if (info->italic_p && use_fonts) {
		if (temp = string_dictionary_Fetch(termcap_dict, "E.u"))
		  item = string_Concat2(item, temp);
	    }

	    switch (info->alignment) {
	      default:
	      case 'l':
		left = string_Concat2(left, item);
		left_width += info->len;
		break;

	      case 'c':
		center = string_Concat2(center, item);
		center_width += info->len;
		break;

	      case 'r':
		right = string_Concat2(right, item);
		right_width += info->len;
		break;
	    }
	    free(item);
	}

	result_so_far = string_Concat2(result_so_far, left);
	if (center_width)
	  while (left_width < (max_line_width-center_width)/2 ) {
	      result_so_far = string_Concat2(result_so_far, " ");
	      left_width++;
	  }
	result_so_far = string_Concat2(result_so_far, center);
	left_width += center_width;

	if (right_width)
	  while (left_width<max_line_width-right_width) {
	      result_so_far = string_Concat2(result_so_far, " ");
	      left_width++;
	  }
	result_so_far = string_Concat2(result_so_far, right);
	free(left);  free(center);  free(right);

	if (info->alignment == ' ') {
	    info = info->next;
	    result_so_far = string_Concat2(result_so_far, "\n");
	}
    }

    free_info(info);
    free(text_copy);
    return(result_so_far);
}
