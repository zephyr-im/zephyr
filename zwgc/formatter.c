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
static char rcsid_formatter_c[] = "$Id$";
#endif

#include <zephyr/mit-copyright.h>

#include <stdio.h>
#include <ctype.h>
#include "new_memory.h"
#include "char_stack.h"
#include "string_dictionary.h"
#include "formatter.h"
#include "text_operations.h"

static int pure_text_length(), env_length();

#ifdef notdef
static character_class atsign_set = { /* '@' = 0x40 */
   0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
   0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
   0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
   0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
   1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
   0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
   0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
   0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
   0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
   0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
   0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
   0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
   0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
   0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
   0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
   0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
  };
#endif

static character_class paren_set = { /* '(' = 0x28, ')' = 0x29 */
   0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
   0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
   0,0,0,0,0,0,0,0,1,1,0,0,0,0,0,0,
   0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
   0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
   0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
   0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
   0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
   0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
   0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
   0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
   0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
   0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
   0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
   0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
   0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
  };

static character_class sbracket_set = { /* '[' = 0x5b, ']' = 0x5d */
   0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
   0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
   0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
   0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
   0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
   0,0,0,0,0,0,0,0,0,0,0,1,0,1,0,0,
   0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
   0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
   0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
   0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
   0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
   0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
   0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
   0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
   0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
   0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
  };

static character_class abracket_set = { /* '<' = 0x3c, '>' = 0x3e */
   0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
   0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
   0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
   0,0,0,0,0,0,0,0,0,0,0,0,1,0,1,0,
   0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
   0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
   0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
   0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
   0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
   0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
   0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
   0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
   0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
   0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
   0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
   0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
  };

static character_class cbracket_set = { /* '{' = 0x7b, '}' = 0x7d */
   0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
   0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
   0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
   0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
   0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
   0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
   0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
   0,0,0,0,0,0,0,0,0,0,0,1,0,1,0,0,
   0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
   0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
   0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
   0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
   0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
   0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
   0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
   0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
  };

static character_class allbracket_set = {
   0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
   0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
   0,0,0,0,0,0,0,0,1,1,0,0,0,0,0,0,
   0,0,0,0,0,0,0,0,0,0,0,0,1,0,1,0,
   0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
   0,0,0,0,0,0,0,0,0,0,0,1,0,1,0,0,
   0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
   0,0,0,0,0,0,0,0,0,0,0,1,0,1,0,0,
   0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
   0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
   0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
   0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
   0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
   0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
   0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
   0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
  };

static character_class allmaskable_set = {
   0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
   0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
   0,0,0,0,0,0,0,0,1,1,0,0,0,0,0,0,
   0,0,0,0,0,0,0,0,0,0,0,0,1,0,1,0,
   1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
   0,0,0,0,0,0,0,0,0,0,0,1,0,1,0,0,
   0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
   0,0,0,0,0,0,0,0,0,0,0,1,0,1,0,0,
   0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
   0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
   0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
   0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
   0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
   0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
   0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
   0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
  };

static char brackets[]="()<>[]{}@";
static char *openbracket[]={"@<","@<","@[","@[","@{","@{","@(","@(","@("};
static char *closebracket[]={">",">","]","]","}","}",")",")",")"};

/* the char * that str points to is free'd by this function.
 * if you want to keep it, save it yourself
 */
string verbatim(str)
     string str;
{
   char *temp,*temp2;
   int bracketnum,len;

   if (strlen(str) == pure_text_length(str,0)) {
      /* No environments, so consider the fast-and-easy methods */

      if (not_contains(str,allbracket_set))
	 return(string_Copy(str));

      if (not_contains(str,abracket_set)) {
	 temp=(char *) malloc((len=strlen(str))+4);
	 temp[0]='@';
	 temp[1]='<';
	 bcopy(str,temp+2,len);
	 temp[len+2]='>';
	 temp[len+3]='\0';
	 return(temp);
      }
      if (not_contains(str,sbracket_set)) {
	 temp=(char *) malloc((len=strlen(str))+4);
	 temp[0]='@';
	 temp[1]='[';
	 bcopy(str,temp+2,len);
	 temp[len+2]=']';
	 temp[len+3]='\0';
	 return(temp);
      }
      if (not_contains(str,cbracket_set)) {
	 temp=(char *) malloc((len=strlen(str))+4);
	 temp[0]='@';
	 temp[1]='{';
	 bcopy(str,temp+2,len);
	 temp[len+2]='}';
	 temp[len+3]='\0';
	 return(temp);
      }
      if (not_contains(str,paren_set)) {
	 temp=(char *) malloc((len=strlen(str))+4);
	 temp[0]='@';
	 temp[1]='(';
	 bcopy(str,temp+2,len);
	 temp[len+2]=')';
	 temp[len+3]='\0';
	 return(temp);
      }
   }

   temp=lbreak(&str,allmaskable_set);
   while(*str) {
      bracketnum=(int) (index(brackets,str[0])-brackets);
      temp=string_Concat2(temp,openbracket[bracketnum]);
      temp=string_Concat2(temp,temp2=lany(&str," "));
      free(temp2);
      temp=string_Concat2(temp,closebracket[bracketnum]);
      temp=string_Concat2(temp,temp2=lbreak(&str,allmaskable_set));
      free(temp2);
   }
   free(str);  /* str is "" at this point, anyway */

   return(temp);
}

/* text points to beginning of text string.  return value is
   length of string, up to but not including the passed terminator
   or the default terminator \0.  The text will not be modified,
   and @@ will be counted twice */

static int pure_text_length(text,terminator)
     char *text;
     char terminator;
{
   int len=0;

   while (1) {
      while (*text!='@' && *text!=terminator && *text) {
         text++;
         len++;
      }

      if (*text!='@')
         return(len);

      if (*(text+1)=='@') {
	 text++;
	 len++;
      } else if (env_length(text+1) != -1)
        return(len);

      text++;
      len++;
   }
}

/* returns length of "block" pointed to by str, where a block is a
 * combination of pure strings and environments, surrounded by one
 * valid environment.  If str does not point to an environment 
 * then -1 is returned.  No replacement of @@ is made.
*/

static char otherside(opener)
char opener;
{
   switch (opener) {
    case '(':
      return(')');
    case '{':
      return('}');
    case '[':
      return(']');
    case '<':
      return('>');
   }

#ifdef DEBUG
   abort();
#endif
}

int length_of_block(str)
     string str;
{
   int len,temp;
   char terminator;

   if ((! str[0])||(str[0]!='@')||((len=env_length(str+1)) == -1))
      return(-1);

   len++;
   terminator=otherside(str[len++]);
   do {
      len+=((temp=length_of_block(str+len)) != -1)?
	   (temp):
	   (pure_text_length(str+len,terminator));
   } while (str[len] && str[len]!=terminator);

   return(str[len]?len+1:len);
}

/* returns a character to close the most recently opened environment,
 * or \0 if there are no open environments.
 */

int close_bracket(str,terminator)
     string str;
     char terminator;
{
   int len=0,temp;
   char ch;

   while (str[len]) {
      if (temp=pure_text_length(str+len,terminator)) {
	 if (str[len+temp])
	    len+=temp;
	 else
	    return(terminator);
      } else if (str[len+temp] == terminator) {
	 len++;
	 terminator=0;
      } else {
	 temp=env_length(str+len+1);
	 if (ch=close_bracket(str+len+temp+2,otherside(str[len+temp+1])))
	    return(ch);
	 else
	    len+=length_of_block(str+len);
      }
   }

   return(str[len]?'\0':terminator);
}

string protect(str)
     string str;
{
   string temp,temp2,temp3;
   int len,len2,ch;

   /* verbatim all top-level strings */

   temp=string_Copy("");
   while(*str) {
      if ((len=length_of_block(str)) == -1) {
	 temp2=string_CreateFromData(str,len=pure_text_length(str,0));
	 str+=len;
	 temp3=verbatim(temp2);
	 temp=string_Concat2(temp,temp3);
	 free(temp3);
      } else {
	 temp2=string_CreateFromData(str,len);
	 str+=len;
	 temp=string_Concat2(temp,temp2);
	 free(temp2);
      }
   }
   len2=string_Length(temp);
   len=len2-len;
   temp2=temp+len;
   while (ch=close_bracket(temp2,0)>0) {
      temp=(char *) realloc(temp,++len2);
      temp[len2-2]=ch;
      temp[len2-1]='\0';
      temp2=temp+len;
   }

   return(temp);
}

int not_contains(str, set)
     string str;
     character_class set;
{
   while (*str && ! set[*str]) str++;
   return (! *str);
}

void free_desc(desc)
     desctype *desc;
{
    desctype *next_desc;

    while (desc->code != DT_EOF) {
	next_desc = desc->next;
	free(desc);
	desc = next_desc;
    }
    free(desc);
}

/* text points to beginning of possible env name.  return value is
   length of env name, not including @ or opener, or -1 if not a
   possible env name. */
static int env_length(text)
     char *text;
{
   int len=0;

   while (*text && (isalnum(*text) || *text=='_')) {
      text++;
      len++;
   }

   if ((*text=='(') || (*text=='{') || (*text=='[') || (*text=='<'))
     return(len);
   else
     return(-1);
}

/* text points to beginning of text string.  return value is
   length of string, up to but not including the passed terminator
   or the default terminators \0 \n @.  This can modify text, and 0
   is a valid return value. */
static int text_length(text,terminator)
     char *text;
     char terminator;
{
   int len=0;

   while (1) {
      while (*text!='@' && *text!='\n' && *text!=terminator && *text) {
	 text++;
	 len++;
      }

      if (*text!='@')
	 return(len);

      if (*(text+1)=='@')
	 bcopy(text+2,text+1,strlen(text+1));
      else if (env_length(text+1) != -1)
	return(len);

      text++;
      len++;
   }
}

/* parses str into a desc linked list.  Returns number of strings and
   newlines in *pstr and *pnl */

desctype *disp_get_cmds(str,pstr,pnl)
char *str;
int *pstr,*pnl;
{
   desctype *desc,*here;
   int len;
   char_stack terminators = char_stack_create();
   char terminator;
   int nstr=0, nnl=0;
   char *curstr;

   desc=(desctype *) malloc(sizeof(desctype));
   here=desc;
   curstr=str;
   terminator = '\0';

   while (*curstr) {
      if (*curstr=='\n') {
	 here->code=DT_NL;
	 curstr++;
	 nnl++;
      } else if (*curstr==terminator) { /* if this is the end of an env */
	 here->code=DT_END;
	 terminator = char_stack_top(terminators);
	 char_stack_pop(terminators);
	 curstr++;
      } else if (len=text_length(curstr,terminator)) { /* if there is a text
							  block here */
	 here->code=DT_STR;
	 here->str=curstr;
	 here->len=len;
	 curstr+=len;
	 nstr++;
      } else if (*curstr=='@') { /* if this is the beginning of an env */
	 len=env_length(curstr+1);
	 here->code=DT_ENV;
	 here->str=curstr+1;
	 here->len=len;
	 char_stack_push(terminators, terminator);
	 terminator=otherside(*(curstr+1+len));
	 curstr+=(len+2); /* jump over @, env name, and opener */
      }

      here->next=(desctype *) malloc(sizeof(desctype));
      here=here->next;
   }

   while (!char_stack_empty(terminators)) {
      here->code=DT_END;
      terminator = char_stack_top(terminators);
      char_stack_pop(terminators);
      here->next=(desctype *) malloc(sizeof(desctype));
      here=here->next;
   }
   here->code=DT_EOF;
   *pstr=nstr;
   *pnl=nnl;

#ifdef DEBUG_PRINTOUT
   { string temp;
       here = desc;
       while (here->code != DT_EOF) {
	   if (here->code == DT_STR || here->code == DT_ENV) {
	       temp = string_CreateFromData(here->str, here->len);
	       printf("[%d <%s>]\n", here->code, temp);
	       free(temp);
	   } else
	     printf("[%d]\n", here->code);
	   here=here->next;
       }
 }
#endif

   return(desc);
}
