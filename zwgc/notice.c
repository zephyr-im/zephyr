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
static char rcsid_notice_c[] = "$Header$";
#endif

#include <zephyr/mit-copyright.h>

/****************************************************************************/
/*                                                                          */
/*         Module containing code to extract a notice's fields:             */
/*                                                                          */
/****************************************************************************/

#include <zephyr/zephyr.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "new_memory.h"
#include "error.h"
#include "variables.h"
#include "notice.h"

/*
 *    int count_nulls(char *data, int length)
 *        Requires: length>=0
 *        Effects: Returns the # of nulls in data[0]..data[length-1]
 */

int count_nulls(data, length)
     char *data;
     int length;
{
    int count = 0;

    for (; length; data++, length--)
      if (!*data)
	count++;

    return(count);
}

/*
 *    string get_next_field(char **data_p, int *length_p)
 *        Requires: *length_p >= 0
 *        Modifies: *data_p, *length_p
 *        Effects: Treats (*data_p)[0], (*data_p)[1], ... (*data_p)[length-1]
 *                 as a series of null-seperated fields.  This function
 *                 returns a copy of the first field on the heap.  This
 *                 string must eventually be freed.  Also, *data_p is
 *                 advanced and *length_p decreased so that another
 *                 call to this procedure with the same arguments will
 *                 return the second field.  The next call will return
 *                 the third field, etc.  "" is returned if 0 fields
 *                 remain.  (this is the case when *length_p == 0)
 */

string get_next_field(data_p, length_p)
     char **data_p;
     int *length_p;
{
    char *data = *data_p;
    int length = *length_p;
    char *ptr;

    for (ptr=data; length; ptr++, length--)
      if (!*ptr) {
	  *data_p = ptr+1;
	  *length_p = length-1;
	  return(string_Copy(data));
      }

    length = *length_p;
    *data_p = ptr;
    *length_p = 0;
    return(string_CreateFromData(data, length));
}

/*
 *    string get_field(char *data, int length, int num)
 *        Requires: length>=0, num>0
 *        Effects: Treats data[0]..data[length-1] as a series of
 *                 null-seperated fields.  This function returns a copy of
 *                 the num'th field (numbered from 1 in this case) on the
 *                 heap.  This string must eventually be freed.  If there
 *                 is no num'th field (because num<1 or num># of fields),
 *                 "" is returned.
 */

string get_field(data, length, num)
     char *data;
     int length;
     int num;
{
    /*
     * While num>1 and there are fields left, skip a field & decrement num:
     */
    while (length && num>1) {
	if (!*data)
	  num--;
	length--;
	data++;
    }

    /*
     * If any more fields left, the first field is the one we want.
     * Otherwise, there is no such field as num -- return "".
     */
    if (length)
      return(get_next_field(&data, &length));
    else
      return(string_Copy(""));
}

/*
 *    string convert_nulls_to_newlines(data, length)
 *       Requires: length>=0, malloc never returns NULL
 *       Effects: Takes data[0]..data[length-1], converts all nulls to
 *                newlines ('\n') and returns the result as a null-terminated
 *                string on the heap.  The returned string must eventually
 *                be freed.
 */

string convert_nulls_to_newlines(data, length)
     char *data;
     int length;
{
    char *result, *ptr;
    char c;

    result = (char *) malloc(length+1);
    result[length] = '\0';
    
    for (ptr=result; length; data++, ptr++, length--)
      *ptr = (c = *data) ? c : '\n';

    return(result);
}


/*
 *  Internal Routine:
 *
 *    string z_kind_to_ascii(ZNotice_Kind_t z_kind)
 *        Effects: Returns an ascii representation for z_kind.
 *                 The string returned is on the heap and must be freed
 *                 eventually.
 */

static string z_kind_to_ascii(z_kind)
     ZNotice_Kind_t z_kind;
{
    string result;

    switch (z_kind) {
      case UNSAFE:
	result = "unsafe";
	break;

      case UNACKED:
	result = "unacked";
	break;

      case ACKED:
	result = "acked";
	break;

      case HMACK:
	result = "hmack";
	break;

      case HMCTL:
	result = "hmctl";
	break;

      case SERVACK:
	result = "servack";
	break;

      case SERVNAK:
	result = "servnak";
	break;

      case CLIENTACK:
	result = "clientack";
	break;

      case STAT:
	result = "stat";
	break;

      default:
	result = "<unknown kind>";
	break;
    }
    
    return(string_Copy(result));
}

/*
 *  Internal Routine:
 *
 *    string z_auth_to_ascii(int z_auth)
 *        Effects: Returns an ascii representation for z_auth.
 *                 The string returned is on the heap and must be freed
 *                 eventually.
 */

static string z_auth_to_ascii(z_auth)
     int z_auth;
{
    string result;

    switch (z_auth) {
      case ZAUTH_FAILED:
	result = "forged";
	break;

      case ZAUTH_NO:
	result = "no";
	break;
	
      case ZAUTH_YES:
	result = "yes";
	break;

      default:
	result = "unknown";
	break;
    }
    
    return(string_Copy(result));
}

/*
 *    char *decode_notice(ZNotice_t *notice)
 *        Modifies: various description language variables
 *        Effects:
 */

char *decode_notice(notice)
     ZNotice_t *notice;
{
    char *temp;
    string time, notyear, year, date_string, time_string;
    struct hostent *fromhost;

    /*
     * Convert useful notice fields to ascii and store away in
     * description language variables for later use by the
     * the user's program:
     */
    var_set_variable("zephyr_version", notice->z_version);
    var_set_variable("class", notice->z_class);
    var_set_variable("instance", notice->z_class_inst);
    var_set_variable("opcode", notice->z_opcode);
    var_set_variable("default", notice->z_default_format);
    var_set_variable("recipient", notice->z_recipient);
    var_set_variable("fullsender", notice->z_sender);
    var_set_variable_to_number("port", (int)notice->z_port);
    var_set_variable_then_free_value("kind", z_kind_to_ascii(notice->z_kind));
    var_set_variable_then_free_value("auth", z_auth_to_ascii(notice->z_auth));

    /*
     * Set $sender to the name of the notice sender except first strip off the
     * realm name if it is the local realm:
     */
    if ( (temp=index(notice->z_sender,'@')) && string_Eq(temp+1, ZGetRealm()) )
      var_set_variable_then_free_value("sender",
				string_CreateFromData(notice->z_sender,
						      temp-notice->z_sender));
    else
      var_set_variable("sender", notice->z_sender);
    
    /*
     * Convert time & date notice was sent to ascii.  The $time
     * has the format "01:03:52" while $date has the format
     * "Sun Sep 16 1973".
     */
    time = ctime(&(notice->z_time.tv_sec));
    time_string = string_CreateFromData(time+11,8);
    var_set_variable_then_free_value("time", time_string);
    date_string = string_Concat(notyear=string_CreateFromData(time,11),
				year=string_CreateFromData(time+20,4));
    var_set_variable_then_free_value("date", date_string);
    free(notyear);
    free(year);

    /*
     * Convert host notice sent from to ascii:
     */
    fromhost = gethostbyaddr(&(notice->z_sender_addr), sizeof(struct in_addr),
			   AF_INET);
    var_set_variable("fromhost", fromhost ? fromhost->h_name :
		     inet_ntoa(notice->z_sender_addr));

    /*
     * Set $message to the message field of the notice with nulls changed
     * to newlines:
     */
    var_set_variable_then_free_value("message",
		     convert_nulls_to_newlines(notice->z_message,
					       notice->z_message_len));

    /*
     * Decide if its a control notice.  If so, return the notice's
     * opcode.  Otherwise, return NULL:
     */
    if ((strcasecmp(notice->z_class, WG_CTL_CLASS)==0) && /* <<<>>> */
	(strcasecmp(notice->z_class_inst, WG_CTL_USER)==0))
      return(notice->z_opcode);
    return(0);
}
