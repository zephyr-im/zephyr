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
static char rcsid_subscriptions_c[] = "$Id$";
#endif

/****************************************************************************/
/*                                                                          */
/*        Subscriptions.c: code to deal with subscriptions & punting:       */
/*                                                                          */
/****************************************************************************/

#include <stdio.h>
#include <zephyr/zephyr.h>
#include <sys/param.h>
#include <netdb.h>
#include "new_memory.h"
#include "new_string.h"
#include "int_dictionary.h"
#include "zwgc.h"
#include "subscriptions.h"
#include "error.h"
#include "file.h"
#include "main.h"

/****************************************************************************/
/*                                                                          */
/*                  Code to implement punting of notices:                   */
/*                                                                          */
/****************************************************************************/

/*
 *
 */
static int_dictionary puntable_addresses_dict = 0;

static void init_puntable_dict()
{
    puntable_addresses_dict = int_dictionary_Create(33);
}

static string address_to_string(class, instance, recipient)
     string class;
     string instance;
     string recipient;
{
    string result;

    /*
     * Treat a recipient of "" as "*":
     */
    if (string_Eq(recipient,""))
      recipient = "*";

    /*
     * The following is a hack for now only.  It should be replaced with
     * several calls to escape_code... <<<>>>
     */
    result = string_Concat(class, "\001");
    result = string_Concat2(result, instance);
    result = string_Concat2(result, "\001");
    result = string_Concat2(result, recipient);
    string_Downcase(result);

    return(result);
}

int puntable_address_p(class, instance, recipient)
     string class;
     string instance;
     string recipient;
{
    string temp;

    if (!puntable_addresses_dict)
      init_puntable_dict();

    temp = address_to_string(class, instance, recipient);
    if (int_dictionary_Lookup(puntable_addresses_dict, temp)) {
	free(temp);
	return(1);
    }

    free(temp);
    return(0);
}

void punt(class, instance, recipient)
     string class;
     string instance;
     string recipient;
{
    string temp;

    if (!puntable_addresses_dict)
      init_puntable_dict();

    temp = address_to_string(class, instance, recipient);
    (void)int_dictionary_Define(puntable_addresses_dict, temp, 0);
    free(temp);
}

void unpunt(class, instance, recipient)
     string class;
     string instance;
     string recipient;
{
    string temp;
    int_dictionary_binding *binding;

    if (!puntable_addresses_dict)
      init_puntable_dict();

    temp = address_to_string(class, instance, recipient);
    binding = int_dictionary_Define(puntable_addresses_dict, temp, 0);
    free(temp);
    if (binding)
      int_dictionary_Delete(puntable_addresses_dict, binding);
}

/****************************************************************************/
/*                                                                          */
/*           Code to implement batching [un]subscription requests:          */
/*                                                                          */
/****************************************************************************/

/*
 * <<<>>> these routines require zwgc_active to be false (0)
 */

#define  BATCH_SIZE   20

static int subscription_list_size = 0;
static ZSubscription_t subscription_list[BATCH_SIZE];

static int unsubscription_list_size = 0;
static ZSubscription_t unsubscription_list[BATCH_SIZE];

static void free_subscription_list(list, number_of_elements)
     ZSubscription_t *list;
     int number_of_elements;
{
    int i;

    for (i=0; i<number_of_elements; i++) {
	free(list[i].zsub_class);
	free(list[i].zsub_classinst);
	free(list[i].zsub_recipient);
    }
}

static void flush_subscriptions()
{
      TRAP(ZSubscribeTo(subscription_list,subscription_list_size, 0),
	   "while subscribing");

    free_subscription_list(subscription_list, subscription_list_size);
    subscription_list_size = 0;
}

static void flush_unsubscriptions()
{
    if (unsubscription_list_size)
      TRAP(ZUnsubscribeTo(unsubscription_list, unsubscription_list_size, 0),
	   "while unsubscribing");

    free_subscription_list(unsubscription_list, unsubscription_list_size);
    unsubscription_list_size = 0;
}

static void subscribe(class, instance, recipient)
     string class;
     string instance;
     string recipient;
{
    subscription_list[subscription_list_size].zsub_class = string_Copy(class);
    subscription_list[subscription_list_size].zsub_classinst= string_Copy(instance);
    subscription_list[subscription_list_size].zsub_recipient=string_Copy(recipient);

    if (++subscription_list_size == BATCH_SIZE)
      flush_subscriptions();
}

static void unsubscribe(class, instance, recipient)
     string class;
     string instance;
     string recipient;
{
    unsubscription_list[unsubscription_list_size].zsub_class = string_Copy(class);
    unsubscription_list[unsubscription_list_size].zsub_classinst
      = string_Copy(instance);
    unsubscription_list[unsubscription_list_size].zsub_recipient
      = string_Copy(recipient);

    if (++unsubscription_list_size == BATCH_SIZE)
      flush_unsubscriptions();
}

/****************************************************************************/
/*                                                                          */
/*         Code to implement reading [un]subscriptions from a file:         */
/*                                                                          */
/****************************************************************************/

#define	TOKEN_HOSTNAME	"%host%"
#define	TOKEN_CANONNAME	"%canon%"
#define	TOKEN_ME	"%me%"
#define	TOKEN_WILD	"*"

char ourhost[MAXHOSTNAMELEN],ourhostcanon[MAXHOSTNAMELEN];

static void inithosts()
{
    struct hostent *hent;
    if (gethostname(ourhost,sizeof(ourhost)-1) == -1) {
	ERROR3("unable to retrieve hostname, %s and %s will be wrong in subscriptions.\n", TOKEN_HOSTNAME, TOKEN_CANONNAME);
	return;
    }

    if (!(hent = gethostbyname(ourhost))) {
	ERROR2("unable to resolve hostname, %s will be wrong in subscriptions.\n", TOKEN_CANONNAME);
	return;
    }
    (void) strncpy(ourhostcanon,hent->h_name, sizeof(ourhostcanon)-1);
    return;
}

static void macro_sub(str)
     char *str;
{
    static int initedhosts = 0;

    if (!initedhosts) {
	inithosts();
	initedhosts = 1;
    }
    if (string_Eq(str, TOKEN_ME))
	strcpy(str, ZGetSender());
    else if (string_Eq(str, TOKEN_HOSTNAME))
	strcpy(str, ourhost);	
    else if (string_Eq(str, TOKEN_CANONNAME))
	strcpy(str, ourhostcanon);
}

#define  UNSUBSCRIBE_CHARACTER  '!'
#define  PUNT_CHARACTER         '-'

static void load_subscriptions_from_file(file)
     FILE *file;
{
    char line[BUFSIZ];
    char class_buffer[BUFSIZ], instance[BUFSIZ], recipient[BUFSIZ];
    char *class, *temp;
    char c;
   
    while ((!feof(file)) && (!ferror(file))) {
	if (fgets(line, BUFSIZ, file)) {
	    class = class_buffer;
	    /* Parse line */
	    /* <<<>>>
	     * The below does NOT work is the recipient field  is "":
	     */ 
	    if (temp = index(line, '#'))
	      *temp = '\0';
	    for (temp=line; *temp && *temp==' '; temp++) ;
	    if (!*temp || *temp=='\n')
	      continue;

	    sscanf(temp,"%[^,],%[^,],%s", class, instance, recipient);

	    /* skip type indicator if any: */
	    c = class[0];
	    if (c==UNSUBSCRIBE_CHARACTER || c==PUNT_CHARACTER)
	      class++;
	    
	    /* perform macro substitutions */
	    macro_sub(class);
	    macro_sub(instance);
	    macro_sub(recipient);
	    
	    /* do the right thing with it */
	    switch (c) {
	      case UNSUBSCRIBE_CHARACTER:
		unsubscribe(class, instance, recipient);
		break;
	      case PUNT_CHARACTER:
		punt(class, instance, recipient);
		break;
	      default:
		subscribe(class, instance, recipient);
		break;
	    }
	} else {
	    break;
	}
    }
    
    if (ferror(file)) {
	com_err("zwgc", errno, "while reading from subscription file");
	exit(1);
    }

    flush_subscriptions();
    flush_unsubscriptions();
    
    fclose(file);
}

#define DEFSUBS "/dev/null"

static void load_subscriptions()
{
    FILE *subscriptions_file;

    /* no system default sub file on client--they live on the server */
    /* BUT...we need to use something to call load_subscriptions_from_file,
       so we use /dev/null */
    subscriptions_file = locate_file(subscriptions_filename_override,
				     USRSUBS, DEFSUBS);
    if (subscriptions_file)
      load_subscriptions_from_file(subscriptions_file);
}

/****************************************************************************/
/*                                                                          */
/*                Code to implement shutdown and startup:                   */
/*                                                                          */
/****************************************************************************/

int zwgc_active = 0;

static ZSubscription_t *saved_subscriptions = NULL;
static int number_of_saved_subscriptions;

void zwgc_shutdown()
{
    if (!zwgc_active)
      return;

    TRAP(ZRetrieveSubscriptions(0, &number_of_saved_subscriptions),
	 "while retrieving zephyr subscription list");
    if (error_code)
      return;
    saved_subscriptions = (ZSubscription_t *)
      malloc(number_of_saved_subscriptions*sizeof(ZSubscription_t));
    if (number_of_saved_subscriptions)
      TRAP(ZGetSubscriptions(saved_subscriptions,
			     &number_of_saved_subscriptions),
	   "while getting subscriptions");
    if (error_code) {
	free(saved_subscriptions);
	saved_subscriptions = NULL;
    }
    TRAP(ZCancelSubscriptions(0), "while canceling subscriptions") ;

    zwgc_active = 0;
}

void zwgc_startup()
{
    if (zwgc_active)
      return;

    if (saved_subscriptions) {
	TRAP(ZSubscribeTo(saved_subscriptions,number_of_saved_subscriptions,0),
	     "while resubscribing to zephyr messages");
	free(saved_subscriptions);
	saved_subscriptions = NULL;
    } else
      load_subscriptions();

    zwgc_active = 1;
}
