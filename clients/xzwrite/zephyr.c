#include <zephyr/zephyr.h>

#include "xzwrite.h"
#include <strings.h>

static int zeph_send_notice();
extern Defaults defs;

/* ARGSUSED */
void zeph_dispatch(client_data, source, input_id)
   XtPointer client_data;
   int *source;
   XtInputId *input_id;
{
     ZNotice_t notice;
     struct sockaddr_in from;
     int ret;

     while (ZPending() > 0) {
	  ret = ZReceiveNotice(&notice, &from);
	  if (ret != ZERR_NONE) {
	       Warning(error_message(ret), " while receiving Zephyr notice.",
		       NULL);
	       continue;
	  }

	  if (defs.track_logins &&
	      (! strcmp(notice.z_opcode, "USER_LOGIN") ||
	       ! strcmp(notice.z_opcode, "USER_LOGOUT")))
	       logins_deal(&notice);

	  else if (defs.auto_reply &&
		   ! strcasecmp(notice.z_class, DEFAULT_CLASS) &&
		   ! strcasecmp(notice.z_recipient, ZGetSender()))
	       dest_add_reply(&notice);
	  
	  /* Handle the zlocating bug the Zephyr library explicitly. */
	  /* Only display bogon zlocate packets in debug mode */
	  else if (strcmp(notice.z_class, LOCATE_CLASS) || defs.debug) {
	       Warning("XZwrite: Unexpected notice received.  ",
		       "You can probably ignore this.\n",
		       "To: <", notice.z_class, ", ",
		       notice.z_class_inst, ", ", (*notice.z_recipient) ?
		       notice.z_recipient : "*", ">\n",
		       "From: ", notice.z_sender, "\nOpcode: ",
		       notice.z_opcode, "\nMessage: ", notice.z_message,
		       "\n", NULL);
	  }
	  
	  ZFreeNotice(&notice);
     }
}

void zeph_init()
{
     int	retval;
     
     retval = ZInitialize();
     if (retval != ZERR_NONE)
	  Error("Cannot initialize the Zephyr library.", NULL);

     retval = ZOpenPort((int *) 0);
     if (retval != ZERR_NONE)
	  Error("Cannot open Zephyr port.", NULL);
}

int zeph_locateable(user)
   char *user;
{
     char	buf[BUFSIZ];
     int   n;

     if (strchr(user, '@') == NULL)
	  sprintf(buf, "%s@%s", user, ZGetRealm());
     ZLocateUser(buf, &n, ZAUTH);
     return (!! n);
}

/* XXX This will break on interrealm zephyr */
void zeph_subto_logins(users, num)
   char **users;
   int num;
{
     ZSubscription_t	*sublist;
     char		*name, *realm;
     int        	rlen, c = 0;

     realm = ZGetRealm();
     rlen = strlen(realm);
     sublist = (ZSubscription_t *) Malloc(num*sizeof(ZSubscription_t),
					  "while subscribing to logins", NULL);

     while (c < num) {
	  sublist[c].zsub_class = "login";
	  sublist[c].zsub_recipient = "";
	  name = (char *) Malloc(strlen(users[c])+rlen+2,
				 "while subscribing to login, ", users[c],
				 NULL);
	  if (strchr(users[c], '@'))
	       sprintf(name, "%s", users[c]);
	  else
	       sprintf(name, "%s@%s", users[c], realm);
	  sublist[c].zsub_classinst = name;
	  c += 1;
     }

     ZSubscribeToSansDefaults(sublist, c, (unsigned short) 0);
     for(; c; --c)
	  free(sublist[c-1].zsub_classinst);
     free(sublist);
}

void zeph_subto_replies()
{
     ZSubscription_t sub;

     sub.zsub_class = "message";
     sub.zsub_classinst = "*";
     sub.zsub_recipient = ZGetSender();

     ZSubscribeToSansDefaults(&sub, 1, (unsigned short) 0);
}

int zeph_send_message(dest, msg)
   Dest	dest;
   char	*msg;
{
     ZNotice_t	notice;
     int 	msglen, siglen, ret;
     char	*sig_msg;

     msglen = strlen(msg);
     siglen = strlen(defs.signature);
     sig_msg = (char *) Malloc(msglen + siglen + 2, "while sending message",
			       NULL);
     sprintf(sig_msg, "%s%c%s", defs.signature, '\0', msg);
          
     (void) memset((char *) &notice, 0, sizeof(ZNotice_t));
     notice.z_kind = ACKED;
     notice.z_class = dest->zclass;
     notice.z_class_inst = dest->zinst;
     notice.z_recipient = dest->zrecip;
     notice.z_sender = 0;
     notice.z_opcode = defs.opcode;
     notice.z_port = 0;
     notice.z_message = sig_msg;
     notice.z_message_len = msglen + siglen + 1;

     /* This really gross looking mess is brought to you by zwrite.c */
     if (defs.auth) {
	  if (*defs.signature)
	       notice.z_default_format = "Class $class, Instance $instance:\nTo: @bold($recipient)\n@bold($1) <$sender>\n\n$2";
	  else
	       notice.z_default_format = "Class $class, Instance $instance:\nTo: @bold($recipient)\n$message";
     }
     else {
	  if (*defs.signature)
	       notice.z_default_format = "@bold(UNAUTHENTIC) Class $class, Instance $instance:\n@bold($1) <$sender>\n\n$2";
	  else
	       notice.z_default_format = "@bold(UNAUTHENTIC) Class $class, Instance $instance:\n$message";
     }
     
     ret = zeph_send_notice(&notice, (defs.auth) ? ZAUTH : ZNOAUTH);
     free(sig_msg);
     return ret;
}

int zeph_ping(dest)
   Dest	dest;
{
     ZNotice_t		notice;

     (void) memset((char *) &notice, 0, sizeof(ZNotice_t));
     notice.z_kind = ACKED;
     notice.z_class = dest->zclass;
     notice.z_class_inst = dest->zinst;
     notice.z_recipient = dest->zrecip;
     notice.z_opcode = "PING";

     /* Should a PING ever be authenticated? */
     return (zeph_send_notice(&notice, ZNOAUTH));
}

int zeph_pong(dest)
   Dest dest;
{
     ZNotice_t		notice;

     (void) memset((char *) &notice, 0, sizeof(ZNotice_t));
     notice.z_kind = ACKED;
     notice.z_class = dest->zclass;
     notice.z_class_inst = dest->zinst;
     notice.z_recipient = dest->zrecip;
     notice.z_opcode = "PING";
     notice.z_message = "PONG";
     notice.z_message_len = 4;

     /* Should a PING ever be authenticated? */
     return (zeph_send_notice(&notice, ZNOAUTH));
}

char *zeph_get_signature()
{
     char *sig;
	  
     sig = ZGetVariable("xzwrite-signature");
     if (! sig) sig = ZGetVariable("zwrite-signature");
     return sig;
}

static int zeph_send_notice(notice, auth)
   ZNotice_t	*notice;
   int		(*auth)();
{
     int	retval;
     ZNotice_t	retnotice;

     /* Send message with appropriate authentication */
     retval = ZSendNotice(notice, auth);
     if (retval != ZERR_NONE) {
	  if (defs.debug)
	       Warning(error_message(retval), " while sending message.", NULL);
	  return SENDFAIL_SEND;
     }

     /* Wait for server acknowledgement */
     retval = ZIfNotice(&retnotice, (struct sockaddr_in *) 0,
			ZCompareUIDPred, (char *) &notice->z_uid);

     if (retval != ZERR_NONE) {
	  if (defs.debug)
	       Warning(error_message(retval),
		       " while waiting for acknowledgement.", NULL);
	  return SENDFAIL_ACK;
     }

     /* Make sure someone receives it */
     if (strcmp(retnotice.z_message, ZSRVACK_NOTSENT)==0)
	  return SENDFAIL_RECV;

     return SEND_OK;
}

#ifdef DEBUG
/* debugging function */
void zeph_display_subscriptions()
{
     ZSubscription_t sub;
     int n, retval, i = 1;

     retval = ZRetrieveSubscriptions((unsigned short) 0, &n);
     if (retval != ZERR_NONE) {
	  Warning(error_message(retval), " while retrieving subscriptions.",
		  NULL);
	  return;
     }

     printf("Retrieving %d subscriptions.\n", n);

     while (ZGetSubscriptions(&sub, &i) == ZERR_NONE) {
	  if (i != 1)
	       Warning("Subscriptions skipped while printing.", NULL);
	  
	  printf("<%s,%s,%s>\n", sub.class, (*sub.zsub_classinst) ?
		 sub.zsub_classinst : "**", (*sub.zsub_recipient) ?
		 sub.zsub_recipient : "**");
     }
}
#endif
