/* This file is part of the Project Athena Zephyr Notification System.
 * It contains the hostmanager queueing routines.
 *
 *      Created by:     David C. Jedlinsky
 *
 *      $Source$
 *      $Author$
 *
 *      Copyright (c) 1987 by the Massachusetts Institute of Technology.
 *      For copying and distribution information, see the file
 *      "mit-copyright.h". 
 */

#include "hm.h"

#ifndef lint
#ifndef SABER
static char rcsid_queue_c[] = "$Header$";
#endif SABER
#endif lint

typedef struct _Queue {
      long timeout;
      int retries;
      ZNotice_t z_notice;
      caddr_t z_packet;
      struct sockaddr_in reply;
} Queue;

struct _qelem {
      struct _qelem *q_forw;
      struct _qelem *q_back;
      Queue *q_data;
};

typedef struct _qelem Qelem;

Qelem hm_queue = { &hm_queue, &hm_queue, NULL }, *is_in_queue();

long time();
extern int timeout_type;

Code_t init_queue()
{
      if (hm_queue.q_forw != &hm_queue)
	do {
	      free(hm_queue.q_forw->q_data->z_packet);
	      free(hm_queue.q_forw->q_data);
	      remque(hm_queue.q_forw);
	      free(hm_queue.q_forw);
	} while (hm_queue.q_forw != &hm_queue);

      hm_queue.q_forw = hm_queue.q_back = &hm_queue;
      hm_queue.q_data = NULL;
      DPR ("Queue initialized and flushed.\n");
}

Code_t add_notice_to_queue(notice, packet, repl)
     ZNotice_t *notice;
     caddr_t packet;
     struct sockaddr_in *repl;
{
      Qelem *elem;
      Queue *entry;

      DPR ("Adding notice to queue...\n");
      if (!is_in_queue(*notice)) {
	    elem = (Qelem *)malloc(sizeof(Qelem));
	    entry = (Queue *)malloc(sizeof(Queue));
	    entry->timeout = time(NULL) + NOTICE_TIMEOUT;
	    entry->retries = 0;
	    entry->z_notice = *notice;
	    entry->z_packet = (char *)malloc(Z_MAXPKTLEN);
	    bcopy(packet, entry->z_packet, Z_MAXPKTLEN);
	    entry->reply = *repl;
	    elem->q_data = entry;
	    elem->q_forw = elem;
	    elem->q_back = elem;
	    insque(elem, hm_queue.q_back);
      }
#ifdef DEBUG
      if (!is_in_queue(*notice))
	return(ZERR_NONOTICE);
      else
#endif DEBUG
	return(ZERR_NONE);
}

Code_t remove_notice_from_queue(notice, kind, repl)
     ZNotice_t *notice;
     ZNotice_Kind_t *kind;
     struct sockaddr_in *repl;
{
      Qelem *elem;

      DPR ("Removing notice from queue...\n");
      if ((elem = is_in_queue(*notice)) == NULL)
	return(ZERR_NONOTICE);
      else {
	    *kind = elem->q_data->z_notice.z_kind;
	    *repl = elem->q_data->reply;
	    free(elem->q_data->z_packet);
	    free(elem->q_data);
	    remque(elem);
	    free(elem);
	    if (hm_queue.q_forw == &hm_queue)
	      (void)alarm(0);
#ifdef DEBUG
	    dump_queue();
#endif DEBUG
	    return(ZERR_NONE);
      }
}

Code_t retransmit_queue(sin)
     struct sockaddr_in *sin;
{
      Qelem *srch;
      Code_t ret;

      DPR ("Retransmitting queue to new server...\n");
      if ((ret = ZSetDestAddr(sin)) != ZERR_NONE) {
	    Zperr (ret);
	    com_err("queue", ret, "setting destination");
      }
      if ((srch = hm_queue.q_forw) != &hm_queue) {
	    do {
		  DPR ("notice:\n");
		  DPR2 ("\tz_kind: %d\n", srch->q_data->z_notice.z_kind);
		  DPR2 ("\tz_port: %u\n",
			ntohs(srch->q_data->z_notice.z_port));
		  DPR2 ("\tz_class: %s\n", srch->q_data->z_notice.z_class);
		  DPR2 ("\tz_clss_inst: %s\n",
			srch->q_data->z_notice.z_class_inst);
		  DPR2 ("\tz_opcode: %s\n", srch->q_data->z_notice.z_opcode);
		  DPR2 ("\tz_sender: %s\n", srch->q_data->z_notice.z_sender);
		  DPR2 ("\tz_recip: %s\n", srch->q_data->z_notice.z_recipient);
		  if ((ret = ZSendRawNotice(&srch->q_data->z_notice))
		      != ZERR_NONE) {
			Zperr (ret);
			com_err("queue", ret, "sending raw notice");
		  }
		  srch->q_data->timeout = NOTICE_TIMEOUT;
		  srch->q_data->retries = 0;
		  srch = srch->q_forw;
	    } while (srch != &hm_queue);
	    timeout_type = NOTICES;
	    (void)alarm(NOTICE_TIMEOUT);
      }
}

Code_t dump_queue()
{
      Qelem *srch;
      caddr_t mp;
      int ml;

      DPR ("Dumping queue...\n");
      if ((srch = hm_queue.q_forw) == &hm_queue)
	printf("Queue is empty.\n");
      else do {
	    printf("notice:\n");
	    printf("\tz_kind: %d\n", srch->q_data->z_notice.z_kind);
	    printf("\tz_port: %u\n", ntohs(srch->q_data->z_notice.z_port));
	    printf("\tz_class: %s\n", srch->q_data->z_notice.z_class);
	    printf("\tz_clss_inst: %s\n", srch->q_data->z_notice.z_class_inst);
	    printf("\tz_opcode: %s\n", srch->q_data->z_notice.z_opcode);
	    printf("\tz_sender: %s\n", srch->q_data->z_notice.z_sender);
	    printf("\tz_recip: %s\n", srch->q_data->z_notice.z_recipient);
	    printf("\tMessage:\n");
	    mp = srch->q_data->z_notice.z_message;
	    for (ml = strlen(mp)+1;
		 ml <= srch->q_data->z_notice.z_message_len; ml++) {
		  printf("\t%s\n", mp);
		  mp += strlen(mp)+1;
		  ml += strlen(mp);
	    }
	    srch = srch->q_forw;
      } while (srch != &hm_queue);
}

int queue_len()
{
      int length = 0;
      Qelem *srch;

      if ((srch = hm_queue.q_forw) != &hm_queue) {
	    do {
		  length++;
		  srch = srch->q_forw;
	    } while (srch != &hm_queue);
      }
      return(length);
}

Qelem *is_in_queue(notice)
     ZNotice_t notice;
{
      Qelem *srch;

      srch = hm_queue.q_forw;
      if (srch == &hm_queue)
	return(NULL);
      do {
	    if (ZCompareUID(&(srch->q_data->z_notice.z_uid), &(notice.z_uid)))
	      return(srch);
	    srch = srch->q_forw;
      } while (srch != &hm_queue);
      return(NULL);
}

void resend_notices(sin)
     struct sockaddr_in *sin;
{
      Qelem *srch;
      Code_t ret;

      DPR ("Resending notices...\n");
      if ((ret = ZSetDestAddr(sin)) != ZERR_NONE) {
	    Zperr(ret);
	    com_err("queue", ret, "setting destination");
      }
      if ((srch = hm_queue.q_forw) == &hm_queue) {
	    syslog (LOG_INFO, "No notices, shouldn't have happened!");
      } else do {
	    if (srch->q_data->timeout <= time(NULL)) {
		  if (++(srch->q_data->retries) > MAXRETRIES) {
			new_server();
			break;
		  } else {
			DPR ("notice:\n");
			DPR2 ("\tz_kind: %d\n", srch->q_data->z_notice.z_kind);
			DPR2 ("\tz_port: %u\n",
			      ntohs(srch->q_data->z_notice.z_port));
			DPR2 ("\tz_class: %s\n",
			      srch->q_data->z_notice.z_class);
			DPR2 ("\tz_clss_inst: %s\n",
			      srch->q_data->z_notice.z_class_inst);
			DPR2 ("\tz_opcode: %s\n",
			      srch->q_data->z_notice.z_opcode);
			DPR2 ("\tz_sender: %s\n", 
			      srch->q_data->z_notice.z_sender);
			DPR2 ("\tz_recip: %s\n",
			      srch->q_data->z_notice.z_recipient);
			if ((ret = ZSendRawNotice(&srch->q_data->z_notice)) 
			    != ZERR_NONE) {
			      Zperr(ret);
			      com_err("queue", ret, "sending raw notice");
			}
			srch->q_data->timeout = time(NULL) + NOTICE_TIMEOUT;
			srch = srch->q_forw;
		  }
	    }
      } while (srch != &hm_queue);
      timeout_type = NOTICES;
      (void)alarm(NOTICE_TIMEOUT);
}
