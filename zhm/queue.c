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

#include <zephyr/mit-copyright.h>
#include <zephyr/zephyr.h>

#ifndef lint
#ifndef SABER
static char rcsid_queue_c[] = "$Header$";
#endif SABER
#endif lint

#ifdef DEBUG
#define DPR(a) fprintf(stderr, a)
#define DPR2(a,b) fprintf(stderr, a, b)
#else
#define DPR(a)
#define DPR2(a,b)
#endif

#define TIMEOUT 10

typedef struct _Queue {
      int timeout;
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

extern char *malloc();

Qelem hm_queue, *is_in_queue();

Code_t init_queue()
{
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
	    entry->timeout = TIMEOUT;
	    entry->retries = 0;
	    entry->z_notice = *notice;
	    entry->z_packet = packet;
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

Code_t remove_notice_from_queue(notice, packet, repl)
     ZNotice_t *notice;
     caddr_t *packet;
     struct sockaddr_in *repl;
{
      Qelem *elem;

      DPR ("Removing notice from queue...\n");
      /* Set notice & packet to the one removed, so we can acknowledge */
      if ((elem = is_in_queue(*notice)) == NULL)
	return(ZERR_NONOTICE);
      else {
	    *notice = elem->q_data->z_notice;
	    *packet = elem->q_data->z_packet;
	    *repl = elem->q_data->reply;
	    remque(elem);
	    dump_queue();
	    return(ZERR_NONE);
      }
}

Code_t retransmit_queue()
{
      DPR ("Retransmitting queue to new server...\n");
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
	    printf("\tz_port: %u\n", srch->q_data->z_notice.z_port);
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
