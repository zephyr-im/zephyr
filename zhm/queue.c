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

#include "zhm.h"

#ifndef lint
#ifndef SABER
static char rcsid_queue_c[] = "$Header$";
#endif /* SABER */
#endif /* lint */

typedef struct _Queue {
     long timeout;
     int retries;
     ZNotice_t z_notice;
     caddr_t z_packet;
     struct sockaddr_in reply;
     struct _Queue *next, **prev_p;
} Queue;

static Queue *hm_queue;

static Queue *is_in_queue __P((ZNotice_t *notice));
static Code_t dump_queue __P((void));

int rexmit_times[] = { 2, 2, 4, 4, 8, 8, 16, 16, 32, 32, -1 };

extern int timeout_type;

#ifdef DEBUG
Code_t dump_queue();
#endif

void init_queue()
{
    Queue *q;

    while (hm_queue) {
	q = hm_queue;
	free(q->z_packet);
	hm_queue = q->next;
	free(q);
    }

     DPR ("Queue initialized and flushed.\n");
}

Code_t add_notice_to_queue(notice, packet, repl, len)
    ZNotice_t *notice;
    char * packet;
    struct sockaddr_in *repl;
    int len;
{
     Queue *entry;

     DPR ("Adding notice to queue...\n");
     if (!is_in_queue(notice)) {
	 entry = (Queue *) malloc(sizeof(Queue));
	 entry->timeout = time((time_t *)0) + rexmit_times[0];
	 entry->retries = 0;
	 entry->z_packet = (char *) malloc(Z_MAXPKTLEN);
	 memcpy(entry->z_packet, packet, Z_MAXPKTLEN);
	 if (ZParseNotice(entry->z_packet, len, &entry->z_notice)
	     != ZERR_NONE) {
	     syslog(LOG_ERR, "ZParseNotice failed, but succeeded before");
	     free(entry->z_packet);
	 } else {
	     entry->reply = *repl;
	     if (hm_queue)
		 hm_queue->prev_p = &entry->next;
	     entry->next = hm_queue;
	     entry->prev_p = &hm_queue;
	     hm_queue = entry;
	 }
     }
#ifdef DEBUG
     if (!is_in_queue(notice))
	  return(ZERR_NONOTICE);
     else
#endif /* DEBUG */
	  return(ZERR_NONE);
}

Code_t remove_notice_from_queue(notice, kind, repl)
    ZNotice_t *notice;
    ZNotice_Kind_t *kind;
    struct sockaddr_in *repl;
{
     Queue *entry;

     DPR ("Removing notice from queue...\n");
     entry = is_in_queue(notice);
     if (entry == NULL)
	  return(ZERR_NONOTICE);

     *kind = entry->z_notice.z_kind;
     *repl = entry->reply;
     free(entry->z_packet);
     if (entry->next)
	 entry->next->prev_p = entry->prev_p;
     *entry->prev_p = entry->next;
     free(entry);
     if (!hm_queue)
	 alarm(0);
#ifdef DEBUG
     dump_queue();
#endif /* DEBUG */
     return(ZERR_NONE);
}

void retransmit_queue(sin)
    struct sockaddr_in *sin;
{
    Queue *entry;
    Code_t ret;

    DPR ("Retransmitting queue to new server...\n");
    ret = ZSetDestAddr(sin);
    if (ret != ZERR_NONE) {
	Zperr (ret);
	com_err("queue", ret, "setting destination");
    }
    for (entry = hm_queue; entry; entry = entry->next) {
	DPR("notice:\n");
	DPR2("\tz_kind: %d\n", entry->z_notice.z_kind);
	DPR2("\tz_port: %u\n", ntohs(entry->z_notice.z_port));
	DPR2("\tz_class: %s\n", entry->z_notice.z_class);
	DPR2("\tz_clss_inst: %s\n", entry->z_notice.z_class_inst);
	DPR2("\tz_opcode: %s\n", entry->z_notice.z_opcode);
	DPR2("\tz_sender: %s\n", entry->z_notice.z_sender);
	DPR2("\tz_recip: %s\n", entry->z_notice.z_recipient);
	ret = send_outgoing(&entry->z_notice);
	if (ret != ZERR_NONE) {
	    Zperr(ret);
	    com_err("queue", ret, "sending raw notice");
	}
	entry->timeout = rexmit_times[0];
	entry->retries = 0;
    }
    timeout_type = NOTICES;
    alarm(rexmit_times[0]);
}

#ifdef DEBUG
static Code_t dump_queue()
{
     Queue *entry;
     caddr_t mp;
     int ml;

     DPR ("Dumping queue...\n");
     if (!hm_queue) {
	 printf("Queue is empty.\n");
	 return;
     }

     for (entry = hm_queue; entry; entry = entry->next) {
	 printf("notice:\n");
	 printf("\tz_kind: %d\n", entry->z_notice.z_kind);
	 printf("\tz_port: %u\n", ntohs(entry->z_notice.z_port));
	 printf("\tz_class: %s\n", entry->z_notice.z_class);
	 printf("\tz_clss_inst: %s\n", entry->z_notice.z_class_inst);
	 printf("\tz_opcode: %s\n", entry->z_notice.z_opcode);
	 printf("\tz_sender: %s\n", entry->z_notice.z_sender);
	 printf("\tz_recip: %s\n", entry->z_notice.z_recipient);
	 printf("\tMessage:\n");
	 mp = entry->z_notice.z_message;
	 for (ml = strlen(mp) + 1; ml <= entry->z_notice.z_message_len; ml++) {
	     printf("\t%s\n", mp);
	     mp += strlen(mp)+1;
	     ml += strlen(mp);
	 }
     }
}
#endif /* DEBUG */

int queue_len()
{
     int length = 0;
     Queue *entry;

     for (entry = hm_queue; entry; entry = entry->next)
	 length++;
     return length;
}

static Queue *is_in_queue(notice)
    ZNotice_t *notice;
{
     Queue *entry;

     for (entry = hm_queue; entry; entry = entry->next) {
	 if (ZCompareUID(&entry->z_notice.z_uid, &notice->z_uid))
	     return entry;
     }
     return NULL;
}

void resend_notices(sin)
    struct sockaddr_in *sin;
{
     Queue *entry;
     Code_t ret;

     DPR ("Resending notices...\n");
     ret = ZSetDestAddr(sin);
     if (ret != ZERR_NONE) {
	  Zperr(ret);
	  com_err("queue", ret, "setting destination");
     }
     for (entry = hm_queue; entry; entry = entry->next) {
	 if (entry->timeout <= time((time_t *)0)) {
	     entry->retries++;
	     if (rexmit_times[entry->retries] == -1) {
		 new_server(NULL);
		 break;
	     } else {
		 DPR("notice:\n");
		 DPR2("\tz_kind: %d\n", entry->z_notice.z_kind);
		 DPR2("\tz_port: %u\n", ntohs(entry->z_notice.z_port));
		 DPR2("\tz_class: %s\n", entry->z_notice.z_class);
		 DPR2("\tz_clss_inst: %s\n", entry->z_notice.z_class_inst);
		 DPR2("\tz_opcode: %s\n", entry->z_notice.z_opcode);
		 DPR2("\tz_sender: %s\n", entry->z_notice.z_sender);
		 DPR2("\tz_recip: %s\n", entry->z_notice.z_recipient);
		 ret = send_outgoing(&entry->z_notice);
		 if (ret != ZERR_NONE) {
		     Zperr(ret);
		     com_err("queue", ret, "sending raw notice");
		 }
		 entry->timeout = time(NULL) + rexmit_times[entry->retries];
	     }
	  }
     }
     timeout_type = NOTICES;
     alarm(rexmit_times[0]);
}
