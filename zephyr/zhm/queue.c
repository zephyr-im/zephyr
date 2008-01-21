/* This file is part of the Project Athena Zephyr Notification System.
 * It contains the hostmanager queueing routines.
 *
 *      Created by:     David C. Jedlinsky
 *
 *      $Id$
 *
 *      Copyright (c) 1987 by the Massachusetts Institute of Technology.
 *      For copying and distribution information, see the file
 *      "mit-copyright.h". 
 */

#include "zhm.h"

#ifndef lint
#ifndef SABER
static char rcsid_queue_c[] = "$Id$";
#endif /* SABER */
#endif /* lint */

typedef struct _Queue {
    Timer *timer;
    int retries;
    ZNotice_t notice;
    caddr_t packet;
    struct sockaddr_in reply;
    struct _Queue *next, **prev_p;
} Queue;

static Queue *hm_queue;
static int retransmits_enabled = 0;

static Queue *find_notice_in_queue(ZNotice_t *notice);
static Code_t dump_queue(void);
static void queue_timeout(void *arg);

int rexmit_times[] = { 2, 2, 4, 4, 8, -1 };

#ifdef DEBUG
Code_t dump_queue(void);
#endif

void
init_queue(void)
{
    Queue *q;

    while (hm_queue) {
	q = hm_queue;
	if (q->timer)
	    timer_reset(q->timer);
	free(q->packet);
	hm_queue = q->next;
	free(q);
    }

    DPR("Queue initialized and flushed.\n");
}

Code_t
add_notice_to_queue(ZNotice_t *notice,
		    char *packet,
		    struct sockaddr_in *repl,
		    int len)
{
    Queue *entry;

    DPR("Adding notice to queue...\n");
    if (!find_notice_in_queue(notice)) {
	entry = (Queue *) malloc(sizeof(Queue));
	if (entry == NULL)
	    return(ZERR_NONOTICE);
	entry->retries = 0;
	entry->packet = (char *) malloc(Z_MAXPKTLEN);
	if (entry->packet == NULL) {
	    free(entry);
	    return(ZERR_NONOTICE);
	}
	memcpy(entry->packet, packet, Z_MAXPKTLEN);
	if (ZParseNotice(entry->packet, len, &entry->notice) != ZERR_NONE) {
	    syslog(LOG_ERR, "ZParseNotice failed, but succeeded before");
	    free(entry->packet);
	} else {
	    entry->reply = *repl;
	    LIST_INSERT(&hm_queue, entry);
	}
	entry->timer = (retransmits_enabled) ?
	    timer_set_rel(rexmit_times[0], queue_timeout, entry) : NULL;
    }
    return(ZERR_NONE);
}

Code_t
remove_notice_from_queue(ZNotice_t *notice,
			 ZNotice_Kind_t *kind,
			 struct sockaddr_in *repl)
{
    Queue *entry;

    DPR("Removing notice from queue...\n");
    entry = find_notice_in_queue(notice);
    if (entry == NULL)
	return(ZERR_NONOTICE);

    *kind = entry->notice.z_kind;
    *repl = entry->reply;
    if (entry->timer)
	timer_reset(entry->timer);
    free(entry->packet);
    LIST_DELETE(entry);
#ifdef DEBUG
    dump_queue();
#endif /* DEBUG */
    free(entry);
    return(ZERR_NONE);
}

/* We have a server; transmit all of our packets. */
void
retransmit_queue(struct sockaddr_in *sin)
{
    Queue *entry;
    Code_t ret;

    DPR("Retransmitting queue to new server...\n");
    ret = ZSetDestAddr(sin);
    if (ret != ZERR_NONE) {
	Zperr (ret);
	com_err("queue", ret, "setting destination");
    }
    for (entry = hm_queue; entry; entry = entry->next) {
	DPR("notice:\n");
	DPR2("\tz_kind: %d\n", entry->notice.z_kind);
	DPR2("\tz_port: %u\n", ntohs(entry->notice.z_port));
	DPR2("\tz_class: %s\n", entry->notice.z_class);
	DPR2("\tz_clss_inst: %s\n", entry->notice.z_class_inst);
	DPR2("\tz_opcode: %s\n", entry->notice.z_opcode);
	DPR2("\tz_sender: %s\n", entry->notice.z_sender);
	DPR2("\tz_recip: %s\n", entry->notice.z_recipient);
	ret = send_outgoing(&entry->notice);
	if (ret != ZERR_NONE) {
	    Zperr(ret);
	    com_err("queue", ret, "sending raw notice");
	}
	entry->timer = timer_set_rel(rexmit_times[0], queue_timeout, entry);
	entry->retries = 0;
    }
    retransmits_enabled = 1;
}

/* We lost our server; nuke all of our timers. */
void
disable_queue_retransmits(void)
{
    Queue *entry;

    for (entry = hm_queue; entry; entry = entry->next) {
	if (entry->timer)
	    timer_reset(entry->timer);
	entry->timer = NULL;
    }
    retransmits_enabled = 0;
}

#ifdef DEBUG
static Code_t
dump_queue(void)
{
    Queue *entry;
    caddr_t mp;
    int ml;

    DPR("Dumping queue...\n");
    if (!hm_queue) {
	printf("Queue is empty.\n");
	return;
    }

    for (entry = hm_queue; entry; entry = entry->next) {
	printf("notice:\n");
	printf("\tz_kind: %d\n", entry->notice.z_kind);
	printf("\tz_port: %u\n", ntohs(entry->notice.z_port));
	printf("\tz_class: %s\n", entry->notice.z_class);
	printf("\tz_clss_inst: %s\n", entry->notice.z_class_inst);
	printf("\tz_opcode: %s\n", entry->notice.z_opcode);
	printf("\tz_sender: %s\n", entry->notice.z_sender);
	printf("\tz_recip: %s\n", entry->notice.z_recipient);
	printf("\tMessage:\n");
	mp = entry->notice.z_message;
	for (ml = strlen(mp) + 1; ml <= entry->notice.z_message_len; ml++) {
	    printf("\t%s\n", mp);
	    mp += strlen(mp)+1;
	    ml += strlen(mp);
	}
    }
}
#endif /* DEBUG */

int
queue_len(void)
{
    int length = 0;
    Queue *entry;

    for (entry = hm_queue; entry; entry = entry->next)
	length++;
    return length;
}

static Queue *
find_notice_in_queue(ZNotice_t *notice)
{
    Queue *entry;

    for (entry = hm_queue; entry; entry = entry->next) {
	if (ZCompareUID(&entry->notice.z_uid, &notice->z_uid))
	    return entry;
    }
    return NULL;
}

static void
queue_timeout(void *arg)
{
    Queue *entry = (Queue *) arg;
    Code_t ret;

    entry->timer = NULL;
    ret = ZSetDestAddr(&serv_sin);
    if (ret != ZERR_NONE) {
	Zperr(ret);
	com_err("queue", ret, "setting destination");
    }
    entry->retries++;
    if (rexmit_times[entry->retries] == -1) {
	new_server(NULL);
	return;
    }
    DPR("Resending notice:\n");
    DPR2("\tz_kind: %d\n", entry->notice.z_kind);
    DPR2("\tz_port: %u\n", ntohs(entry->notice.z_port));
    DPR2("\tz_class: %s\n", entry->notice.z_class);
    DPR2("\tz_clss_inst: %s\n", entry->notice.z_class_inst);
    DPR2("\tz_opcode: %s\n", entry->notice.z_opcode);
    DPR2("\tz_sender: %s\n", entry->notice.z_sender);
    DPR2("\tz_recip: %s\n", entry->notice.z_recipient);
    ret = send_outgoing(&entry->notice);
    if (ret != ZERR_NONE) {
	Zperr(ret);
	com_err("queue", ret, "sending raw notice");
    }
    entry->timer = timer_set_rel(rexmit_times[entry->retries], queue_timeout,
				 entry);
}

