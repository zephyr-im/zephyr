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

static const int rexmit_times[] = { 2, 2, 4, 4, 8, -1 };

static Queue *find_notice_in_galaxy __P((galaxy_info *gi, ZNotice_t *notice));
static void queue_timeout __P((void *arg));

#ifdef DEBUG
Code_t dump_galaxy_queue(galaxy_info *);
#endif

void init_galaxy_queue(galaxy_info *gi)
{
    Queue *q;

    while (gi->queue) {
	q = gi->queue;
	if (q->timer)
	    timer_reset(q->timer);
	free(q->packet);
	gi->queue = q->next;
	free(q);
    }

    DPR("Queue initialized and flushed.\n");
}

Code_t add_notice_to_galaxy(gi, notice, repl, len)
    galaxy_info *gi;
    ZNotice_t *notice;
    struct sockaddr_in *repl;
    int len;
{
    Queue *entry;
    int length;
    int retval;

    DPR("Adding notice to queue...\n");
    if (!find_notice_in_galaxy(gi, notice)) {
	entry = (Queue *) malloc(sizeof(Queue));
	if (entry == NULL)
	    return(ZERR_NONOTICE);
	entry->gi = gi;
	entry->retries = 0;
	if (!(entry->packet = (char *) malloc((unsigned)sizeof(ZPacket_t)))) {
	    free(entry);
	    return(ENOMEM);
	}

	if ((retval = ZFormatSmallRawNotice(notice, entry->packet, &length))
	    != ZERR_NONE) {
	    free(entry->packet);
	    free(entry);
	    return(retval);
	}

	/* I dislike this, but I need a notice which represents the
	   packet.  since the notice structure refers to the internals
	   of its packet, I can't use the notice which was passed in,
	   so I need to make a new one. */

	if ((retval = ZParseNotice(entry->packet, length, &entry->notice))
	    != ZERR_NONE) {
	   free(entry->packet);
	   free(entry);
	   return(retval);
	}

	entry->reply = *repl;
	LIST_INSERT(&gi->queue, entry);

	entry->timer = (gi->state == ATTACHED) ?
	   timer_set_rel(rexmit_times[0], queue_timeout, entry) : NULL;
    }
    return(ZERR_NONE);
}

Code_t remove_notice_from_galaxy(gi, notice, kind, repl)
    galaxy_info *gi;
    ZNotice_t *notice;
    ZNotice_Kind_t *kind;
    struct sockaddr_in *repl;
{
    Queue *entry;

    DPR("Removing notice from queue...\n");
    entry = find_notice_in_galaxy(gi, notice);
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
void retransmit_galaxy(gi)
    galaxy_info *gi;
{
    Queue *entry;
    Code_t ret;

    DPR("Retransmitting queue to new server...\n");
    for (entry = gi->queue; entry; entry = entry->next) {
	DPR("notice:\n");
	DPR2("\tz_kind: %d\n", entry->notice.z_kind);
	DPR2("\tz_port: %u\n", ntohs(entry->notice.z_port));
	DPR2("\tz_class: %s\n", entry->notice.z_class);
	DPR2("\tz_clss_inst: %s\n", entry->notice.z_class_inst);
	DPR2("\tz_opcode: %s\n", entry->notice.z_opcode);
	DPR2("\tz_sender: %s\n", entry->notice.z_sender);
	DPR2("\tz_recip: %s\n", entry->notice.z_recipient);
	ret = send_outgoing(&gi->sin, &entry->notice);
	if (ret != ZERR_NONE) {
	    Zperr(ret);
	    com_err("queue", ret, "sending raw notice");
	}
	entry->timer = timer_set_rel(rexmit_times[0], queue_timeout, entry);
	entry->retries = 0;
    }
}

/* We lost our server; nuke all of our timers. */
void disable_galaxy_retransmits(gi)
    galaxy_info *gi;
{
    Queue *entry;

    for (entry = gi->queue; entry; entry = entry->next) {
	if (entry->timer)
	    timer_reset(entry->timer);
	entry->timer = NULL;
    }
}

#ifdef DEBUG
static Code_t dump_galaxy_queue(gi)
    galaxy_info *gi;
{
    Queue *entry;
    caddr_t mp;
    int ml;

    DPR("Dumping queue...\n");
    if (!gi->queue) {
	printf("Queue is empty.\n");
	return;
    }

    for (entry = gi->queue; entry; entry = entry->next) {
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

int galaxy_queue_len(gi)
    galaxy_info *gi;
{
    int length = 0;
    Queue *entry;

    for (entry = gi->queue; entry; entry = entry->next)
	length++;
    return length;
}

static Queue *find_notice_in_galaxy(gi, notice)
    galaxy_info *gi;
    ZNotice_t *notice;
{
    Queue *entry;

    for (entry = gi->queue; entry; entry = entry->next) {
	if (ZCompareUID(&entry->notice.z_uid, &notice->z_uid))
	    return entry;
    }
    return NULL;
}

static void queue_timeout(arg)
    void *arg;
{
    Queue *entry = (Queue *) arg;
    Code_t ret;

    entry->timer = NULL;

    if (ret != ZERR_NONE) {
	Zperr(ret);
	com_err("queue", ret, "setting destination");
    }
    entry->retries++;
    if (rexmit_times[entry->retries] == -1) {
	galaxy_new_server(entry->gi, NULL);
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
    ret = send_outgoing(&entry->gi->sin, &entry->notice);
    if (ret != ZERR_NONE) {
	Zperr(ret);
	com_err("queue", ret, "sending raw notice");
    }
    entry->timer = timer_set_rel(rexmit_times[entry->retries], queue_timeout,
				 entry);
}

