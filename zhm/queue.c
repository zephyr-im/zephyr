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
static char rcsid_queue_c[] = "$Header$";
#endif lint

#ifdef DEBUG
#define DPR(a) fprintf(stderr, a)
#define DPR2(a,b) fprintf(stderr, a, b)
#else
#define DPR(a)
#define DPR2(a,b)
#endif

Code_t add_notice_to_queue(notice)
     ZNotice_t *notice;
{
      DPR ("Adding notice to queue...\n");
}

Code_t remove_notice_from_queue(notice)
     ZNotice_t *notice;
{
      DPR ("Removing notice from queue...\n");
}

Code_t retransmit_queue(notice)
     ZNotice_t *notice;
{
      DPR ("Retransmitting queue to new server...\n");
}

Code_t dump_queue()
{
      DPR ("Dumping queue...\n");
}
