/* 
  This file contains code related to the zwgcplus extension to zwgc.
  zwgc is copyrighted by the Massachusetts Institute of Technology.
  This file is public domain.
  Written by Andrew Plotkin, ap1i+@andrew.cmu.edu
  Timequeue code added by Ryan Ingram, ryani+@andrew.cmu.edu
  Rewritten for incorporation into MIT zwgc from 2.0.2 by Derrick Brashear
 */

#include <sysdep.h>
#ifdef CMU_ZWGCPLUS
#if (!defined(lint) && !defined(SABER))
static const char rcsid_plus_c[] = "$Id$";
#endif

#include <zephyr/mit-copyright.h>
#include <zephyr/zephyr.h>

#include "new_memory.h"
#include "node.h"
#include "exec.h"
#include "eval.h"
#include "node.h"
#include "buffer.h"
#include "port.h"
#include "variables.h"
#include "notice.h"
#include "X_gram.h"
#include "xrevstack.h"
#include "main.h"
#include "plus.h"

int get_full_names = 0;

#define HASHSIZE (251)

typedef struct timenode_s {
  ZNotice_t *notice;
  struct timenode_s *next;
  time_t when;
  char *event_name;
} TimeNode;

typedef struct _notnode {
    ZNotice_t *notice;
    int fake_notice; /* if TRUE, do not call ZFreeNotice() */
    int refcount;
    struct _notnode *next;
    char *opcode;
    char *hname;
} notnode;

static ZNotice_t *stored_notice;
static notnode *notlist[HASHSIZE];
TimeNode *timeq_head = NULL;

int list_hash_fun(ZNotice_t *notice);

TimeNode *
addtimenode(TimeNode *head, TimeNode *node)
{
  if(head == NULL) {
#ifdef DEBUG_TIMEQUEUE
    fprintf(stderr, "adding new timenode; creating queue\n");
#endif
    node->next = NULL;
    return node;
  }
  
  if(head->when > node->when) {
#ifdef DEBUG_TIMEQUEUE
    fprintf(stderr, "adding new timenode at start of queue\n");
#endif
    node->next = head;
    return node;
  }

  head->next = addtimenode(head->next, node);
  return head;
}

void 
handle_timeq_event(TimeNode *event)
{
  char buf[128];
  notnode *pt;
  int bx = list_hash_fun(event->notice);

  for (pt=notlist[bx]; pt && pt->notice!=event->notice; pt=pt->next);

  /* "time-" + event_name + '\0' */
#ifdef DEBUG_TIMEQUEUE
  fprintf(stderr, "handle_timeq_event()\n");
#endif

  if (strlen(event->event_name)<123)
    sprintf(buf, "time-%s", event->event_name);
  else
    sprintf(buf, "time-bogus");

#ifdef DEBUG_TIMEQUEUE
  fprintf(stderr, "opcode: %s\n", buf);
#endif

  event->notice->z_version = "zwgcplus-repeat";
  event->notice->z_opcode = buf;
 
  reprocess_notice(event->notice, pt->hname);

#ifdef DEBUG_TIMEQUEUE
  fprintf(stderr, "end handle_timeq_event()\n");
#endif
}

void 
schedule_event(long secs, char *name, ZNotice_t *notice)
{
  time_t eventtime = (time(NULL)) + secs;
  TimeNode *newnode;
  char *buf;

#ifdef DEBUG_TIMEQUEUE
  fprintf(stderr, "schedule_event(%ld, %ld, %s)\n", eventtime, secs, name);
#endif

  if(!notice || !name) return;

  list_add_notice(notice);

  newnode = (TimeNode *)malloc(sizeof(TimeNode));
  buf = (char *)malloc(strlen(name) + 1);

  strcpy(buf, name);

#ifdef DEBUG_TIMEQUEUE
  fprintf(stderr, "name: %s\n", buf);
#endif

  newnode->when = eventtime;
  newnode->event_name = buf;
  newnode->notice = notice;

  timeq_head = addtimenode(timeq_head, newnode);
#ifdef DEBUG_TIMEQUEUE
  fprintf(stderr, "end schedule_event()\n");
#endif
}

void 
free_timenode(TimeNode *node)
{
#ifdef DEBUG_TIMEQUEUE
  fprintf(stderr, "free_timenode(%s)\n", node->event_name);
#endif

  free(node->event_name);
  free(node);
}

/* returns the number of notices destroyed */
int 
destroy_timeq_notice(ZNotice_t *notice, char *name)
{
  TimeNode *curr = timeq_head;
  TimeNode *prev = NULL;
  TimeNode *tmp;

  int ct = 0;

#ifdef DEBUG_TIMEQUEUE
  fprintf(stderr, "destroy_timeq_notice(%s)\n", name);
#endif

  while(curr != NULL) {
    if(curr->notice == notice &&
       (!name || !strcmp(curr->event_name, name)))
      {
	ct++;
	if(!prev) {
	  timeq_head = curr->next;
	} else {
	  prev->next = curr->next;
	}
	tmp = curr;
	curr = curr->next;
	free_timenode(tmp);
      } else {
	prev = curr;
	curr = curr->next;
      }
  }
  
  return ct;
}

long 
plus_timequeue_events(void)
{ 
  /* returns number of seconds to the next event or 0L */
  /* if there are no events remaining to be processed */

  time_t timenow = time(NULL);
  TimeNode *curr;

  while(timeq_head != NULL && timeq_head->when <= timenow) {
#ifdef DEBUG_TIMEQUEUE
    fprintf(stderr, "handling event\n");
#endif
    handle_timeq_event(timeq_head);
    curr = timeq_head;
    timeq_head = timeq_head->next;
    free_timenode(curr);
  }

#ifdef DEBUG_TIMEQUEUE
  if(timeq_head != NULL)
    fprintf(stderr, "next event in %ld seconds.\n",
       (timeq_head->when) - timenow);
#endif

  return ((timeq_head == NULL) ? 0L : ((timeq_head->when) - timenow));
}

void
plus_set_hname(ZNotice_t *notice, char *hname) 
{
  notnode *pt;
  int bx;

  if (hname) {
    bx = list_hash_fun(notice);
    for (pt=notlist[bx]; pt && pt->notice!=notice; pt=pt->next);
    pt->hname=(char *)malloc(strlen(hname)+1);
    strcpy(pt->hname, hname);
  }
  return;
}

void 
plus_queue_notice(ZNotice_t *notice)
{
  char *val;
  int howlong = 0;
  
#ifdef DEBUG_TIMEQUEUE
  fprintf(stderr, "plus_queue_notice()\n");
#endif

  val = var_get_variable("event_time");
  if(val) {
    if(strcmp(val, "kill")) {
      howlong = atoi(val);
#ifdef DEBUG_TIMEQUEUE
      fprintf(stderr, "$event_time %d\n", howlong);
#endif
    } else {
      val = var_get_variable("event_name");
      if(!val || strcmp(val, "all"))
	destroy_timeq_notice(notice, (val && val[0]) ? val : "event");
      else
	destroy_timeq_notice(notice, (char *)NULL);
    }
  }
  
  if(howlong > 0) {
    val = var_get_variable("event_name");
#ifdef DEBUG_TIMEQUEUE
    fprintf(stderr, "$event_name = %s\n", val);
#endif
    schedule_event(howlong, (val && val[0]) ? val : "event", notice);
  }
}

int 
list_hash_fun(ZNotice_t *notice)
{
    int ix;
    int res = 0, val = 1, ptval;
    char *pt = (char *)(notice);

    for (ix=0; ix<sizeof(ZNotice_t *); ix++) {
	ptval = (int)pt[ix];
	if (ptval<0) ptval = (-ptval);
	res += val * ptval;
	res %= HASHSIZE;
	val *= 7;
    };

    return res;
}

/* initialize hash table */
void 
init_noticelist(void)
{
    int ix;

    stored_notice = NULL;

    for (ix=0; ix<HASHSIZE; ix++) {
	notlist[ix] = NULL;
    }
}

void 
dump_noticelist(void)
{
    notnode *pt;
    int bx;

    for (bx=0; bx<HASHSIZE; bx++) {
	for (pt=notlist[bx]; pt; pt=pt->next) {
	    fprintf(stderr, "Not %p: %d [%d]\n", pt->notice, pt->refcount, bx);
	}
    }
}

/* add notice to table. Either generate a new entry, or increment ref count. */
void 
list_add_notice(ZNotice_t *notice)
{
    notnode *pt;
    int bx = list_hash_fun(notice);

    for (pt=notlist[bx]; pt && pt->notice!=notice; pt=pt->next);

    if (pt) {
	/* found entry */
	pt->refcount++;
    }
    else {
	/* no entry */
	pt = (notnode *)malloc(sizeof(notnode));
	pt->notice = notice;
	pt->refcount = 1;
	pt->fake_notice = 0;
	pt->next = notlist[bx];
	pt->opcode = notice->z_opcode;
	pt->hname = NULL;
	notlist[bx] = pt;
    }

    /*fprintf(stderr, "list_add_notice(%p)\n", notice);
    dump_noticelist();*/
}   

/* remove notice from table. If refcount reaches 0, return 1; if refcount is 
   still positive, return 0; if notice not there, return -1. */
int 
list_del_notice(ZNotice_t *notice)
{
    notnode *pt, **ppt;
    int bx = list_hash_fun(notice);

    for (pt=notlist[bx]; pt && pt->notice!=notice; pt=pt->next);

    if (!pt) {
	/* no entry */
	/*fprintf(stderr, "list_del_notice(%p): ERROR\n", notice);
	dump_noticelist();*/
	return (-1);
    }

    pt->refcount--;
    if (pt->refcount > 0) {
	/*fprintf(stderr, "list_del_notice(%p): count %d\n", notice, pt->refcount);
	dump_noticelist();*/
	return 0;
    }

    for (ppt = &(notlist[bx]); (*ppt)!=pt; ppt = &((*ppt)->next));

    *ppt = (*ppt)->next;

    if (!pt->fake_notice)
	ZFreeNotice(pt->notice);
    if (pt->hname)
      free(pt->hname);
    free(pt->notice);
    free(pt);

    /*fprintf(stderr, "list_del_notice(%p): count 0, gone\n", notice);*/
    /*dump_noticelist();*/
    return 1;
}

void 
set_notice_fake(ZNotice_t *notice, int val)
{
    notnode *pt;
    int bx = list_hash_fun(notice);

    for (pt=notlist[bx]; pt && pt->notice!=notice; pt=pt->next);

    if (pt) {
	pt->fake_notice = val;
    }
}

int 
get_notice_fake(ZNotice_t *notice)
{
    notnode *pt;
    int bx = list_hash_fun(notice);

    for (pt=notlist[bx]; pt && pt->notice!=notice; pt=pt->next);

    if (pt) {
	return pt->fake_notice;
    }
    else 
	return 0;
}

int 
get_list_refcount(ZNotice_t *notice)
{
    notnode *pt;
    int bx = list_hash_fun(notice);

    for (pt=notlist[bx]; pt && pt->notice!=notice; pt=pt->next);

    if (pt) {
	/*fprintf(stderr, "get_list_refcount(%p): count %d\n", notice, pt->refcount);*/
	return pt->refcount;
    }
    else {
	/*fprintf(stderr, "get_list_refcount(%p): count 0\n", notice);*/
	return 0;
    }
}

/* export a reference to the current notice. */
ZNotice_t *
get_stored_notice(void)
{
    if (!stored_notice)
	return NULL;

    list_add_notice(stored_notice);

    return stored_notice;
}

void 
set_stored_notice(ZNotice_t *notice)
{
    stored_notice = notice;
}

void 
plus_retry_notice(ZNotice_t *notice, char ch, int metaflag)
{
    char buf[128];
    char *tmp;
    notnode *pt;
    int bx;

    if (!notice)
	return;

    bx = list_hash_fun(notice);
    for (pt=notlist[bx]; pt && pt->notice!=notice; pt=pt->next);

    if (metaflag) tmp = "-meta";
    else tmp = "";

    if (ch==' ')
	sprintf(buf, "key%s-space", tmp);
    else if (ch==127)
	sprintf(buf, "key%s-delete", tmp);
    else if (ch==0)
	sprintf(buf, "key%s-ctrl-@", tmp);
    else if (ch==27)
	sprintf(buf, "key%s-esc", tmp);
    else if (isprint(ch))
	sprintf(buf, "key%s-%c", tmp, ch);
    else if (ch>=1 && ch<=26)
	sprintf(buf, "key%s-ctrl-%c", tmp, ch+'a'-1);
    else if (iscntrl(ch))
	sprintf(buf, "key%s-ctrl-%c", tmp, ch+'A'-1);
    else
	sprintf(buf, "key%s-unknown", tmp);

    /* concat the old opcode if they're running in "new" mode */
    if (zwgcplus == 2 && pt && pt->opcode[0] && 
	strcmp(pt->opcode, "") != 0) 
      {
	strcat(buf, " ");
	strncat(buf, pt->opcode, sizeof(buf)-strlen(buf));
      }
      
    notice->z_version = "zwgcplus-repeat";
    notice->z_opcode = buf;

    reprocess_notice(notice, NULL);
}
#endif /* CMU_ZWGCPLUS */
