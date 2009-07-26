/* 
  This file contains code related to the zwgcplus extension to zwgc.
  zwgc is copyrighted by the Massachusetts Institute of Technology.
  This file is public domain.
  Written by Andrew Plotkin, ap1i+@andrew.cmu.edu
 */

#define NAMESIZE (256)

extern int get_full_names;
extern int zwgcplus;

extern void init_noticelist(void);
extern void dump_noticelist(void);
extern void list_add_notice(ZNotice_t *notice);
extern int list_del_notice(ZNotice_t *notice);
extern int get_list_refcount(ZNotice_t *notice);
extern void set_notice_fake(ZNotice_t *notice, int val);
extern int get_notice_fake(ZNotice_t *notice);
extern ZNotice_t *get_stored_notice(void);
extern void plus_retry_notice(ZNotice_t *notice, char ch, int metaflag);
extern void set_stored_notice(ZNotice_t *notice);
extern void plus_window_deletions(ZNotice_t *notice); /* actually in xshow.c */

extern void plus_queue_notice(ZNotice_t *notice);
extern long plus_timequeue_events(void);
void plus_set_hname(ZNotice_t *notice, char *hname);
