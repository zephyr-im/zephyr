/* 
  This file contains code related to the zwgcplus extension to zwgc.
  zwgc is copyrighted by the Massachusetts Institute of Technology.
  This file is public domain.
  Written by Andrew Plotkin, ap1i+@andrew.cmu.edu
 */

#define NAMESIZE (256)

extern int get_full_names;
extern int zwgcplus;

extern void init_noticelist();
extern void dump_noticelist();
extern void list_add_notice();
extern int list_del_notice();
extern int get_list_refcount();
extern void set_notice_fake();
extern int get_notice_fake();
extern char *get_stored_notice();
extern void plus_retry_notice();
extern void set_stored_notice();
extern void plus_window_deletions();

extern void plus_queue_notice();
extern long plus_timequeue_events();
