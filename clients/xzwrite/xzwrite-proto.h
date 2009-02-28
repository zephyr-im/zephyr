#ifndef __P
#ifdef __STDC__
# define	__P(s) s
#else
# define __P(s) ()
#endif
#endif


/* interface.c */
void go __P((void ));
void build_interface __P((int *argc , char **argv ));

/* resource.c */

/* destlist.c */
void dest_print __P((void ));
char **dest_text __P((void ));
int dest_num __P((void ));
void dest_set_current_dest __P((Dest dest ));
void dest_init __P((void ));
char **load_default_dest __P((void ));
char **dest_add __P((Dest dest ));
char **dest_add_string __P((char *s ));
char **dest_delete_string __P((char *s ));
char **delete_dest_index __P((int i ));
char **sort_destinations __P((void ));
int parse_into_dest __P((Dest dest , char *s ));
void dest_add_reply __P((ZNotice_t *notice ));

/* util.c */
void Warning __P((const char *first, ...));
void Error __P((const char *first, ...));
char *Malloc __P((int n, ...));
char *get_username __P((void ));

/* bfgets.c */
char *bfgets __P((char *s , int n , FILE *iop ));

/* gethomedir.c */
char *get_home_dir __P((void ));

/* dest_window.c */
void dest_add_reply __P((ZNotice_t *notice ));
void display_dest __P((void ));
void delete_dest __P((void ));
void create_dest __P((void ));
void select_dest __P((void ));

/* xzwrite.c */
int main __P((int argc , char **argv ));
void usage __P((void ));

/* edit_window.c */
void edit_win_init __P((void ));
void send_message __P((void ));
void edit_set_title __P((Dest dest ));
void edit_clear __P((void ));
void edit_yank_prev __P((void ));
void edit_yank_next __P((void ));
void edit_yank_store __P((void ));

/* zephyr.c */
void zeph_dispatch __P((XtPointer client_data , int *source , XtInputId *input_id ));
void zeph_init __P((void ));
int zeph_locateable __P((char *user ));
void zeph_subto_logins __P((char **users , int num ));
void zeph_subto_replies __P((void ));
int zeph_send_message __P((Dest dest , char *msg ));
int zeph_ping __P((Dest dest ));
int zeph_pong __P((Dest dest ));
char *zeph_get_signature __P((void ));
void log_message __P((Dest dest , char *msg ));

/* GetString.c */
Widget InitGetString __P((Widget parent , char *name ));
int GetString __P((Widget getStringWindow , String label , String value , int pop_type , char *buf , int len ));

/* Popup.c */
void Popup __P((Widget shell , XtGrabKind GrabType , int pop_type ));
void PopupSafe __P((Widget w , Dimension x , Dimension y , XtGrabKind GrabType ));
void PopupAtPointer __P((Widget w , XtGrabKind GrabType ));

/* yank.c */
void yank_init __P((void ));
Yank yank_prev __P((void ));
Yank yank_next __P((void ));
void yank_store __P((Dest dest , char *msg ));

/* menu_window.c */
void menu_toggle __P((Widget w ));
void menu_match_defs __P((void ));
void menu_signature __P((void ));

/* logins.c */
void logins_deal __P((ZNotice_t *notice ));
void logins_subscribe __P((void ));
Boolean login_scan_work __P((caddr_t client_data ));

/* xzwrite.h */

/* GetString.h */

#undef P
