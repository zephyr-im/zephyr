#ifdef __STDC__
# define	P(s) s
#else
# define P(s) ()
#endif


/* interface.c */
void go P((void ));
void build_interface P((int *argc , char **argv ));

/* resource.c */

/* destlist.c */
void dest_print P((void ));
char **dest_text P((void ));
int dest_num P((void ));
void dest_set_current_dest P((Dest dest ));
void dest_init P((void ));
char **load_default_dest P((void ));
char **dest_add P((Dest dest ));
char **dest_add_string P((char *s ));
char **dest_delete_string P((char *s ));
char **delete_dest_index P((int i ));
char **sort_destinations P((void ));
int parse_into_dest P((Dest dest , char *s ));
void dest_add_reply P((ZNotice_t *notice ));

/* util.c */
char *get_username P((void ));

/* bfgets.c */
char *bfgets P((char *s , int n , FILE *iop ));

/* gethomedir.c */
char *get_home_dir P((void ));

/* dest_window.c */
void dest_add_reply P((ZNotice_t *notice ));
void display_dest P((void ));
void delete_dest P((void ));
void create_dest P((void ));
void select_dest P((void ));

/* xzwrite.c */
int main P((int argc , char **argv ));
int usage P((void ));

/* edit_window.c */
void edit_win_init P((void ));
void send_message P((void ));
void edit_set_title P((Dest dest ));
void edit_clear P((void ));
void edit_yank_prev P((void ));
void edit_yank_next P((void ));
void edit_yank_store P((void ));

/* zephyr.c */
void zeph_dispatch P((XtPointer client_data , int *source , XtInputId *input_id ));
void zeph_init P((void ));
int zeph_locateable P((char *user ));
void zeph_subto_logins P((char **users , int num ));
void zeph_subto_replys P((void ));
int zeph_send_message P((Dest dest , char *msg ));
int zeph_ping P((Dest dest ));
int zeph_pong P((Dest dest ));
char *zeph_get_signature P((void ));
void log_message P((Dest dest , char *msg ));

/* GetString.c */
Widget InitGetString P((Widget parent , char *name ));
int GetString P((Widget getStringWindow , String label , String value , int pop_type , char *buf , int len ));

/* Popup.c */
void Popup P((Widget shell , XtGrabKind GrabType , int pop_type ));
void PopupSafe P((Widget w , Dimension x , Dimension y , XtGrabKind GrabType ));
void PopupAtPointer P((Widget w , XtGrabKind GrabType ));

/* yank.c */
void yank_init P((void ));
Yank yank_prev P((void ));
Yank yank_next P((void ));
void yank_store P((Dest dest , char *msg ));

/* menu_window.c */
void menu_toggle P((Widget w ));
void menu_match_defs P((void ));
void menu_signature P((void ));

/* logins.c */
void logins_deal P((ZNotice_t *notice ));
void logins_subscribe P((void ));
Boolean login_scan_work P((caddr_t client_data ));

/* xzwrite.h */

/* GetString.h */

#undef P
