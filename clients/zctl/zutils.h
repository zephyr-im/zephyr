/* XXX this file is duplicated in clients/zctl and clients/zwgc, until
   zctl is changed to message zwgc to perform these tasks */

#define ZCTL

#include <zephyr/zephyr.h>

#define	TOKEN_HOSTNAME	"%host%"
#define	TOKEN_CANONNAME	"%canon%"
#define	TOKEN_ME	"%me%"
#define	TOKEN_WILD	"*"

#define SUBSATONCE 7

#define SUB 0
#define UNSUB 1
#define PUNT 2
#define UNPUNT 3
#define LIST 4
#define ALL 5

Code_t send_wgc_control (char *, char *, int);
void fix_macros (ZSubscription_t *, ZSubscription_t *, int);
void fix_macros2 (char *src, char **dest);
Code_t set_exposure (char *, char *);
Code_t load_sub_file (int, char *, char *);
Code_t load_all_sub_files (int, char *);
Code_t xpunt (char *, char *, char *, int);
