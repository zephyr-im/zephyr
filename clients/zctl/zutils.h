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

Code_t send_wgc_control ZP((char *, char *, int));
void fix_macros ZP((ZSubscription_t *, ZSubscription_t *, int));
void fix_macros2 ZP((char *src, char **dest));
Code_t set_exposure ZP((char *, char *));
Code_t load_sub_file ZP((int, char *, char *));
Code_t load_all_sub_files ZP((int, char *));
Code_t xpunt ZP((char *, char *, char *, int));
