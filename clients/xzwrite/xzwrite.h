#include <stdio.h>
#include <X11/Intrinsic.h>	/* for String and Boolean */

#define ZLEN		60
#define DEFAULT_CLASS	"MESSAGE"
#define DEFAULT_INST	"PERSONAL"
#define XZWRITE_DEST_FILE "/.xzwrite.dest"
#define ZEPHYR_FILE	"/.zephyr.subs"
#define ANYONE_FILE	"/.anyone"

#define SEND_OK		-1000
#define SENDFAIL_RECV	-1001
#define SENDFAIL_SEND	-1002
#define SENDFAIL_ACK	-1003

/* Structure to contains values from the resource database */
typedef struct _defaults {
     String signature, opcode;
     Boolean auth;
     Boolean close_on_send;
     Boolean clear_on_send;
     Boolean ping;
     Boolean verbose;
     Boolean yank_dest;
     Boolean add_globals;
     Boolean read_xzwrite;
     Boolean read_zephyr;
     Boolean read_anyone;
     Boolean class_inst;
     Boolean track_logins;
     Boolean popup_cursor;
     Boolean debug;
     Boolean pong_scan;
     Boolean auto_reply;
     int max_yanks, command_mask, columns;
     String  zsigfile;
     String  logfile;
} Defaults;

/* Structure to contain a legal zephyr triple */
typedef struct _destination {
     char zclass[ZLEN], zinst[ZLEN], zrecip[ZLEN];
} DestRec, *Dest;

/* Structure to contain a yank */
typedef struct _yank {
     DestRec dest;
     char *msg;
} YankRec, *Yank;

#include <zephyr/zephyr.h>
#include "xzwrite-proto.h"
