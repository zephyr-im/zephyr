#include <X11/Intrinsic.h>
#include <X11/StringDefs.h>

#include "xzwrite.h"

String fallback_resources[] = {
     "*icon.label: Cannot find xzwrite resource file.  Click to exit.",
     "*icon.translations: #override \n <BtnDown>: Set() \n <BtnUp>: Quit()",
     NULL,
};

XrmOptionDescRec app_options[] = {
     {"+d","*auth", XrmoptionNoArg, (caddr_t) "true"},
     {"-d","*auth", XrmoptionNoArg, (caddr_t) "false"},
     {"-s","*signature", XrmoptionSepArg, (caddr_t) NULL},
     {"+v","*verbose", XrmoptionNoArg, (caddr_t) "true"},
     {"-v","*verbose", XrmoptionNoArg, (caddr_t) "false"},
     {"-close","*closeOnSend", XrmoptionNoArg, (caddr_t) "false"},
     {"+close","*closeOnSend", XrmoptionNoArg, (caddr_t) "true"},
     {"-clear","*clearOnSend", XrmoptionNoArg, (caddr_t) "false"},
     {"+clear","*clearOnSend", XrmoptionNoArg, (caddr_t) "true"},
     {"+n","*ping", XrmoptionNoArg, (caddr_t) "true"},
     {"-n","*ping", XrmoptionNoArg, (caddr_t) "false"},
     {"+yd","*yankDest", XrmoptionNoArg, (caddr_t) "true"},
     {"-yd","*yankDest", XrmoptionNoArg, (caddr_t) "false"},
     {"+av","*addVars", XrmoptionNoArg, (caddr_t) "true"},
     {"-av","*addVars", XrmoptionNoArg, (caddr_t) "false"},
     {"+ci","*classInst", XrmoptionNoArg, (caddr_t) "true"},
     {"-ci","*classInst", XrmoptionNoArg, (caddr_t) "false"},
     {"-my","*maxYanks", XrmoptionSepArg, 0},
     {"+l","*trackLogins", XrmoptionNoArg, (caddr_t) "true"},
     {"-l","*trackLogins", XrmoptionNoArg, (caddr_t) "false"},
     {"+x","*readXzwrite", XrmoptionNoArg, (caddr_t) "true"},
     {"+z","*readZephyr", XrmoptionNoArg, (caddr_t) "true"},
     {"+a","*readAnyone", XrmoptionNoArg, (caddr_t) "true"},
     {"-x","*readXzwrite", XrmoptionNoArg, (caddr_t) "false"},
     {"-z","*readZephyr", XrmoptionNoArg, (caddr_t) "false"},
     {"-a","*readAnyone", XrmoptionNoArg, (caddr_t) "false"},
     {"+pac", "*popupAtCursor", XrmoptionNoArg, (caddr_t) "true"},
     {"-pac", "*popupAtCursor", XrmoptionNoArg, (caddr_t) "false"},
     {"-mask", "*commandMask", XrmoptionSepArg, (caddr_t) 0},
     {"-debug", "*debug", XrmoptionNoArg, (caddr_t) "true"},
     {"-opcode", "*opcode", XrmoptionSepArg, (caddr_t) ""},
     {"+pong", "*pongScan", XrmoptionNoArg, (caddr_t) "true"},
     {"-pong", "*pongScan", XrmoptionNoArg, (caddr_t) "false"},
     {"+reply", "*autoReply", XrmoptionNoArg, (caddr_t) "true"},
     {"-reply", "*autoReply", XrmoptionNoArg, (caddr_t) "false"},
     {"-columns", "*columns", XrmoptionSepArg, (caddr_t) 80},
     {"-zsigs", "*randomZsigFile", XrmoptionSepArg, (caddr_t) "*"},
     {"-logfile", "*logFile", XrmoptionSepArg, (caddr_t) "*"},
};

#define offset(field) XtOffset(Defaults *, field)
XtResource app_resources[] = {
     {"auth", "Auth", XtRBoolean, sizeof(Boolean), 
      offset(auth), XtRString, "true"}, 

     {"yankDest", "YankDest", XtRBoolean, sizeof(Boolean), 
      offset(yank_dest), XtRString, "false"}, 

     {"addGlobals", "AddGlobals", XtRBoolean, sizeof(Boolean), 
      offset(add_globals), XtRString, "false"}, 

     {"signature", "Signature", XtRString, sizeof(String), 
      offset(signature), XtRString, ""}, 

     {"verbose", "Verbose", XtRBoolean, sizeof(Boolean), 
      offset(verbose), XtRString, "false"}, 

     {"closeOnSend", "Close", XtRBoolean, sizeof(Boolean), 
      offset(close_on_send), XtRString, "false"}, 

     {"clearOnSend", "Close", XtRBoolean, sizeof(Boolean), 
      offset(clear_on_send), XtRString, "false"}, 

     {"ping", "Ping", XtRBoolean, sizeof(Boolean), 
      offset(ping), XtRString, "true"}, 

     {"classInst", "ClassInst", XtRBoolean, sizeof(Boolean), 
      offset(class_inst), XtRString, "true"}, 

     {"maxYanks", "MaxYanks", XtRInt, sizeof(int), 
      offset(max_yanks), XtRString, "25"}, 

     {"trackLogins", "TrackLogins", XtRBoolean, sizeof(Boolean), 
      offset(track_logins), XtRString, "false"}, 

     {"readZephyr", "ReadFile", XtRBoolean, sizeof(Boolean), 
      offset(read_zephyr), XtRString, "false"}, 

     {"readAnyone", "ReadFile", XtRBoolean, sizeof(Boolean), 
      offset(read_anyone), XtRString, "false"}, 

     {"readXzwrite", "ReadFile", XtRBoolean, sizeof(Boolean), 
      offset(read_xzwrite), XtRString, "false"}, 

     {"popupAtCursor", "PopupAtCursor", XtRBoolean, sizeof(Boolean), 
      offset(popup_cursor), XtRString, "false"}, 

     {"commandMask", "CommandMask", XtRInt, sizeof(int), 
      offset(command_mask), XtRString, "0"}, 

     {"debug", "Debug", XtRBoolean, sizeof(Boolean), 
      offset(debug), XtRString, "false"},

     {"opcode", "Opcode", XtRString, sizeof(String),
      offset(opcode), XtRString, ""},

     {"pongScan", "PongScan", XtRBoolean, sizeof(Boolean),
      offset(pong_scan), XtRString, "true"},

     {"autoReply", "AutoReply", XtRBoolean, sizeof(Boolean),
      offset(auto_reply), XtRString, "false"},

     {"columns", "Columns", XtRInt, sizeof(int),
	offset(columns), XtRString, "80"},
     
     {"randomZsigFile", "RandomZsigFile", XtRString, sizeof(String),
	offset(zsigfile), XtRString, "*"},

     {"logFile", "LogFile", XtRString, sizeof(String),
	offset(logfile), XtRString, "*"},
};
#undef offset

/* These are necessary because XtNumber uses sizeof, and these arrays
 * are declared as extern in interface.c */
unsigned int num_options = XtNumber(app_options);
unsigned int num_resources = XtNumber(app_resources);
