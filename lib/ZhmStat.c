/* This file is part of the Project Athena Zephyr Notification System.
 * It contains the ZhmStat() function.
 *
 *      Created by:     Marc Horowitz
 *
 *      $Source$
 *      $Author$
 *
 *      Copyright (c) 1996 by the Massachusetts Institute of Technology.
 *      For copying and distribution information, see the file
 *      "mit-copyright.h". 
 */

#include <internal.h>
#include <sys/socket.h>

static int outoftime = 0;

static RETSIGTYPE timeout()
{
	outoftime = 1;
}

Code_t ZhmStat(hostaddr, notice)
    struct in_addr *hostaddr;
    ZNotice_t *notice;
{
    struct servent *sp;
    struct sockaddr_in sin;
    ZNotice_t req;
    Code_t code;
#ifdef _POSIX_VERSION
    struct sigaction sa;
#endif

    (void) memset((char *)&sin, 0, sizeof(struct sockaddr_in));

    sp = getservbyname(HM_SVCNAME, "udp");

    sin.sin_port = (sp) ? sp->s_port : HM_SVC_FALLBACK;
    sin.sin_family = AF_INET;

    if (hostaddr)
	sin.sin_addr = *hostaddr;
    else
	sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    (void) memset((char *)&req, 0, sizeof(req));
    req.z_kind = STAT;
    req.z_port = 0;
    req.z_class = HM_STAT_CLASS;
    req.z_class_inst = HM_STAT_CLIENT;
    req.z_opcode = HM_GIMMESTATS;
    req.z_sender = "";
    req.z_recipient = "";
    req.z_default_format = "";
    req.z_message_len = 0;
	
    if ((code = ZSetDestAddr(&sin)) != ZERR_NONE)
	return(code);

    if ((code = ZSendNotice(&req, ZNOAUTH)) != ZERR_NONE)
	return(code);

#ifdef _POSIX_VERSION
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sa.sa_handler = timeout;
    (void) sigaction(SIGALRM, &sa, (struct sigaction *)0);
#else
    (void) signal(SIGALRM,timeout);
#endif

    outoftime = 0;
    (void) alarm(10);

    if (((code = ZReceiveNotice(notice, (struct sockaddr_in *) 0))
	 != ZERR_NONE) &&
	code != EINTR)
	return(code);

    (void) alarm(0);

    if (outoftime)
	return(ZERR_HMDEAD);

    return(ZERR_NONE);
}
