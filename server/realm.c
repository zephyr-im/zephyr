#include "zserver.h"
#include <sys/socket.h>

Unacked *rlm_nacklist = NULL;   /* not acked list for realm-realm
                                   packets */
ZRealm **otherrealms = NULL;    /* points to an array of the known
                                   servers */
int nrealms = 0;                /* number of other realms */
int n_realm_slots = 0;          /* size of malloc'd otherrealms */

/*
 * External Routines:
 *
 * ZRealm *realm_which_realm(struct sockaddr_in *who)
 * figures out if this packet came from another realm's server
 *
 * ZRealm *realm_get_realm_by_pid(int pid)
 * figures out which realm a child handler was for
 *
 * void kill_realm_pids()
 * kills all ticket getting childen
 *
 * char *realm_expand_realm(char *realmname)
 * figures out what an abbreviated realm expands to
 *
 * Code_t realm_send_realms()
 * loops through all realms for a brain dump
 *
 * int realm_bound_for_realm(char *realm, char *recip)
 * figures out if recip is in realm, expanding recip's realm
 *
 * int realm_sender_in_realm(char *realm, char *sender)
 * figures out if sender is in realm
 *
 * ZRealm *realm_get_realm_by_name(char *name)
 * finds a realm struct from the realm array by name, tries expansion
 *
 * Code_t realm_dispatch(ZNotice_t *notice, int auth, struct sockaddr_in *who,
 *                       Server *server)
 * dispatches a message from a foreign realm
 *
 * void realm_init()
 * sets up the realm module
 *
 * void realm_deathgram()
 * tells other realms this server is going down
 *
 * Code_t realm_control_dispatch(ZNotice_t *notice, int auth,
 *                               struct sockaddr_in *who, Server *server,
 *				 ZRealm *realm)
 * dispatches a foreign realm control message
 *
 * void realm_handoff(ZNotice_t *notice, int auth, struct sockaddr_in *who,
 *                    ZRealm *realm, int ack_to_sender)
 * hands off a message to another realm
 *
 * void realm_dump_realms(File *fp)
 * do a database dump of foreign realm info
 *
 */
static int realm_next_idx_by_idx(ZRealm *realm, int idx);
static void realm_sendit(ZNotice_t *notice, struct sockaddr_in *who, int auth, ZRealm *realm, int ack_to_sender);
#ifdef HAVE_KRB5
static Code_t realm_sendit_auth(ZNotice_t *notice, struct sockaddr_in *who, int auth, ZRealm *realm, int ack_to_sender);
#endif
static void rlm_ack(ZNotice_t *notice, Unacked *nacked);
static void rlm_nack_cancel(ZNotice_t *notice, struct sockaddr_in *who);
static void rlm_rexmit(void *arg);
static Code_t realm_ulocate_dispatch(ZNotice_t *notice,int auth,struct sockaddr_in *who,Server *server,ZRealm *realm);
static Code_t realm_new_server(struct sockaddr_in *, ZNotice_t *, ZRealm *);
static Code_t realm_set_server(struct sockaddr_in *, ZRealm *);
#ifdef HAVE_KRB5
static Code_t ticket_retrieve(ZRealm *realm);
static int ticket_lookup(char *realm);
#endif

static int
is_usable(ZRealm_server *srvr)
{
    return !srvr->deleted && srvr->got_addr;
}

static int
is_sendable(ZRealm_server *srvr)
{
    return !srvr->deleted && srvr->got_addr && !srvr->dontsend;
}

static void
rlm_wakeup_cb(void *arg)
{
    ZRealm *realm = arg;
    ZNotice_t snotice;
    char *pack;
    char rlm_recipient[REALM_SZ + 1];
    int packlen, retval;

    memset (&snotice, 0, sizeof (snotice));

    snotice.z_opcode = REALM_BOOT;
    snotice.z_port = srv_addr.sin_port;
    snotice.z_class_inst = ZEPHYR_CTL_REALM;
    snotice.z_class = ZEPHYR_CTL_CLASS;
    snotice.z_recipient = "";
    snotice.z_kind = ACKED;
    snotice.z_num_other_fields = 0;
    snotice.z_default_format = "";
    snotice.z_sender = myname; /* my host name */
    sprintf(rlm_recipient, "@%s", realm->name);
    snotice.z_recipient = rlm_recipient;
    snotice.z_default_format = "";
    snotice.z_message = NULL;
    snotice.z_message_len = 0;

#ifdef HAVE_KRB5
    if (!ticket_lookup(realm->name))
	if ((retval = ticket_retrieve(realm)) != ZERR_NONE) {
	    syslog(LOG_WARNING, "rlm_wakeup failed: %s",
		   error_message(retval));
	    return;
	}
#endif

    if ((retval = ZFormatNotice(&snotice, &pack, &packlen, ZAUTH))
	!= ZERR_NONE)
    {
	syslog(LOG_WARNING, "rlm_wakeup format: %s",
	       error_message(retval));
	return;
    }
    if ((retval = ZParseNotice(pack, packlen, &snotice))
	!= ZERR_NONE) {
	syslog(LOG_WARNING, "rlm_wakeup parse: %s",
	       error_message(retval));
	free(pack);
	return;
    }

    realm_handoff(&snotice, 1, NULL, realm, 0);
    free(pack);
}

static void
rlm_set_server_address(ZRealm_server *srvr, struct hostent *hp)
{
    memmove(&srvr->addr.sin_addr, hp->h_addr, sizeof(struct in_addr));
    /* use the server port */
    srvr->addr.sin_port = srv_addr.sin_port;
    srvr->addr.sin_family = AF_INET;
    srvr->got_addr = 1;
    if (is_sendable(srvr) && srvr->realm->state == REALM_NEW) {
	srvr->realm->idx = realm_next_idx_by_idx(srvr->realm, srvr->realm->idx);
	srvr->realm->state = REALM_TARDY;
	/*
	 * Set a timer to send a wakeup to this realm.  We do this rather
	 * than just sending the notice now because, if we are not using
	 * C-ARES, then we might be called during server startup before
	 * the server is prepared to send notices.
	 */
	timer_set_rel(0, rlm_wakeup_cb, srvr->realm);
    }
}

#ifdef HAVE_ARES

static void rlm_server_address_timer_cb(void *srvr);
static void rlm_server_address_lookup_cb(void *, int, int, struct hostent *);

static void
rlm_lookup_server_address(ZRealm_server *srvr)
{
    /* Cancel any pending future lookup. */
    if (srvr->timer) {
	timer_reset(srvr->timer);
	srvr->timer = NULL;
    }
    ares_gethostbyname(achannel, srvr->name->string, AF_INET,
		       rlm_server_address_lookup_cb, srvr);
}

static void
rlm_server_address_timer_cb(void *arg)
{
    ZRealm_server *srvr = arg;

    srvr->timer = NULL;
    ares_gethostbyname(achannel, srvr->name->string, AF_INET,
		       rlm_server_address_lookup_cb, arg);
}

static void
rlm_server_address_lookup_cb(void *arg, int status, int timeouts,
			     struct hostent *hp)
{
    ZRealm_server *srvr = arg;
    int delay = 30;

    if (status == ARES_SUCCESS) {
	rlm_set_server_address(srvr, hp);
	delay = 24 * 3600; /* Check again once per day */
    } else {
	syslog(LOG_WARNING, "%s: hostname lookup failed: %s",
	       srvr->name->string, ares_strerror(status));
    }

    /*
     * Set a timer to trigger another lookup.
     * But, not if the server is deleted, which may have happened
     * while we were waiting for ARES to finish the last lookup.
     * Also, not if there is already a timer, which is possible if
     * there were two outstanding lookups and we are the second to
     * complete.  This can happen if we are asked to refresh the
     * server list while a previous lookup is still in progress,
     * since there is no convenient way to tell whether there is a
     * lookup in progress.
     */
    if (!srvr->timer && !srvr->deleted)
	srvr->timer = timer_set_rel(delay, rlm_server_address_timer_cb, arg);
}

#else

static void
rlm_lookup_server_address(ZRealm_server *srvr)
{
    struct hostent *hp;

    hp = gethostbyname(srvr->name->string);
    if (hp)
	rlm_set_server_address(srvr, hp);
    else
	syslog(LOG_WARNING, "hostname failed, %s", srvr->name->string);
}

#endif

static int
realm_get_idx_by_addr(ZRealm *realm,
		      struct sockaddr_in *who)
{
    ZRealm_server *srvr;
    int b;

    /* loop through the realms */
    for (b = 0; b < realm->count; b++) {
	srvr = realm->srvrs[b];
	if (!is_usable(srvr))
	    continue;
	if (srvr->addr.sin_addr.s_addr == who->sin_addr.s_addr)
	    return(b);
    }

    return 0;
}

static int
realm_next_idx_by_idx(ZRealm *realm, int idx)
{
    ZRealm_server *srvr;
    int b;

    /* loop through the servers */
    for (b = idx; b < realm->count; b++) {
	srvr = realm->srvrs[b];
	if (is_sendable(srvr))
	    return(b);
    }

    /* recycle */
    if (idx != 0)
	for (b = 0; b < idx; b++) {
	    srvr = realm->srvrs[b];
	    if (is_sendable(srvr))
		return(b);
	}

    return 0;
}

const char *
realm_expand_realm(char *realmname)
{
    int a;

    /* First, look for an exact match (case insensitive) */
#if defined(HAVE_KRB4) || defined(HAVE_KRB5)
    if (!strcasecmp(ZGetRealm(), realmname))
	return(ZGetRealm());
#endif

    for (a = 0; a < nrealms; a++)
      if (!strcasecmp(otherrealms[a]->name, realmname))
	return(otherrealms[a]->name);

    /* No exact match. See if there's a partial match */
#if defined(HAVE_KRB4) || defined(HAVE_KRB5)
    if (!strncasecmp(ZGetRealm(), realmname, strlen(realmname)))
	return(ZGetRealm());
#endif

    for (a = 0; a < nrealms; a++)
	if (!strncasecmp(otherrealms[a]->name, realmname, strlen(realmname)))
	    return(otherrealms[a]->name);
    return(realmname);
}

ZRealm *
realm_get_realm_by_pid(int pid)
{
    int a;

    for (a = 0; a < nrealms; a++)
	if (otherrealms[a]->child_pid == pid)
	    return(otherrealms[a]);

    return 0;
}

void
kill_realm_pids(void)
{
    int a;

    for (a = 0; a < nrealms; a++)
	if (otherrealms[a]->child_pid != 0)
	    kill(otherrealms[a]->child_pid, 9);

    return;
}

static ZRealmname *
get_realm_lists(char *file)
{
    ZRealmname *rlm_list, *rlm;
    int ii, nused, ntotal;
    FILE *fp;
    char buf[REALM_SZ + NS_MAXDNAME + 1]; /* one for newline */
    char realm[REALM_SZ], server[NS_MAXDNAME + 1];
    String *realm_name;

    nused = 0;
    if (!(fp = fopen(file, "r")))
	return((ZRealmname *)0);

    /* start with 16, realloc if necessary */
    ntotal = 16;
    rlm_list = (ZRealmname *)malloc(ntotal * sizeof(ZRealmname));
    if (!rlm_list) {
	syslog(LOG_CRIT, "get_realm_lists malloc");
	abort();
    }

    while (fgets(buf, sizeof(buf), fp)) {
	if (sscanf(buf, "%s %s", realm, server) != 2) {
	    syslog(LOG_CRIT, "bad format in %s", file);
	    abort();
	}
	realm_name = make_string(realm, 0);
	for (ii = 0; ii < nused; ii++) {
	    /* look for this realm */
	    if (rlm_list[ii].name == realm_name)
		break;
	}
	if (ii < nused) {
	    free_string(realm_name);
	    rlm = &rlm_list[ii];
	    if (rlm->nused +1 >= rlm->nservers) {
		/* make more space */
		rlm->servers = (struct _ZRealm_server *)
		    realloc((char *)rlm->servers,
			    (unsigned)rlm->nservers * 2 *
			    sizeof(struct _ZRealm_server));
		if (!rlm->servers) {
		    syslog(LOG_CRIT, "get_realm_lists realloc");
		    abort();
		}
		rlm->nservers *= 2;
	    }
	} else {
	    /* new realm */
	    if (nused + 1 >= ntotal) {
		/* make more space */
		rlm_list = (ZRealmname *)realloc((char *)rlm_list,
						(unsigned)ntotal * 2 *
						sizeof(ZRealmname));
		if (!rlm_list) {
		    syslog(LOG_CRIT, "get_realm_lists realloc");
		    abort();
		}
		ntotal *= 2;
	    }
	    rlm = &rlm_list[nused++];
	    rlm->name = realm_name;
	    rlm->nused = 0;
	    rlm->nservers = 16;
	    rlm->servers = (struct _ZRealm_server *)
		malloc(rlm->nservers * sizeof(struct _ZRealm_server));
	    if (!rlm->servers) {
		syslog(LOG_CRIT, "get_realm_lists malloc");
		abort();
	    }
	}
	memset(&rlm->servers[rlm->nused], 0, sizeof(struct _ZRealm_server));
	if (*server == '/') {
	    rlm->servers[rlm->nused].name = make_string(server + 1, 1);
	    rlm->servers[rlm->nused].dontsend = 1;
	} else {
	    rlm->servers[rlm->nused].name = make_string(server, 1);
	}
	rlm->nused++;
    }
    if (nused + 1 >= ntotal) {
	rlm_list = (ZRealmname *)realloc((char *)rlm_list,
					(unsigned)(ntotal + 1) *
					sizeof(ZRealmname));
	if (!rlm_list) {
	    syslog(LOG_CRIT, "get_realm_lists realloc");
	    abort();
	}
    }
    rlm_list[nused].name = 0;

    fclose(fp);
    return(rlm_list);
}

Code_t
realm_send_realms(void)
{
    int cnt, retval;
    for (cnt = 0; cnt < nrealms; cnt++) {
	retval = subscr_send_realm_subs(otherrealms[cnt]);
	if (retval != ZERR_NONE)
	    return(retval);
    }
    return ZERR_NONE;
}

int
realm_bound_for_realm(const char *realm, char *recip)
{
    char *rlm = NULL;
    int remote = strcmp(ZGetRealm(), realm);

    if (recip)
      rlm = strchr(recip, '@');

    if (!rlm && !remote)
	return 1;

    if (rlm && strcmp(realm_expand_realm(rlm + 1), realm) == 0)
	return 1;

    return 0;
}

int
realm_sender_in_realm(const char *realm, char *sender)
{
    char *rlm = NULL;
    int remote = strcmp(ZGetRealm(), realm);

    if (sender)
	rlm = strchr(sender, '@');

    if (!rlm && !remote)
	return 1;

    if (rlm && strcmp((rlm + 1), realm) == 0)
	return 1;

    return 0;
}

ZRealm *
realm_which_realm(struct sockaddr_in *who)
{
    ZRealm_server *srvr;
    int a, b;

    if (who->sin_port != srv_addr.sin_port)
	return 0;

    /* loop through the realms */
    for (a = 0; a < nrealms; a++)
	/* loop through the addresses for the realm */
	for (b = 0; b < otherrealms[a]->count; b++) {
	    srvr = otherrealms[a]->srvrs[b];
	    if (!is_usable(srvr))
		continue;
	    if (srvr->addr.sin_addr.s_addr == who->sin_addr.s_addr)
		return(otherrealms[a]);
	}

    return 0;
}

ZRealm *
realm_get_realm_by_name(char *name)
{
    int a;

    /* First, look for an exact match (case insensitive) */
    for (a = 0; a < nrealms; a++)
	if (!strcasecmp(otherrealms[a]->name, name))
	    return(otherrealms[a]);

    /* Failing that, look for an inexact match */
    for (a = 0; a < nrealms; a++)
	if (!strncasecmp(otherrealms[a]->name, name, strlen(name)))
	    return(otherrealms[a]);

    return 0;
}

ZRealm *
realm_get_realm_by_name_string(String *namestr)
{
    int a;

    for (a = 0; a < nrealms; a++)
	if (otherrealms[a]->namestr == namestr)
	    return otherrealms[a];

    return 0;
}

static void
rlm_nack_cancel(register ZNotice_t *notice,
		struct sockaddr_in *who)
{
    register ZRealm *which = realm_which_realm(who);
    register Unacked *nacked;

    zdbug((LOG_DEBUG, "rlm_nack_cancel: %s:%08X,%08X",
           inet_ntoa(notice->z_uid.zuid_addr),
           notice->z_uid.tv.tv_sec, notice->z_uid.tv.tv_usec));

    if (!which) {
	syslog(LOG_ERR, "non-realm ack?");
	return;
    }

    for (nacked = rlm_nacklist; nacked; nacked = nacked->next) {
	if (nacked->dest.rlm.realm == which) {
	    /* First, note the realm appears to be up */
	    which->state = REALM_UP;
	    if (ZCompareUID(&nacked->uid, &notice->z_uid)) {
		timer_reset(nacked->timer);

		if (nacked->ack_addr.sin_addr.s_addr)
		    rlm_ack(notice, nacked);

		/* free the data */
		free(nacked->packet);
		Unacked_delete(nacked);
		free(nacked);
		return;
	    }
	}
    }
    return;
}

static void
rlm_ack(ZNotice_t *notice,
	Unacked *nacked)
{
    ZNotice_t acknotice;
    ZPacket_t ackpack;
    int packlen;
    Code_t retval;

    /* tell the original sender the result */
    acknotice = *notice;
    acknotice.z_message_len = strlen(acknotice.z_message) + 1;

    packlen = sizeof(ackpack);

    if ((retval = ZFormatSmallRawNotice(&acknotice, ackpack, &packlen))
	!= ZERR_NONE) {
	syslog(LOG_ERR, "rlm_ack format: %s",
	       error_message(retval));
	return;
    }
    zdbug((LOG_DEBUG, "rlm_ack sending to %s/%d",
	   inet_ntoa(nacked->ack_addr.sin_addr),
	   ntohs(nacked->ack_addr.sin_port)));
    if ((retval = ZSetDestAddr(&nacked->ack_addr)) != ZERR_NONE) {
	syslog(LOG_WARNING, "rlm_ack set addr: %s",
	       error_message(retval));
	return;
    }
    if ((retval = ZSendPacket(ackpack, packlen, 0)) != ZERR_NONE) {
	syslog(LOG_WARNING, "rlm_ack xmit: %s", error_message(retval));
	return;
    }
}

Code_t
realm_dispatch(ZNotice_t *notice,
	       int auth,
	       struct sockaddr_in *who,
	       Server *server)
{
    ZRealm *realm;
    Code_t status = ZERR_NONE;
    char rlm_recipient[REALM_SZ + 1];
    int external = 0;
    String *notice_class;

    if (notice->z_kind == SERVACK || notice->z_kind == SERVNAK) {
	rlm_nack_cancel(notice, who);
	return(ZERR_NONE);
    }

    /* check if it's a control message */
    realm = realm_which_realm(who);

    notice_class = make_string(notice->z_class,1);

    if (class_is_admin(notice_class)) {
	syslog(LOG_WARNING, "%s sending admin opcode %s",
	       realm->name, notice->z_opcode);
    } else if (class_is_hm(notice_class)) {
	syslog(LOG_WARNING, "%s sending hm opcode %s",
	       realm->name, notice->z_opcode);
    } else if (class_is_control(notice_class)) {
	status = realm_control_dispatch(notice, auth, who,
					server, realm);
    } else if (class_is_ulogin(notice_class)) {
	/* don't need to forward this */
	if (server == me_server) {
            sprintf(rlm_recipient, "@%s", realm->name);
            notice->z_recipient = rlm_recipient;

            sendit(notice, 1, who, 0);
	}
    } else if (class_is_ulocate(notice_class)) {
	status = realm_ulocate_dispatch(notice, auth, who, server, realm);
    } else {
	/* redo the recipient */
	if (*notice->z_recipient == '\0') {
	    sprintf(rlm_recipient, "@%s", realm->name);
	    notice->z_recipient = rlm_recipient;
	    external = 0;
	} else if (realm_bound_for_realm(ZGetRealm(), notice->z_recipient)
		   && *notice->z_recipient == '@')
	{
	    /* we're responsible for getting this message out */
	    external = 1;
	    notice->z_recipient = "";
	}

	/* otherwise, send to local subscribers */
	sendit(notice, auth, who, external);
    }

    return(status);
}

void
realm_init(void)
{
    Client *client;
    ZRealmname *rlmnames;
    ZRealm *rlm;
    int ii, jj, kk, nrlmnames, nsendable;
    char realm_list_file[128];
    char rlmprinc[MAX_PRINCIPAL_SIZE];

    sprintf(realm_list_file, "%s/zephyr/%s", SYSCONFDIR, REALM_LIST_FILE);
    rlmnames = get_realm_lists(realm_list_file);
    if (!rlmnames) {
	zdbug((LOG_DEBUG, "No other realms"));
	/* should we nuke all existing server records? */
	return;
    }

    for (nrlmnames = 0; rlmnames[nrlmnames].name; nrlmnames++);

    /*
     * This happens only when we first start up.  Otherwise, otherrealms
     * is grown as needed.
     */
    if (!otherrealms) {
	otherrealms = (ZRealm **)malloc(nrlmnames * sizeof(ZRealm *));
	if (!otherrealms) {
	    syslog(LOG_CRIT, "malloc failed in realm_init");
	    abort();
	}
	memset(otherrealms, 0, (nrlmnames * sizeof(ZRealm *)));
	n_realm_slots = nrlmnames;
    }

    /* ii: entry in rlmnames */
    for (ii = 0; ii < nrlmnames; ii++) {
	nsendable = 0;
	rlm = realm_get_realm_by_name_string(rlmnames[ii].name);
	if (rlm) {
	    /* jj: server entry in otherrealms */
	    /* kk: server entry in rlmnames */
	    for (jj = 0; jj < rlm->count; jj++) {
		rlm->srvrs[jj]->deleted = 1;
		for (kk = 0; kk < rlmnames[ii].nused; kk++) {
		    if (rlmnames[ii].servers[kk].name != rlm->srvrs[jj]->name)
			continue;
		    /* update existing server */
		    rlm->srvrs[jj]->dontsend = rlmnames[ii].servers[kk].dontsend;
		    rlm->srvrs[jj]->deleted = 0;
		    rlm_lookup_server_address(rlm->srvrs[jj]);
		    if (is_sendable(rlm->srvrs[jj])) nsendable++;

		    /* mark realm.list server entry used */
		    rlmnames[ii].servers[kk].deleted = 1;
		    break;
		}
		if (rlm->srvrs[jj]->deleted && rlm->srvrs[jj]->timer) {
		    timer_reset(rlm->srvrs[jj]->timer);
		    rlm->srvrs[jj]->timer = NULL;
		}
	    }
	    for (jj = kk = 0; kk < rlmnames[ii].nused; kk++)
		if (!rlmnames[ii].servers[kk].deleted) jj++;

	    rlm->srvrs = realloc(rlm->srvrs,
				 (rlm->count + jj) * sizeof(ZRealm_server *));
	    if (!rlm->srvrs) {
		syslog(LOG_CRIT, "realloc failed in realm_init");
		abort();
	    }
	    for (kk = 0; kk < rlmnames[ii].nused; kk++) {
		if (rlmnames[ii].servers[kk].deleted) continue;
		rlm->srvrs[rlm->count] = malloc(sizeof(ZRealm_server));
		if (!rlm->srvrs[rlm->count]) {
		    syslog(LOG_CRIT, "realloc failed in realm_init");
		    abort();
		}
		*(rlm->srvrs[rlm->count]) = rlmnames[ii].servers[kk];
		rlm->srvrs[rlm->count]->realm = rlm;
		rlm_lookup_server_address(rlm->srvrs[rlm->count]);
		if (is_sendable(rlm->srvrs[rlm->count])) nsendable++;
		rlm->count++;
	    }
	    /* The current server might have been deleted or marked dontsend.
	       Advance to one we can use, if necessary. */
	    if (nsendable) {
		rlm->idx = realm_next_idx_by_idx(rlm, rlm->idx);
	    } else {
		rlm->idx = 0;
		rlm->state = REALM_NEW;
	    }
	    free(rlmnames[ii].servers);
	    continue;
	}

	if (nrealms >= n_realm_slots) {
	    otherrealms = realloc(otherrealms,
				  n_realm_slots * 2 * sizeof(ZRealm *));
	    if (!otherrealms) {
		syslog(LOG_CRIT, "realloc failed in realm_init");
		abort();
	    }
	    memset(otherrealms + n_realm_slots, 0,
		   n_realm_slots * sizeof(ZRealm *));
	    n_realm_slots *= 2;
	}

	rlm = (ZRealm *) malloc(sizeof(ZRealm));
	if (!rlm) {
	    syslog(LOG_CRIT, "malloc failed in realm_init");
	    abort();
	}
	memset(rlm, 0, sizeof(ZRealm));
	otherrealms[nrealms++] = rlm;

	rlm->namestr = rlmnames[ii].name;
	rlm->name = rlm->namestr->string;
	rlm->state = REALM_NEW;

	/* convert names to addresses */
	rlm->count = rlmnames[ii].nused;
	rlm->srvrs = malloc(rlm->count * sizeof(ZRealm_server *));
	if (!rlm->srvrs) {
	    syslog(LOG_CRIT, "malloc failed in realm_init");
	    abort();
	}
	for (jj = 0; jj < rlm->count; jj++) {
	    rlm->srvrs[jj] = &rlmnames[ii].servers[jj];
	    rlm->srvrs[jj]->realm = rlm;
	    rlm_lookup_server_address(rlm->srvrs[jj]);
	    if (is_sendable(rlm->srvrs[jj])) nsendable++;
	}

	client = (Client *) malloc(sizeof(Client));
	if (!client) {
	    syslog(LOG_CRIT, "malloc failed in realm_init");
	    abort();
	}
	memset(&client->addr, 0, sizeof(struct sockaddr_in));
#ifdef HAVE_KRB5
        client->session_keyblock = NULL;
#else
#ifdef HAVE_KRB4
	memset(&client->session_key, 0, sizeof(client->session_key));
#endif
#endif
	snprintf(rlmprinc, MAX_PRINCIPAL_SIZE, "%s.%s@%s", SERVER_SERVICE, SERVER_INSTANCE,
		rlm->name);
	client->principal = make_string(rlmprinc, 0);
	client->last_send = 0;
	client->last_ack = NOW;
	client->subs = NULL;
	client->realm = rlm;
	client->addr.sin_family = 0;
	client->addr.sin_port = 0;
	client->addr.sin_addr.s_addr = 0;

	rlm->client = client;
	rlm->idx = (nsendable) ?
	    realm_next_idx_by_idx(rlm, (random() % rlm->count)) : 0;
	rlm->subs = NULL;
	rlm->remsubs = NULL;
	rlm->child_pid = 0;
	rlm->have_tkt = 1;
    }
    free(rlmnames);
}

void
realm_deathgram(Server *server)
{
    ZRealm *realm;
    int jj = 0;

    /* Get it out once, and assume foreign servers will share */
    for (jj = 0; jj < nrealms; jj++) {
	ZNotice_t snotice;
	char *pack;
	char rlm_recipient[REALM_SZ + 1];
	int packlen, retval;

	realm = otherrealms[jj];
	memset (&snotice, 0, sizeof (snotice));

	snotice.z_kind = ACKED;
	snotice.z_port = srv_addr.sin_port;
	snotice.z_class = ZEPHYR_CTL_CLASS;
	snotice.z_class_inst = ZEPHYR_CTL_REALM;
	snotice.z_opcode = SERVER_SHUTDOWN;
	snotice.z_sender = myname; /* my host name */
	sprintf(rlm_recipient, "@%s", realm->name);
	snotice.z_recipient = rlm_recipient;
	snotice.z_default_format = "";
	snotice.z_num_other_fields = 0;
	snotice.z_default_format = "";
	snotice.z_message = (server) ? server->addr_str : NULL;
	snotice.z_message_len = (server) ? strlen(server->addr_str) + 1 : 0;

	zdbug((LOG_DEBUG, "rlm_deathgram: suggesting %s to %s",
	       (server) ? server->addr_str : "nothing", realm->name));

#ifdef HAVE_KRB5
	if (!ticket_lookup(realm->name))
	    if ((retval = ticket_retrieve(realm)) != ZERR_NONE) {
		syslog(LOG_WARNING, "rlm_deathgram failed: %s",
		       error_message(retval));
		return;
	    }
#endif

	if ((retval = ZFormatNotice(&snotice, &pack, &packlen, ZCAUTH))
	    != ZERR_NONE)
	{
	    syslog(LOG_WARNING, "rlm_deathgram format: %s",
		   error_message(retval));
	    return;
	}
	if ((retval = ZParseNotice(pack, packlen, &snotice)) != ZERR_NONE) {
	    syslog(LOG_WARNING, "rlm_deathgram parse: %s",
		   error_message(retval));
	    free(pack);
	    return;
	}

	realm_handoff(&snotice, 1, NULL, realm, 0);
	free(pack);
    }
}

static Code_t
realm_ulocate_dispatch(ZNotice_t *notice,
		       int auth,
		       struct sockaddr_in *who,
		       Server *server,
		       ZRealm *realm)
{
    register char *opcode = notice->z_opcode;

    if (!auth) {
	syslog(LOG_WARNING, "unauth locate msg from %s (%s/%s/%s)",
	       inet_ntoa(who->sin_addr),
	       notice->z_class, notice->z_class_inst,
	       notice->z_opcode); /* XXX */
	clt_ack(notice, who, AUTH_FAILED);
	return(ZERR_NONE);
    }

    if (!strcmp(opcode, REALM_REQ_LOCATE)) {
	ack(notice, who);
	ulogin_realm_locate(notice, who, realm);
    } else if (!strcmp(opcode, REALM_ANS_LOCATE)) {
	ack(notice, who);
	ulogin_relay_locate(notice, who);
    } else {
	syslog(LOG_WARNING, "%s unknown/illegal loc opcode %s",
	       realm->name, opcode);
	nack(notice, who);
    }

    return(ZERR_NONE);
}


Code_t
realm_control_dispatch(ZNotice_t *notice,
		       int auth,
		       struct sockaddr_in *who,
		       Server *server,
		       ZRealm *realm)
{
    register char *opcode = notice->z_opcode;
    Code_t status;

    if (!auth) {
	syslog(LOG_WARNING, "unauth ctl msg from %s (%s/%s/%s)",
	       inet_ntoa(who->sin_addr),
	       notice->z_class, notice->z_class_inst,
	       notice->z_opcode); /* XXX */
	if (server == me_server)
	    clt_ack(notice, who, AUTH_FAILED);
	return(ZERR_NONE);
    }

    if (strcmp(notice->z_class_inst, ZEPHYR_CTL_REALM)) {
	syslog(LOG_WARNING, "Invalid rlm_dispatch instance %s",
	       notice->z_class_inst);
	return(ZERR_NONE);
    }

    if (!strcmp(opcode, REALM_REQ_SUBSCRIBE) || !strcmp(opcode, REALM_ADD_SUBSCRIBE)) {
	/* try to add subscriptions */
	/* attempts to get defaults are ignored */
	if ((status = subscr_foreign_user(notice, who, server, realm)) != ZERR_NONE) {
	    clt_ack(notice, who, AUTH_FAILED);
	} else if (server == me_server) {
	    server_forward(notice, auth, who);
	    ack(notice, who);
	}
    } else if (!strcmp(opcode, REALM_UNSUBSCRIBE)) {
	/* try to remove subscriptions */
	if ((status = subscr_realm_cancel(who, notice, realm)) != ZERR_NONE) {
	    clt_ack(notice, who, NOT_FOUND);
	} else if (server == me_server) {
	    server_forward(notice, auth, who);
	    ack(notice, who);
	}
    } else if (!strcmp(opcode, REALM_BOOT)) {
	zdbug((LOG_DEBUG, "got a REALM_BOOT from %s",
               inet_ntoa(server->addr.sin_addr)));
	if (realm->state != REALM_UP) realm->state = REALM_STARTING;
	realm_set_server(who, realm);
#ifdef REALM_MGMT
	/* resend subscriptions but only if this was to us */
	if (server == me_server) {
	    if ((status = subscr_realm_subs(realm)) != ZERR_NONE) {
		clt_ack(notice, who, NOT_FOUND);
	    } else {
		/* do forward the hint in case it ever matters */
		server_forward(notice, auth, who);
		ack(notice, who);
	    }
	}
#endif
    } else if (!strcmp(opcode, SERVER_SHUTDOWN)) {
	/* try to remove subscriptions */
	if ((status = realm_new_server(who, notice, realm)) != ZERR_NONE) {
	    clt_ack(notice, who, NOT_FOUND);
	} else if (server == me_server) {
	    server_forward(notice, auth, who);
	    ack(notice, who);
	}
    } else {
	syslog(LOG_WARNING, "%s unknown/illegal ctl opcode %s",
	       realm->name, opcode);
	if (server == me_server)
	    nack(notice, who);
	return(ZERR_NONE);
    }
    return(ZERR_NONE);
}

static Code_t
realm_new_server(struct sockaddr_in *sin,
		 ZNotice_t *notice,
		 ZRealm *realm)
{
    unsigned long addr;
    ZRealm *rlm;
    struct sockaddr_in sinaddr;
    int srvidx;

    if (!realm)
	return ZSRV_NORLM;

    srvidx = realm_get_idx_by_addr(realm, sin);
    zdbug((LOG_DEBUG, "rlm_new_srv: message from %d in %s (%s)",
	   srvidx, realm->name, inet_ntoa(sin->sin_addr)));
    if (realm->idx == srvidx) {
	if (notice->z_message_len) {
	    addr = inet_addr(notice->z_message);
	    sinaddr.sin_addr.s_addr = addr;
	    rlm = realm_which_realm(&sinaddr);
	    /* Not exactly */
	    if (!rlm || (rlm != realm))
		return ZSRV_NORLM;
	    /* Validate the hint */
	    realm->idx =
		realm_next_idx_by_idx(realm, realm_get_idx_by_addr(realm,
								   &sinaddr));
	} else {
	    realm->idx = realm_next_idx_by_idx(realm, (realm->idx + 1) %
					       realm->count);
	}
	zdbug((LOG_DEBUG, "rlm_new_srv: switched servers (%s)", inet_ntoa((realm->srvrs[realm->idx]->addr).sin_addr)));
    } else {
      zdbug((LOG_DEBUG, "rlm_new_srv: not switching servers (%s)", inet_ntoa((realm->srvrs[realm->idx]->addr).sin_addr)));
    }
    return 0;
}

static Code_t
realm_set_server(struct sockaddr_in *sin,
		 ZRealm *realm)
{
    ZRealm *rlm;
    int idx;

    rlm = realm_which_realm(sin);
    /* Not exactly */
    if (!rlm || (rlm != realm))
	return ZSRV_NORLM;
    idx = realm_get_idx_by_addr(realm, sin);

    /* Not exactly */
    if (!is_sendable(realm->srvrs[idx]))
	return ZSRV_NORLM;

    realm->idx = idx;

    zdbug((LOG_DEBUG, "rlm_pick_srv: switched servers (%s)", inet_ntoa((realm->srvrs[realm->idx]->addr).sin_addr)));

    return 0;
}

void
realm_handoff(ZNotice_t *notice,
	      int auth,
	      struct sockaddr_in *who,
	      ZRealm *realm,
	      int ack_to_sender)
{
#ifdef HAVE_KRB5
    Code_t retval;

    if (!auth) {
	zdbug((LOG_DEBUG, "realm_sendit unauthentic to realm %s",
	       realm->name));
	realm_sendit(notice, who, auth, realm, ack_to_sender);
	return;
    }

    if (!ticket_lookup(realm->name))
	if ((retval = ticket_retrieve(realm)) != ZERR_NONE) {
	    syslog(LOG_WARNING, "rlm_handoff failed: %s",
		   error_message(retval));
	    realm_sendit(notice, who, auth, realm, ack_to_sender);
	    return;
	}

    zdbug((LOG_DEBUG, "realm_sendit to realm %s auth %d", realm->name, auth));
    /* valid ticket available now, send the message */
    retval = realm_sendit_auth(notice, who, auth, realm, ack_to_sender);
#else /* HAVE_KRB4 */
    realm_sendit(notice, who, auth, realm, ack_to_sender);
#endif /* HAVE_KRB4 */
}

static void
realm_sendit(ZNotice_t *notice,
	     struct sockaddr_in *who,
	     int auth,
	     ZRealm *realm,
	     int ack_to_sender)
{
    char *pack;
    int packlen;
    Code_t retval;
    Unacked *nacked;

    if (realm->count == 0 || realm->state == REALM_NEW) {
	/* XXX we should have a queue or something */
	syslog(LOG_WARNING, "rlm_sendit no servers for %s", realm->name);
	return;
    }

    notice->z_auth = auth;
    notice->z_authent_len = 0;
    notice->z_ascii_authent = "";
    notice->z_checksum = 0;

    /* format the notice */
    if ((retval = ZFormatRawNotice(notice, &pack, &packlen)) != ZERR_NONE) {
	syslog(LOG_WARNING, "rlm_sendit format: %s",
	       error_message(retval));
	return;
    }

    /* now send */
    if ((retval = ZSetDestAddr(&realm->srvrs[realm->idx]->addr)) != ZERR_NONE) {
	syslog(LOG_WARNING, "rlm_sendit set addr: %s",
	       error_message(retval));
	free(pack);
	return;
    }
    if ((retval = ZSendPacket(pack, packlen, 0)) != ZERR_NONE) {
	syslog(LOG_WARNING, "rlm_sendit xmit: %s", error_message(retval));
	free(pack);
	return;
    }

    /* now we've sent it, mark it as not ack'ed */

    if (!(nacked = (Unacked *)malloc(sizeof(Unacked)))) {
	/* no space: just punt */
	syslog(LOG_ERR, "rlm_sendit nack malloc");
	free(pack);
	return;
    }

    memset(nacked, 0, sizeof(Unacked));
    nacked->packet = pack;
    nacked->dest.rlm.realm = realm;
    nacked->dest.rlm.rlm_srv_idx = realm->idx;
    nacked->packsz = packlen;
    nacked->uid = notice->z_uid;
    if (ack_to_sender)
	nacked->ack_addr = *who;
    else
	nacked->ack_addr.sin_addr.s_addr = 0;

    /* set a timer to retransmit */
    nacked->timer = timer_set_rel(rexmit_times[0], rlm_rexmit, nacked);
    /* chain in */
    Unacked_insert(&rlm_nacklist, nacked);
    return;
}

static void
packet_ctl_nack(Unacked *nackpacket)
{
    ZNotice_t notice;

    /* extract the notice */
    ZParseNotice(nackpacket->packet, nackpacket->packsz, &notice);
    if (nackpacket->ack_addr.sin_addr.s_addr != 0)
	nack(&notice, &nackpacket->ack_addr);
    else
	syslog(LOG_WARNING, "would have acked nobody (%s/%s/%s)",
	       notice.z_class, notice.z_class_inst, notice.z_opcode); /* XXX */
}

static void
rlm_rexmit(void *arg)
{
    Unacked *nackpacket = (Unacked *) arg;
    Code_t retval;
    register ZRealm *realm;

    zdbug((LOG_DEBUG,"rlm_rexmit"));

    realm = nackpacket->dest.rlm.realm;

    zdbug((LOG_DEBUG, "rlm_rexmit: sending to %s:%d (%d)",
	   realm->name, realm->idx, nackpacket->rexmits));

    if (realm->count == 0 || realm->state == REALM_NEW)
	return;

    /* Check to see if we've retransmitted as many times as we can */
    if (nackpacket->rexmits >= (NUM_REXMIT_TIMES * realm->count)) {
	/* give a server ack that the packet is lost/realm dead */
	packet_ctl_nack(nackpacket);
	Unacked_delete(nackpacket);

	zdbug((LOG_DEBUG, "rlm_rexmit: %s appears dead", realm->name));
	realm->state = REALM_DEAD;

	free(nackpacket->packet);
	free(nackpacket);
	return;
    }

    /* if we've reached our limit, move on to the next server */
    if ((realm->state == REALM_TARDY) ||
	(nackpacket->rexmits &&
	 !((nackpacket->rexmits+1) % (NUM_REXMIT_TIMES/3))))
    {
	realm->idx = realm_next_idx_by_idx(realm, (realm->idx + 1) %
					   realm->count);
	zdbug((LOG_DEBUG, "rlm_rexmit: %s switching servers:%d (%s)",
	       realm->name, realm->idx,
	       inet_ntoa((realm->srvrs[realm->idx]->addr).sin_addr)));
    }

    /* throttle back if it looks like the realm is down */
    if ((realm->state != REALM_DEAD) ||
	((nackpacket->rexmits % (realm->count+1)) == 1)) {
	/* do the retransmit */
	retval = ZSetDestAddr(&realm->srvrs[realm->idx]->addr);
	if (retval != ZERR_NONE) {
	    syslog(LOG_WARNING, "rlm_rexmit set addr: %s",
		   error_message(retval));
	} else {
	    retval = ZSendPacket(nackpacket->packet, nackpacket->packsz, 0);
	    if (retval != ZERR_NONE)
		syslog(LOG_WARNING, "rlm_rexmit xmit: %s",
		       error_message(retval));
	}
	/* no per-server nack queues for foreign realms yet, doesn't matter */
	nackpacket->dest.rlm.rlm_srv_idx = realm->idx;
	zdbug((LOG_DEBUG, "rlm_rexmit(%s): send to %s", realm->name,
	       inet_ntoa((realm->srvrs[realm->idx]->addr).sin_addr)));
    } else {
	zdbug((LOG_DEBUG, "rlm_rexmit(%s): not sending to %s", realm->name,
	       inet_ntoa((realm->srvrs[realm->idx]->addr).sin_addr)));
    }

    /* reset the timer */
    nackpacket->rexmits++;
    nackpacket->timer =
	timer_set_rel(rexmit_times[nackpacket->rexmits%NUM_REXMIT_TIMES],
		      rlm_rexmit, nackpacket);
    if (rexmit_times[nackpacket->rexmits%NUM_REXMIT_TIMES] == -1) {
	zdbug((LOG_DEBUG, "rlm_rexmit(%s): would send at -1 to %s",
	       realm->name, inet_ntoa((realm->srvrs[realm->idx]->addr).sin_addr)));
    }

    return;
}

void
realm_dump_realms(FILE *fp)
{
    register int ii, jj;

    for (ii = 0; ii < nrealms; ii++) {
	(void) fprintf(fp, "%d:%s\n", ii, otherrealms[ii]->name);
	for (jj = 0; jj < otherrealms[ii]->count; jj++) {
	    (void) fprintf(fp, "\t%s%s%s%s\n",
			   inet_ntoa(otherrealms[ii]->srvrs[jj]->addr.sin_addr),
			   otherrealms[ii]->srvrs[jj]->dontsend ? " nosend" : "",
			   otherrealms[ii]->srvrs[jj]->got_addr ? " gotaddr" : "",
			   otherrealms[ii]->srvrs[jj]->deleted ? " deleted" : "");
	}
	/* dump the subs */
	subscr_dump_subs(fp, otherrealms[ii]->subs);
    }
}

#ifdef HAVE_KRB5

static Code_t
realm_auth_sendit_nacked(char *buffer, int packlen, ZRealm *realm,
			 ZUnique_Id_t uid, int ack_to_sender,
			 struct sockaddr_in *who)
{
    Unacked *nacked;

    nacked = (Unacked *) malloc(sizeof(Unacked));
    if (nacked == NULL)
	return ENOMEM;

    memset(nacked, 0, sizeof(Unacked));
    nacked->packet = buffer;
    nacked->dest.rlm.realm = realm;
    nacked->dest.rlm.rlm_srv_idx = realm->idx;
    nacked->packsz = packlen;
    nacked->uid = uid;

    /* Do the ack for the last frag, below */
    if (ack_to_sender)
	nacked->ack_addr = *who;
    else
	nacked->ack_addr.sin_addr.s_addr = 0;

    /* set a timer to retransmit */
    nacked->timer = timer_set_rel(rexmit_times[0], rlm_rexmit, nacked);

    /* chain in */
    Unacked_insert(&rlm_nacklist, nacked);

    return ZERR_NONE;
}

static Code_t
realm_sendit_auth(ZNotice_t *notice,
		  struct sockaddr_in *who,
		  int auth,
		  ZRealm *realm,
		  int ack_to_sender)
{
    char *buffer = NULL;
    int hdrlen, offset, fragsize, message_len;
    int origoffset, origlen;
    Code_t retval;
    char multi[64];
    ZNotice_t partnotice, newnotice;

    if (realm->count == 0 || realm->state == REALM_NEW) {
	/* XXX we should have a queue or something */
	syslog(LOG_WARNING, "rlm_sendit_auth no servers for %s", realm->name);
	return ZERR_INTERNAL;
    }

    offset = 0;

    buffer = (char *)malloc(sizeof(ZPacket_t));
    if (!buffer) {
	syslog(LOG_ERR, "realm_sendit_auth malloc");
	return ENOMEM; /* DON'T put on nack list */
    }

    newnotice = *notice;

    hdrlen = 0;
    retval = ZMakeZcodeRealmAuthentication(&newnotice, buffer, sizeof(ZPacket_t),
					   &hdrlen, realm->name);
    if (retval)
	syslog(LOG_WARNING,
	       "rlm_sendit_auth: ZMakeZcodeRealmAuthentication: %s",
	       error_message(retval));

    if (!retval) {
	retval = ZSetDestAddr(&realm->srvrs[realm->idx]->addr);
	if (retval)
	    syslog(LOG_WARNING, "rlm_sendit_auth: ZSetDestAddr: %s",
		   error_message(retval));
    }

    /* This is not terribly pretty, but it does do its job.
     * If a packet we get that needs to get sent off to another realm is
     * too big after we slap on our authent, we refragment it further,
     * a la Z_SendFragmentedNotice. This obviates the need for what
     * used to be done in ZFormatAuthenticRealmNotice, as we do it here.
     * At some point it should be pulled back out into its own function,
     * but only the server uses it.
     */

    if (!retval &&
	((notice->z_message_len+hdrlen > (int)sizeof(ZPacket_t)) ||
	 (notice->z_message_len+hdrlen > Z_MAXPKTLEN))) {

	/* Reallocate buffers inside the refragmenter */
	free(buffer);
	buffer = NULL;

	partnotice = *notice;

	origoffset = 0;
	origlen = notice->z_message_len;

	if (notice->z_multinotice && strcmp(notice->z_multinotice, "")) {
	    if (sscanf(notice->z_multinotice, "%d/%d", &origoffset,
		       &origlen) != 2) {
		syslog(LOG_WARNING,
		       "rlm_sendit_auth frag: multinotice parse failed");
		retval = ZERR_BADFIELD;
	    }
	}

	fragsize = Z_MAXPKTLEN - hdrlen - Z_FRAGFUDGE;

	if (fragsize < 0)
	    retval = ZERR_HEADERLEN;

	while (!retval &&
	       (offset < notice->z_message_len || !notice->z_message_len)) {
	    (void)sprintf(multi, "%d/%d", offset+origoffset, origlen);
	    partnotice.z_multinotice = multi;
	    if (offset > 0) {
		(void)Z_gettimeofday(&partnotice.z_uid.tv,
				      (struct timezone *)0);
		partnotice.z_uid.tv.tv_sec = htonl((u_long)
						   partnotice.z_uid.tv.tv_sec);
		partnotice.z_uid.tv.tv_usec =
		    htonl((u_long) partnotice.z_uid.tv.tv_usec);
		(void)memcpy((char *)&partnotice.z_uid.zuid_addr, &__My_addr,
			      sizeof(__My_addr));
		partnotice.z_sender_sockaddr.ip4.sin_family = AF_INET; /* XXX */
		(void)memcpy((char *)&partnotice.z_sender_sockaddr.ip4.sin_addr,
			      &__My_addr, sizeof(__My_addr));
	    }
	    message_len = min(notice->z_message_len-offset, fragsize);
	    partnotice.z_message = notice->z_message+offset;
	    partnotice.z_message_len = message_len;

	    buffer = (char *)malloc(sizeof(ZPacket_t));
	    if (!buffer) {
		syslog(LOG_ERR, "realm_sendit_auth malloc");
		retval = ENOMEM; /* DON'T put on nack list */
	    }

	    if (!retval) {
		retval = ZMakeZcodeRealmAuthentication(&partnotice, buffer,
						       sizeof(ZPacket_t),
						       &hdrlen,
						       realm->name);
		if (retval != ZERR_NONE)
		    syslog(LOG_WARNING, "rlm_sendit_auth set addr: %s",
			   error_message(retval));
	    }

	    if (!retval) {
		(void) memcpy(buffer + hdrlen, partnotice.z_message,
			      partnotice.z_message_len);

		retval = ZSendPacket(buffer,
				     hdrlen + partnotice.z_message_len, 0);
		if (retval)
		    syslog(LOG_WARNING, "rlm_sendit_auth xmit: %s",
			   error_message(retval));
	    }

	    if (!retval) {
		retval = realm_auth_sendit_nacked(buffer, hdrlen +
                                                partnotice.z_message_len,realm,
						  partnotice.z_uid,
						  ack_to_sender, who);
		if (retval) /* no space: just punt */
		    syslog(LOG_ERR,
			   "rlm_sendit_auth: realm_auth_sendit_nacked: %s",
			   error_message(retval));
	    }

	    if (!retval)
		offset += fragsize;

	    if (!notice->z_message_len)
		break;
	}
    } else if (!retval) {
	/* This is easy, no further fragmentation needed */
	(void)memcpy(buffer + hdrlen, newnotice.z_message,
		      newnotice.z_message_len);

	retval = ZSendPacket(buffer, hdrlen + newnotice.z_message_len, 0);
	if (retval)
	    syslog(LOG_WARNING, "rlm_sendit_auth xmit: %s",
		   error_message(retval));
	else {
	    retval = realm_auth_sendit_nacked(buffer,
                                              hdrlen + newnotice.z_message_len,
                                              realm, newnotice.z_uid,
					      ack_to_sender, who);
	    if (retval) /* no space: just punt */
		syslog(LOG_ERR, "rlm_sendit_auth: realm_auth_sendit_nacked: %s",
		       error_message(retval));
	}
    }

    if (retval && buffer != NULL)
	free(buffer);
    return retval;
}

static int
ticket_lookup(char *realm)
{
    krb5_error_code result;
    krb5_timestamp sec;
    krb5_ccache ccache;
    krb5_creds creds_in, creds;

    result = krb5_cc_default(Z_krb5_ctx, &ccache);
    if (result)
      return 0;

    memset(&creds_in, 0, sizeof(creds_in));
    memset(&creds, 0, sizeof(creds));

    result = krb5_cc_get_principal(Z_krb5_ctx, ccache, &creds_in.client);
    if (result) {
      krb5_cc_close(Z_krb5_ctx, ccache);
      return 0;
    }

    result = krb5_build_principal(Z_krb5_ctx, &creds_in.server,
                                  strlen(realm),
                                  realm,
                                  SERVER_KRB5_SERVICE, SERVER_INSTANCE,
				  NULL);
    if (result) {
      krb5_cc_close(Z_krb5_ctx, ccache);
      return 0;
    }

    result = krb5_cc_retrieve_cred(Z_krb5_ctx, ccache, 0, &creds_in, &creds);
    krb5_cc_close(Z_krb5_ctx, ccache);
    /* good ticket? */

    krb5_timeofday (Z_krb5_ctx, &sec);
    krb5_free_cred_contents(Z_krb5_ctx, &creds_in); /* hope this is OK */
    if ((result == 0) && (sec < creds.times.endtime)) {
      krb5_free_cred_contents(Z_krb5_ctx, &creds);
      return (1);
    }
    if (!result)
      krb5_free_cred_contents(Z_krb5_ctx, &creds);

    return (0);
}

static Code_t
ticket_retrieve(ZRealm *realm)
{
    int pid;
    krb5_ccache ccache;
    krb5_error_code result;
    krb5_creds creds_in, *creds;

    get_tgt();

    if (realm->child_pid)
	/* Right idea. Basically, we haven't gotten it yet */
	return KRB5KRB_AP_ERR_TKT_EXPIRED;

    if (realm->have_tkt) {
	/* Get a pointer to the default ccache. We don't need to free this. */
	result = krb5_cc_default(Z_krb5_ctx, &ccache);

	/* GRRR.  There's no allocator or constructor for krb5_creds */
	/* GRRR.  It would be nice if this API were documented at all */
	memset(&creds_in, 0, sizeof(creds_in));

	if (!result)
	    result = krb5_cc_get_principal(Z_krb5_ctx, ccache, &creds_in.client);
	/* construct the service principal */
	if (!result)
	    result = krb5_build_principal(Z_krb5_ctx, &creds_in.server,
					  strlen(realm->name), realm->name,
					  SERVER_KRB5_SERVICE, SERVER_INSTANCE,
					  NULL);

	/* HOLDING: creds_in.server */

	/* look up or get the credentials we need */
	if (!result)
	    result = krb5_get_credentials(Z_krb5_ctx, 0 /* flags */, ccache,
					  &creds_in, &creds);
	krb5_cc_close(Z_krb5_ctx, ccache);
	krb5_free_cred_contents(Z_krb5_ctx, &creds_in); /* hope this is OK */
	if (!result) {
	    krb5_free_creds(Z_krb5_ctx, creds);
	    return 0;
	}
    } else {
	syslog(LOG_ERR, "tkt_rtrv: don't have ticket, but have no child");
        result = KRB5KRB_AP_ERR_TKT_EXPIRED;
    }

    pid = fork();
    if (pid < 0) {
	syslog(LOG_ERR, "tkt_rtrv: can't fork");
	return errno;
    }
    else if (pid == 0) {
#ifdef _POSIX_VERSION
	struct sigaction action;

	action.sa_flags = 0;
	sigemptyset(&action.sa_mask);
	action.sa_handler = 0;
	sigaction(SIGCHLD, &action, NULL);
	sigaction(SIGINT, &action, NULL);
	sigaction(SIGTERM, &action, NULL);
	sigaction(SIGUSR1, &action, NULL);
	sigaction(SIGUSR2, &action, NULL);
	sigaction(SIGFPE, &action, NULL);
	sigaction(SIGHUP, &action, NULL);
#ifdef SIGEMT
	sigaction(SIGEMT, &action, NULL);
#endif
#else
	signal(SIGCHLD, SIG_DFL);
	signal(SIGINT, SIG_DFL);
	signal(SIGTERM, SIG_DFL);
	signal(SIGUSR1, SIG_DFL);
	signal(SIGUSR2, SIG_DFL);
	signal(SIGFPE, SIG_DFL);
	signal(SIGHUP, SIG_DFL);
#ifdef SIGEMT
	signal(SIGEMT, SIG_DFL);
#endif
#endif

	syslog(LOG_INFO, "tkt_rtrv running for %s", realm->name);
	while (1) {
	    /* Get a pointer to the default ccache.
	       We don't need to free this. */
	    result = krb5_cc_default(Z_krb5_ctx, &ccache);

	    /* GRRR.  There's no allocator or constructor for krb5_creds */
	    /* GRRR.  It would be nice if this API were documented at all */
	    memset(&creds_in, 0, sizeof(creds_in));

	    if (!result)
		result = krb5_cc_get_principal(Z_krb5_ctx, ccache,
					       &creds_in.client);
	    /* construct the service principal */
	    if (!result)
		result = krb5_build_principal(Z_krb5_ctx, &creds_in.server,
					      strlen(realm->name), realm->name,
					      SERVER_KRB5_SERVICE,
					      SERVER_INSTANCE,
					      NULL);

	    /* HOLDING: creds_in.server */

	    /* look up or get the credentials we need */
	    if (!result)
		result = krb5_get_credentials(Z_krb5_ctx, 0 /* flags */, ccache,
					      &creds_in, &creds);
	    krb5_cc_close(Z_krb5_ctx, ccache);
	    krb5_free_cred_contents(Z_krb5_ctx, &creds_in); /* hope this is OK */
	    if (!result) {
		krb5_free_creds(Z_krb5_ctx, creds);
		syslog(LOG_INFO, "tkt_rtrv succeeded for %s", realm->name);
		exit(0);
	    }

	    /* Sleep a little while before retrying */
	    sleep(30);
	}
    } else {
	realm->child_pid = pid;
	realm->have_tkt = 0;

	syslog(LOG_WARNING, "tkt_rtrv: %s: %d", realm->name,
	       result);
	return (result);
    }
}
#endif /* HAVE_KRB5 */
