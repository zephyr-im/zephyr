#include "zserver.h"
#include <sys/socket.h>

Unacked *rlm_nacklist = NULL;   /* not acked list for realm-realm
                                   packets */
Realm *otherrealms;             /* points to an array of the known
                                   servers */
int nrealms = 0;                /* number of other realms */

static void get_realm_addrs __P(());
static void realm_sendit __P((ZNotice_t *notice, struct sockaddr_in *who, int auth, Realm *realm, int ack_to_sender));
static void realm_sendit_auth __P((ZNotice_t *notice, struct sockaddr_in *who, int auth, Realm *realm, int ack_to_sender));
static void rlm_ack __P((ZNotice_t *notice, Unacked *nacked));
static void rlm_nack_cancel __P((ZNotice_t *notice, struct sockaddr_in *who));
static void rlm_new_ticket __P(());
static void rlm_rexmit __P((void *arg));
static Code_t realm_ulocate_dispatch __P((ZNotice_t *notice,int auth,struct sockaddr_in *who,Server *server,Realm *realm));
#ifdef HAVE_KRB4
static Code_t ticket_retrieve __P((Realm *realm));
#endif

char *
realm_expand_realm(realmname)
char *realmname;
{
	static char expand[REALM_SZ];
	static char krb_realm[REALM_SZ+1];
	char *cp1, *cp2;
	int retval;
	FILE *rlm_file;
	char list_file[128];
	char linebuf[BUFSIZ];
	char scratch[128];

	/* upcase what we got */
	cp2 = realmname;
	cp1 = expand;
	while (*cp2) {
		*cp1++ = toupper(*cp2++);
	}
	*cp1 = '\0';

	sprintf(list_file, "%s/zephyr/%s", SYSCONFDIR, REALM_LIST_FILE);

	if ((rlm_file = fopen(list_file, "r")) == (FILE *) 0) {
		return(expand);
	}

	if (fgets(linebuf, BUFSIZ, rlm_file) == NULL) {
		/* error reading */
		(void) fclose(rlm_file);
		return(expand);
	}

	while (1) {
		/* run through the file, looking for admin host */
		if (fgets(linebuf, BUFSIZ, rlm_file) == NULL) {
			(void) fclose(rlm_file);
			return(expand);
		}

		if (sscanf(linebuf, "%s %s", krb_realm, scratch) < 2)
			continue;
		if (!strncmp(krb_realm, expand, strlen(expand))) {
			(void) fclose(rlm_file);
			return(krb_realm);
		}
	}
#ifdef KERBEROS
	if (!strncmp(my_realm, expand, strlen(expand)))
	    return(my_realm);
#endif
	return(expand);
}

Realmname *
get_realm_lists(file)
    char *file;
{
  Realmname *rlm_list, *rlm;
  int ii, nused, ntotal;
  FILE *fp;
  char buf[REALM_SZ + MAXHOSTNAMELEN + 1]; /* one for newline */
  char realm[REALM_SZ], server[MAXHOSTNAMELEN + 1];
  
  nused = 0;
  if (!(fp = fopen(file, "r")))
    return((Realmname *)0);
  
  /* start with 16, realloc if necessary */
  ntotal = 16;
  rlm_list = (Realmname *)malloc(ntotal * sizeof(Realmname));
  if (!rlm_list) {
    syslog(LOG_CRIT, "get_realm_lists malloc");
    abort();
  }

  while (fgets(buf, REALM_SZ + MAXHOSTNAMELEN + 1, fp)) {
    if (sscanf(buf, "%s %s", realm, server) != 2) {
      syslog(LOG_CRIT, "bad format in %s", file);
      abort();
    }
    for (ii = 0; ii < nused; ii++) {
      /* look for this realm */
      if (!strcmp(rlm_list[ii].name, realm))
        break;
    }
    if (ii < nused) {
      rlm = &rlm_list[ii];
      if (rlm->nused +1 >= rlm->nservers) {
        /* make more space */
        rlm->servers = (char **)realloc((char *)rlm->servers, 
                                        (unsigned)rlm->nservers * 2 * 
                                        sizeof(char *));
        if (!rlm->servers) {
          syslog(LOG_CRIT, "get_realm_lists realloc");
          abort();
        }
        rlm->nservers *= 2;
      }
      rlm->servers[rlm->nused++] = strsave(server);
    } else {
      /* new realm */
      if (nused + 1 >= ntotal) {
        /* make more space */
        rlm_list = (Realmname *)realloc((char *)rlm_list,
                                               (unsigned)ntotal * 2 * 
                                               sizeof(Realmname));
        if (!rlm_list) {
          syslog(LOG_CRIT, "get_realm_lists realloc");
          abort();
        }
        ntotal *= 2;
      }
      rlm = &rlm_list[nused++];
      strcpy(rlm->name, realm);
      rlm->nused = 0;
      rlm->nservers = 16;
      rlm->servers = (char **)malloc(rlm->nservers * sizeof(char *));
      if (!rlm->servers) {
        syslog(LOG_CRIT, "get_realm_lists malloc");
        abort();
      }
      rlm->servers[rlm->nused++] = strsave(server);
    }
  }
  if (nused + 1 >= ntotal) {
    rlm_list = (Realmname *)realloc((char *)rlm_list,
                                           (unsigned)(ntotal + 1) * 
                                           sizeof(Realmname));
    if (!rlm_list) {
      syslog(LOG_CRIT, "get_realm_lists realloc");
      abort();
    }
  }
  *rlm_list[nused].name = '\0';
  
  return(rlm_list);
}

Code_t 
realm_send_realms()
{
  int cnt, retval;
  for (cnt = 0; cnt < nrealms; cnt++) {
    if (retval = (subscr_send_realm_subs(&otherrealms[cnt])) != ZERR_NONE)
      return(retval);
  }
}

int
bound_for_local_realm(notice)
    ZNotice_t *notice;
{
  char *realm;
  
  realm = strchr(notice->z_recipient, '@');
  
  if (!realm || !strcmp(realm_expand_realm(realm + 1), ZGetRealm()))
    return 1;

  return 0;
}

int
sender_in_realm(notice)
    ZNotice_t *notice;
{
  char *realm;

  realm = strchr(notice->z_sender, '@');

  if (!realm || !strcmp(realm + 1, ZGetRealm()))
    return 1;

  return 0;
}

Realm *
realm_which_realm(who)
    struct sockaddr_in *who;
{
  Realm *realm;
  struct sockaddr_in *addr;
  int a, b;

  /* loop through the realms */
  for (realm = otherrealms, a = 0; a < nrealms; a++, realm++)
    /* loop through the addresses for the realm */
    for (addr = realm->addrs, b = 0; b < realm->count; b++, addr++)
      if (addr->sin_addr.s_addr == who->sin_addr.s_addr)
        return(realm);
  
  return 0;
}

Realm *
realm_get_realm_by_name(name)
char *name;
{
  int a;
  Realm *realm;

  for (realm = otherrealms, a = 0; a < nrealms; a++, realm++)
    if (!strcmp(realm->name, name))
      return(realm);

  return 0;
}

static void
rlm_nack_cancel(notice, who)
    register ZNotice_t *notice;
    struct sockaddr_in *who;
{
  register Realm *which = realm_which_realm(who);
  register Unacked *nacked, *next;
  ZNotice_t acknotice;
  ZPacket_t retval;
  
#if 0
    zdbug((LOG_DEBUG, "rlm_nack_cancel: %s:%08X,%08X",
           inet_ntoa(notice->z_uid.zuid_addr),
           notice->z_uid.tv.tv_sec, notice->z_uid.tv.tv_usec));
#endif
  if (!which) {
    syslog(LOG_ERR, "non-realm ack?");
    return;
  }

  for (nacked = rlm_nacklist; nacked; nacked = nacked->next) {
    if (&otherrealms[nacked->dest.rlm.rlm_idx] == which) {
      if (ZCompareUID(&nacked->uid, &notice->z_uid)) {
        timer_reset(nacked->timer);
        
        if (nacked->ack_addr.sin_addr.s_addr)
          rlm_ack(notice, nacked);
        
        /* free the data */
        free(nacked->packet);
        LIST_DELETE(nacked);
        free(nacked);
        return;
      }
    }
  }
#if 0
    zdbug((LOG_DEBUG,"nack_cancel: nack not found %s:%08X,%08X",
           inet_ntoa (notice->z_uid.zuid_addr),
           notice->z_uid.tv.tv_sec, notice->z_uid.tv.tv_usec));
#endif
  return;
}

static void
rlm_ack(notice, nacked)
    ZNotice_t *notice;
    Unacked *nacked;
{
  ZNotice_t acknotice;
  ZPacket_t ackpack;
  int packlen;
  Code_t retval;
  
  /* tell the original sender the result */
  acknotice = *notice;
  acknotice.z_message_len = strlen(acknotice.z_message) + 1;
  
  packlen = sizeof(ackpack);
  
  if ((retval = ZFormatSmallRawNotice(&acknotice, ackpack, &packlen)) != ZERR_NONE) {
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
realm_dispatch(notice, auth, who, server)
    ZNotice_t *notice;
    int auth;
    struct sockaddr_in *who;
    Server *server;
{
        Realm *realm;
        struct sockaddr_in newwho;
        Code_t status = ZERR_NONE;
        char rlm_recipient[REALM_SZ + 1];
        int external = 0;
        String *notice_class;

        if (notice->z_kind == SERVACK || notice->z_kind == SERVNAK) {
          rlm_nack_cancel(notice, who);
          return(ZERR_NONE);
        }
        /* set up a who for the real origin */
        memset((caddr_t) &newwho, 0, sizeof(newwho));
        newwho.sin_family = AF_INET;
        newwho.sin_addr.s_addr = notice->z_sender_addr.s_addr;
        newwho.sin_port = hm_port;

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
            /* only send to our realm */
            external = 0;
          } else if (bound_for_local_realm(notice) && *notice->z_recipient 
                     == '@') 
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
realm_init()
{
  Client *client;
  Realmname *rlmnames;
  Realm *rlm;
  int ii, jj, found;
  struct in_addr *addresses;
  struct hostent *hp;
  char list_file[128];
  char rlmprinc[ANAME_SZ+INST_SZ+REALM_SZ+3];

  sprintf(list_file, "%s/zephyr/%s", SYSCONFDIR, REALM_LIST_FILE);
  rlmnames = get_realm_lists(list_file);
  if (!rlmnames) {
    zdbug((LOG_DEBUG, "No other realms"));
    nrealms = 0;
    return;
  }

  for (nrealms = 0; *rlmnames[nrealms].name; nrealms++);
  
  otherrealms = (Realm *)malloc(nrealms * sizeof(Realm));
  if (!otherrealms) {
    syslog(LOG_CRIT, "malloc failed in get_realm_addrs");
    abort();
  }

  for (ii = 0; ii < nrealms; ii++) {
    rlm = &otherrealms[ii];
    strcpy(rlm->name, rlmnames[ii].name);

    addresses = (struct in_addr *)malloc(rlmnames[ii].nused * sizeof(struct in_addr));
    if (!addresses) {
      syslog(LOG_CRIT, "malloc failed in get_realm_addrs");
      abort();
    }
    /* convert names to addresses */
    found = 0;
    for (jj = 0; jj < rlmnames[ii].nused; jj++) {
      hp = gethostbyname(rlmnames[ii].servers[jj]);
      if (hp) {
        memmove((caddr_t) &addresses[found], (caddr_t)hp->h_addr, sizeof(struct in_addr));
        found++;
      } else
        syslog(LOG_WARNING, "hostname failed, %s", rlmnames[ii].servers[jj]);
      /* free the hostname */
      free(rlmnames[ii].servers[jj]);
    }
    rlm->count = found;
    rlm->addrs = (struct sockaddr_in *)malloc(found * sizeof (struct sockaddr_in));
    if (!rlm->addrs) {
      syslog(LOG_CRIT, "malloc failed in get_realm_addrs");
      abort();
    }
    for (jj = 0; jj < rlm->count; jj++) {
      rlm->addrs[jj].sin_family = AF_INET;
      /* use the server port */
      rlm->addrs[jj].sin_port = srv_addr.sin_port;
      rlm->addrs[jj].sin_addr = addresses[jj];
    }
    client = (Client *) malloc(sizeof(Client));
    if (!client) {
      syslog(LOG_CRIT, "malloc failed in get_realm_addrs");
      abort();
    }
    memset(&client->addr, 0, sizeof(struct sockaddr_in));
#ifdef HAVE_KRB4
    memset(&client->session_key, 0, sizeof(client->session_key));
#endif
    sprintf(rlmprinc, "%s.%s@%s", SERVER_SERVICE, SERVER_INSTANCE, rlm->name);
    client->principal = make_string(rlmprinc, 0);
    client->last_send = 0;
    client->last_ack = NOW;
    client->subs = NULL;
    client->realm = rlm;
    client->addr.sin_family = 0;
    client->addr.sin_port = 0;
    client->addr.sin_addr.s_addr = 0;
    
    rlm->client = client;
    rlm->idx = random() % rlm->count;
    rlm->subs = NULL;
    rlm->tkt_try = 0;
    free(rlmnames[ii].servers);
    free(addresses);
  }
  free(rlmnames);
}

static Code_t
realm_ulocate_dispatch(notice, auth, who, server, realm)
    ZNotice_t *notice;
    int auth;
    struct sockaddr_in *who;
    Server *server;
    Realm *realm;
{
  register char *opcode = notice->z_opcode;
  Code_t status;
  
  if (!auth) {
    syslog(LOG_WARNING, "unauth locate msg from %s",
           inet_ntoa(who->sin_addr));
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
realm_control_dispatch(notice, auth, who, server, realm)
    ZNotice_t *notice;
    int auth;
    struct sockaddr_in *who;
    Server *server;
    Realm *realm;
{
  register char *opcode = notice->z_opcode;
  Code_t status;

  if (!auth) {
    syslog(LOG_WARNING, "unauth ctl msg from %s",
           inet_ntoa(who->sin_addr));
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
    if ((status = subscr_foreign_user(notice, who, realm)) != ZERR_NONE) {
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
  } else {
    syslog(LOG_WARNING, "%s unknown/illegal ctl opcode %s",
           realm->name, opcode);
    if (server == me_server)
      nack(notice, who);
    return(ZERR_NONE);
  }
  return(ZERR_NONE);
}

void
realm_handoff(notice, auth, who, realm, ack_to_sender)
    ZNotice_t *notice;
    int auth;
    struct sockaddr_in *who;
    Realm *realm;
    int ack_to_sender;
{
#ifdef HAVE_KRB4
  Code_t retval;

  if (!auth) {
    zdbug((LOG_DEBUG, "realm_sendit unauthentic to realm %s", realm->name)) 
    realm_sendit(notice, who, auth, realm, ack_to_sender);
  }
  
  if (!ticket_lookup(realm->name))
    if ((retval = ticket_retrieve(realm)) != ZERR_NONE) {
      syslog(LOG_WARNING, "rlm_handoff failed: %s", error_message(retval));
      return;
    }
  
  zdbug((LOG_DEBUG, "realm_sendit to realm %s auth %d", realm->name, auth)); 
  /* valid ticket available now, send the message */
  realm_sendit_auth(notice, who, auth, realm, ack_to_sender);
#else /* HAVE_KRB4 */
  realm_sendit(notice, who, auth, realm, ack_to_sender);
#endif /* HAVE_KRB4 */
}

static void
realm_sendit(notice, who, auth, realm, ack_to_sender)
    ZNotice_t *notice;
    struct sockaddr_in *who;
    int auth;
    Realm *realm;
    int ack_to_sender;
{
  caddr_t pack;
  int packlen;
  Code_t retval;
  Unacked *nacked;

  notice->z_auth = auth;
  
  /* format the notice */
  if ((retval = ZFormatRawNotice(notice, &pack, &packlen)) != ZERR_NONE) {
    syslog(LOG_WARNING, "rlm_sendit format: %s",
           error_message(retval));
    return;
  }
  
  /* now send */
  if ((retval = ZSetDestAddr(&realm->addrs[realm->idx])) != ZERR_NONE) {
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

  nacked->client = NULL;
  nacked->rexmits = 0;
  nacked->packet = pack;
  nacked->dest.rlm.rlm_idx = realm - otherrealms;
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
  LIST_INSERT(&rlm_nacklist, nacked);
  return;
}

static void
packet_ctl_nack(nackpacket)
    Unacked *nackpacket;
{
  ZNotice_t notice;

  /* extract the notice */
  ZParseNotice(nackpacket->packet, nackpacket->packsz, &notice);
  nack(&notice, &nackpacket->ack_addr);
}

static void
rlm_rexmit(arg)
    void *arg;
{
  Unacked *nackpacket = (Unacked *) arg;
  Code_t retval;
  register Realm *realm;
  int new_srv_idx;

        zdbug((LOG_DEBUG,"rlm_rexmit"));

  realm = &otherrealms[nackpacket->dest.rlm.rlm_idx];

  zdbug((LOG_DEBUG, "rlm_rexmit: sending to %s", realm->name));

  if (rexmit_times[(nackpacket->rexmits + 1)/(realm->count)] == -1) {
    /* give a server ack that the packet is lost/realm dead */
    packet_ctl_nack(nackpacket);
    LIST_DELETE(nackpacket);
    free(nackpacket->packet);
    free(nackpacket);

    zdbug((LOG_DEBUG, "rlm_rexmit: %s appears dead", realm->name));
    return;
  }

  /* retransmit the packet, trying each server in the realm multiple times */
#if 0
  new_srv_idx = ((nackpacket->rexmits / NUM_REXMIT_TIMES)
                 + nackpacket->rlm.rlm_srv_idx) % realm->count;
#else
  new_srv_idx = nackpacket->rexmits % realm->count;
#endif
  if (new_srv_idx != realm->idx)
    realm->idx = new_srv_idx;

  retval = ZSetDestAddr(&realm->addrs[realm->idx]);
  if (retval != ZERR_NONE) {
    syslog(LOG_WARNING, "rlm_rexmit set addr: %s", error_message(retval));
  } else {
    retval = ZSendPacket(nackpacket->packet, nackpacket->packsz, 0);
    if (retval != ZERR_NONE)
      syslog(LOG_WARNING, "rlm_rexmit xmit: %s", error_message(retval));
  }
  /* reset the timer */
  if (rexmit_times[(nackpacket->rexmits + 1)/(realm->count)] != -1)
    nackpacket->rexmits++;
  
  nackpacket->timer = timer_set_rel(rexmit_times[(nackpacket->rexmits)/(realm->count)], rlm_rexmit, nackpacket);
  return;
}

void
realm_dump_realms(fp)
    FILE *fp;
{
  register int ii, jj;
  
  for (ii = 0; ii < nrealms; ii++) {
    (void) fprintf(fp, "%d:%s\n", ii, otherrealms[ii].name);
    for (jj = 0; jj < otherrealms[ii].count; jj++) {
      (void) fprintf(fp, "\t%s\n",
                     inet_ntoa(otherrealms[ii].addrs[jj].sin_addr));
    }
    /* dump the subs */
    subscr_dump_subs(fp, otherrealms[ii].subs);
  }
}


#ifdef HAVE_KRB4
static void
realm_sendit_auth(notice, who, auth, realm, ack_to_sender)
    ZNotice_t *notice;
    int auth;
    struct sockaddr_in *who;
    Realm *realm;
    int ack_to_sender;
{
  char *buffer, *ptr;
  caddr_t pack;
  int buffer_len, hdrlen, offset, fragsize, ret_len, message_len;
  int origoffset, origlen;
  Code_t retval;
  Unacked *nacked;
  char buf[1024], multi[64];
  CREDENTIALS cred;
  KTEXT_ST authent;
  ZNotice_t partnotice, newnotice;

  offset = 0;

  /* first, build an authent */
  retval = krb_get_cred(SERVER_SERVICE, SERVER_INSTANCE, realm, &cred);
  if (retval != GC_OK) {
    syslog(LOG_WARNING, "rlm_sendit_auth get_cred: %s",
           error_message(retval+krb_err_base));
    return;
  }

  retval = krb_mk_req(&authent, SERVER_SERVICE, SERVER_INSTANCE, realm, 1);
  if (retval != MK_AP_OK) {
    syslog(LOG_WARNING, "rlm_sendit_auth mk_req: %s",
           error_message(retval+krb_err_base));
    return;
  }

  retval = ZMakeAscii(buf, sizeof(buf), authent.dat, authent.length);
  if (retval != ZERR_NONE) {
    syslog(LOG_WARNING, "rlm_sendit_auth mk_ascii: %s",
           error_message(retval));
    return;
  }

  /* set the dest addr */
  retval = ZSetDestAddr(&realm->addrs[realm->idx]);
  if (retval != ZERR_NONE) {
    syslog(LOG_WARNING, "rlm_sendit_auth set addr: %s", error_message(retval));
    return;
  }

  /* now format the notice, refragmenting if needed */
  newnotice = *notice;
  newnotice.z_auth = 1;
  newnotice.z_ascii_authent = buf;
  newnotice.z_authent_len = authent.length;

  buffer = (char *) malloc(sizeof(ZPacket_t));
  if (!buffer) {
    syslog(LOG_ERR, "realm_sendit_auth malloc");
    return;                 /* DON'T put on nack list */
  }

  buffer_len = sizeof(ZPacket_t);

  retval = Z_FormatRawHeader(&newnotice, buffer, buffer_len, &hdrlen, &ptr, 
                             NULL);
  if (retval != ZERR_NONE) {
    syslog(LOG_WARNING, "rlm_sendit_auth raw: %s", error_message(retval));
    free(buffer);
    return;
  }

#ifdef NOENCRYPTION
  newnotice.z_checksum = 0;
#else
  newnotice.z_checksum =
    (ZChecksum_t)des_quad_cksum(buffer, NULL, ptr - buffer, 0, cred.session);
#endif

  retval = Z_FormatRawHeader(&newnotice, buffer, buffer_len, &hdrlen, 
                             NULL, NULL);
  if (retval != ZERR_NONE) {
    syslog(LOG_WARNING, "rlm_sendit_auth raw: %s", error_message(retval));
    free(buffer);
    return;
  }
  
  /* This is not terribly pretty, but it does do its job. 
   * If a packet we get that needs to get sent off to another realm is
   * too big after we slap on our authent, we refragment it further,
   * a la Z_SendFragmentedNotice. This obliviates the need for what
   * used to be done in ZFormatAuthenticRealmNotice, as we do it here.
   * At some point it should be pulled back out into its own function,
   * but only the server uses it.
   */ 

  if ((newnotice.z_message_len+hdrlen > buffer_len) || 
      (newnotice.z_message_len+hdrlen > Z_MAXPKTLEN)){
    /* Deallocate buffer, use a local one */
    free(buffer);
    
    partnotice = *notice;

    partnotice.z_auth = 1;
    partnotice.z_ascii_authent = buf;
    partnotice.z_authent_len = authent.length;

    origoffset = 0;
    origlen = notice->z_message_len;

    if (notice->z_multinotice && strcmp(notice->z_multinotice, ""))
      if (sscanf(notice->z_multinotice, "%d/%d", &origoffset, &origlen) != 2) {
        syslog(LOG_WARNING, "rlm_sendit_auth frag: parse failed");
        return;
      }

#if 0
    zdbug((LOG_DEBUG,"rlm_send_auth: orig: %d-%d/%d", origoffset, notice->z_message_len, origlen));
#endif

    fragsize = Z_MAXPKTLEN-hdrlen-Z_FRAGFUDGE;

    while (offset < notice->z_message_len || !notice->z_message_len) {
      (void) sprintf(multi, "%d/%d", offset+origoffset, origlen);
      partnotice.z_multinotice = multi;
      if (offset > 0) {
        (void) gettimeofday(&partnotice.z_uid.tv, (struct timezone *)0);
        partnotice.z_uid.tv.tv_sec = htonl((u_long) 
                                           partnotice.z_uid.tv.tv_sec);
        partnotice.z_uid.tv.tv_usec = htonl((u_long) 
                                            partnotice.z_uid.tv.tv_usec);
        (void) memcpy((char *)&partnotice.z_uid.zuid_addr, &__My_addr, 
                      sizeof(__My_addr));
      }
      message_len = min(notice->z_message_len-offset, fragsize);
      partnotice.z_message = notice->z_message+offset;
      partnotice.z_message_len = message_len;

#if 0
      zdbug((LOG_DEBUG,"rlm_send_auth: new: %d-%d/%d", origoffset+offset, message_len, origlen));
#endif

      buffer = (char *) malloc(sizeof(ZPacket_t));
      if (!buffer) {
        syslog(LOG_ERR, "realm_sendit_auth malloc");
        return;                 /* DON'T put on nack list */
      }

      retval = Z_FormatRawHeader(&partnotice, buffer, buffer_len, &hdrlen, 
                                 &ptr, NULL);
      if (retval != ZERR_NONE) {
        syslog(LOG_WARNING, "rlm_sendit_auth raw: %s", error_message(retval));
        free(buffer);
        return;
      }

#ifdef NOENCRYPTION
      partnotice.z_checksum = 0;
#else
      partnotice.z_checksum =
        (ZChecksum_t)des_quad_cksum(buffer, NULL, ptr - buffer, 0, 
                                    cred.session);
#endif

      retval = Z_FormatRawHeader(&partnotice, buffer, buffer_len, &hdrlen, 
                                 NULL, NULL);
      if (retval != ZERR_NONE) {
        syslog(LOG_WARNING, "rlm_sendit_auth raw: %s", error_message(retval));
        free(buffer);
        return;
      }

      ptr = buffer+hdrlen;

      (void) memcpy(ptr, partnotice.z_message, partnotice.z_message_len);

      buffer_len = hdrlen+partnotice.z_message_len;

      /* now send */
      if ((retval = ZSendPacket(buffer, buffer_len, 0)) != ZERR_NONE) {
        syslog(LOG_WARNING, "rlm_sendit_auth xmit: %s", error_message(retval));
        free(buffer);
        return;
      }

      offset += fragsize;

      if (!(nacked = (Unacked *)malloc(sizeof(Unacked)))) {
        /* no space: just punt */
        syslog(LOG_ERR, "rlm_sendit_auth nack malloc");
        free(buffer);
        return;
      }

      nacked->rexmits = 0;
      nacked->packet = buffer;
      nacked->dest.rlm.rlm_idx = realm - otherrealms;
      nacked->dest.rlm.rlm_srv_idx = realm->idx;
      nacked->packsz = buffer_len;
      nacked->uid = partnotice.z_uid;

    /* Do the ack for the last frag, below */
      if (ack_to_sender)
        nacked->ack_addr = *who;
      else
        nacked->ack_addr.sin_addr.s_addr = 0;

      /* set a timer to retransmit */
      nacked->timer = timer_set_rel(rexmit_times[0], rlm_rexmit, nacked);

      /* chain in */
      LIST_INSERT(&rlm_nacklist, nacked);

      if (!notice->z_message_len)
        break;
    }
#if 0
    zdbug((LOG_DEBUG, "rlm_sendit_auth frag message sent"));
#endif
  } else {
    /* This is easy, no further fragmentation needed */
    ptr = buffer+hdrlen;

    (void) memcpy(ptr, newnotice.z_message, newnotice.z_message_len);

    buffer_len = hdrlen+newnotice.z_message_len;
    
    /* now send */
    if ((retval = ZSendPacket(buffer, buffer_len, 0)) != ZERR_NONE) {
      syslog(LOG_WARNING, "rlm_sendit_auth xmit: %s", error_message(retval));
      free(buffer);
      return;
    }

#if 0
    zdbug((LOG_DEBUG, "rlm_sendit_auth message sent"));
#endif
    /* now we've sent it, mark it as not ack'ed */
    
    if (!(nacked = (Unacked *)malloc(sizeof(Unacked)))) {
      /* no space: just punt */
      syslog(LOG_ERR, "rlm_sendit_auth nack malloc");
      free(buffer);
      return;
    }

    nacked->rexmits = 0;
    nacked->packet = buffer;
    nacked->dest.rlm.rlm_idx = realm - otherrealms;
    nacked->dest.rlm.rlm_srv_idx = realm->idx;
    nacked->packsz = buffer_len;
    nacked->uid = notice->z_uid;

    /* Do the ack for the last frag, below */
    if (ack_to_sender)
      nacked->ack_addr = *who;
    else
      nacked->ack_addr.sin_addr.s_addr = 0;
    
    /* set a timer to retransmit */
    nacked->timer = timer_set_rel(rexmit_times[0], rlm_rexmit, nacked);
    /* chain in */
    LIST_INSERT(&rlm_nacklist, nacked);
  }
#if 0
  if (ack_to_sender)
    nacked->ack_addr = *who;
#endif
  return;
}

int
ticket_expired(cred)
CREDENTIALS *cred;
{
        /* extra 15 minutes for safety margin */
#ifdef AFS_LIFETIMES
        return (krb_life_to_time(cred->issue_date, cred->lifetime) < NOW + 15*60);
#else /* AFS_LIFETIMES */
        return (cred->issue_date + cred->lifetime*5*60 < NOW + 15*60);
#endif /* AFS_LIFETIMES */
}

int
ticket_lookup(realm)
char *realm;
{
  CREDENTIALS cred;
  KTEXT_ST authent;
  int retval;

  retval = krb_get_cred(SERVER_SERVICE, SERVER_INSTANCE, realm, &cred);
  if (retval == GC_OK && !ticket_expired(&cred))
    /* good ticket */
    return(1);

  if (!strcmp(realm, ZGetRealm())) {
    get_tgt();
    
    /* For Putrify */
    memset(&authent.dat,0,MAX_KTXT_LEN);
    authent.mbz=0;

    /* this is local, so try to contact the Kerberos server */
    retval = krb_mk_req(&authent, SERVER_SERVICE, SERVER_INSTANCE,
                        realm, 0);
    if (retval != KSUCCESS) {
      syslog(LOG_ERR, "tkt_lookup: local: %s",
             krb_err_txt[retval]);
      return(0);
    } else {
      return(1);
    }
  }
  
  return (0);
}

static Code_t
ticket_retrieve(realm)
    Realm *realm;
{
  int pid, retval;
  KTEXT_ST authent;
  
  get_tgt();

  /* For Putrify */
  memset(&authent.dat,0,MAX_KTXT_LEN);
  authent.mbz=0;

  /* Don't lose by trying too often. */
  if (NOW - realm->tkt_try > 5 * 60) {
    retval = krb_mk_req(&authent, SERVER_SERVICE, SERVER_INSTANCE,
			realm->name, 0);
    realm->tkt_try = NOW;
    if (retval != KSUCCESS) {
      syslog(LOG_WARNING, "tkt_rtrv: %s: %s", realm,
	     krb_err_txt[retval]);
      return (retval+krb_err_base);
    }
    return (0);
  } else {
    return (1);
  }
}
#endif /* HAVE_KRB4 */

