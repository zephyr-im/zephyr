/* XXX this file is duplicated in clients/zctl and clients/zwgc, until
   zctl is changed to message zwgc to perform these tasks */

#include <stdio.h>
#include <string.h>
#include <netdb.h>
#include <errno.h>

#include <sys/param.h>

#include <zephyr/zephyr.h>
#include <krb_err.h>

#include "zutils.h"

#ifdef ZWGC
#include "subscriptions.h"
#define ZGetWGPort() (ZGetPort())
#endif

#ifdef ZCTL
Code_t send_wgc_control(opcode, msg, len)
     char *opcode;
     char *msg;
     int len;
{
	int retval;
	short newport;
	struct sockaddr_in oldsin, newsin;
	ZNotice_t notice;

	oldsin = ZGetDestAddr();

	if ((newport = ZGetWGPort()) == -1) {
		return(errno);
	}

	newsin = oldsin;
	newsin.sin_port = (u_short) newport;
	if ((retval = ZSetDestAddr(&newsin)) != ZERR_NONE) {
		return(retval);
	}

	(void) memset((char *)&notice, 0, sizeof(notice));
	notice.z_kind = UNSAFE;
	notice.z_port = 0;
	notice.z_class = WG_CTL_CLASS;
	notice.z_class_inst = WG_CTL_USER;
	notice.z_opcode = opcode;
	notice.z_sender = 0;
	notice.z_recipient = "";
	notice.z_default_format = "";
	notice.z_dest_galaxy = "";
	notice.z_message = msg;
	notice.z_message_len = len;

	if ((retval = ZSendNotice(&notice,ZNOAUTH)) != ZERR_NONE)
		return(retval);

	if ((retval = ZSetDestAddr(&oldsin)) != ZERR_NONE) {
		return(retval);
	}

#if 0
	/* XXX why was this here? */
	if ((retval = ZInitialize()) != ZERR_NONE)
		return(retval);
#endif
} 
#endif

void fix_macros(subs,subs2,num)
	ZSubscription_t *subs,*subs2;
	int num;
{
	int i;

	for (i=0;i<num;i++) {
		subs2[i] = subs[i];
		fix_macros2(subs[i].zsub_class,&subs2[i].zsub_class);
		fix_macros2(subs[i].zsub_classinst,&subs2[i].zsub_classinst);
		fix_macros2(subs[i].zsub_recipient,&subs2[i].zsub_recipient);
	}
}

void fix_macros2(src,dest)
	char *src;
	char **dest;
{
    static char ourhost[MAXHOSTNAMELEN],ourhostcanon[MAXHOSTNAMELEN];
    struct hostent *hent;

    if (!*ourhost) {
#ifdef HAVE_SYS_UTSNAME
	uname(&name);
	strcpy(ourhost, name.nodename);
#else
	if (gethostname(ourhost,MAXHOSTNAMELEN) == -1) {
	    /* XXX */
	    com_err("",errno,"while getting host name");
	    return;
	}
#endif
    }

    if (!*ourhostcanon) {
	if (!(hent = gethostbyname(ourhost))) {
	    fprintf(stderr,"Can't get canonical name for host %s",
		    ourhost);
	    return;
	}

	(void) strcpy(ourhostcanon,hent->h_name);
    }

    if (!strcmp(src,TOKEN_HOSTNAME)) {
	*dest = ourhost;
    } else if (!strcmp(src,TOKEN_CANONNAME)) {
	*dest = ourhostcanon;
    } else if (!strcmp(src,TOKEN_ME)) {
	*dest = ZGetSender();
    }
}

Code_t set_exposure(galaxy, exposure)
     char *galaxy;
     char *exposure;
{
    char *exp_level, *galaxy_exp_level, zvar[1024];
    Code_t code, retval;
    int cnt, i;

    exp_level = ZParseExposureLevel(exposure);

    if (galaxy && strcmp(galaxy, "*") == 0) {
	if (retval = ZGetGalaxyCount(&cnt))
		return(retval);

	for (i=0; i<cnt; i++) {
	    if (retval = ZGetGalaxyName(i, &galaxy))
		return(retval);

	    sprintf(zvar, "exposure-%s", galaxy);
				
	    if (galaxy_exp_level = ZGetVariable(zvar)) {
		if (strcmp(galaxy_exp_level, EXPOSE_NETVIS) == 0)
		    galaxy_exp_level = EXPOSE_REALMVIS;
		else
		    galaxy_exp_level = ZParseExposureLevel(galaxy_exp_level);
	    } else if (galaxy_exp_level = exp_level) {
		if (strcmp(galaxy_exp_level, EXPOSE_NETVIS) == 0)
		    galaxy_exp_level = EXPOSE_REALMVIS;

		if (i > 0) {
		    if (strcmp(galaxy_exp_level, EXPOSE_REALMVIS) == 0)
			galaxy_exp_level = EXPOSE_OPSTAFF;
		    else if (strcmp(galaxy_exp_level, EXPOSE_REALMANN) == 0)
			galaxy_exp_level = EXPOSE_OPSTAFF;
		} else {
		    galaxy_exp_level = ZParseExposureLevel(galaxy_exp_level);
		}
	    } else {
		galaxy_exp_level = EXPOSE_NONE;
	    }
		
	    if (strcmp(galaxy_exp_level, EXPOSE_NONE) == 0)
		continue;

	    if ((code = ZSetLocation(galaxy, exp_level)) != ZERR_NONE) {
	       retval = code;
	       continue;
	    }
#ifdef ZCTL
	    if (strcmp(exp_level,EXPOSE_NONE) == 0) {
		if (code = send_wgc_control(USER_SHUTDOWN, NULL, 0)) {
		    retval = code;
		    continue;
		}
	    } else {
		if (code = send_wgc_control(USER_STARTUP, NULL, 0)) {
		    retval = code;
		    continue;
		}
	    }
#endif
	}
	return((retval == KRBET_AD_NOTGT)?ZERR_NONE:retval);
    } else {
	if ((retval = ZSetLocation(galaxy, exp_level)) != ZERR_NONE)
	    return(retval);
#ifdef ZCTL
	if (strcmp(exp_level,EXPOSE_NONE) == 0) {
	    if (retval = send_wgc_control(USER_SHUTDOWN, NULL, 0))
		return(retval);
	} else {
	    if (retval = send_wgc_control(USER_STARTUP, NULL, 0))
		return(retval);
	}
#endif
    }
}
		
#ifdef ZCTL
Code_t xpunt(zclass, zinst, zrecip, type)
     char *zclass;
     char *zinst;
     char *zrecip;
     int type;
{
    char *msg;

    msg = (char *) malloc(strlen(zclass) + strlen(zinst) + strlen(zrecip) + 3);

    sprintf(msg, "%s%c%s%c%s", zclass, '\0', zinst, '\0', zrecip);

    return(send_wgc_control((type == PUNT)?"SUPPRESS":"UNSUPPRESS",
			    msg, 
			    strlen(zclass) + strlen(zinst) +
			    strlen(zrecip) + 3));
}

#elif defined(ZWGC)

Code_t xpunt(zclass, zinst, zrecip, type)
     char *zclass;
     char *zinst;
     char *zrecip;
     int type;
{
    if (type == PUNT)
	punt(zclass, zinst, zrecip);
    else
	unpunt(zclass, zinst, zrecip);

    return(ZERR_NONE);
}

#endif

Code_t load_sub_file(type, file, galaxy)
	int type;
	char *file;
	char *galaxy;
{
    ZSubscription_t subs[SUBSATONCE],subs2[SUBSATONCE],unsubs[SUBSATONCE],
	punts[1];
    FILE *fp;
    int ind,unind,puntind,lineno,i,retval;
    short wgport;
    char *comma,*comma2,subline[BUFSIZ];

    if (type != LIST) 
	if ((wgport = ZGetWGPort()) == -1) {
	    return(errno);
	} 

    if (file) {
	fp = fopen(file,"r");

	if ((fp == NULL) && (errno != ENOENT))
	    return(errno);
    } else {
	fp = NULL;
    }
	
    ind = unind = puntind = 0;
    lineno = 1;
	
    /* this will fall through to subbing an empty list, giving the default
       subs only */

    if (fp) {
	for (;;lineno++) {
	    if (!fgets(subline,sizeof subline,fp))
		break;
	    if (*subline == '#' || !*subline)
		continue;
	    subline[strlen(subline)-1] = '\0'; /* nuke newline */
	    comma = strchr(subline,',');
	    if (comma)
		comma2 = strchr(comma+1,',');
	    else
		comma2 = 0;
	    if (!comma || !comma2) {
		fprintf(stderr,
			"Malformed subscription at line %d of %s:\n%s\n",
			lineno,file,subline);
		continue;
	    }
	    *comma = '\0';
	    *comma2 = '\0';
	    if (type == LIST) {
		if (*subline == '!') 
		    printf("(Un-subscription) Class %s instance %s recipient %s\n",
			   subline+1, comma+1, comma2+1);
		else if (*subline = '-')
		    printf("(Suppression) Class %s instance %s recipient %s\n",
			   subline+1, comma+1, comma2+1);
		else
		    printf("Class %s instance %s recipient %s\n",
			   subline, comma+1, comma2+1);
		continue;
	    }
	    if (*subline == '!') {	/* an un-subscription */
		/* if we are explicitly un-subscribing to
		   the contents of a subscription file, ignore
		   any un-subscriptions in that file */
		if (type == UNSUB)
		    continue;
		unsubs[unind].zsub_class =
		    (char *)malloc((unsigned)(strlen(subline)));
		/* XXX check malloc return */
		/* skip the leading '!' */
		(void) strcpy(unsubs[unind].zsub_class,subline+1);
		unsubs[unind].zsub_classinst =
		    (char *)malloc((unsigned)(strlen(comma+1)+1));
		/* XXX check malloc return */
		(void) strcpy(unsubs[unind].zsub_classinst,comma+1);
		unsubs[unind].zsub_recipient =
		    (char *)malloc((unsigned)(strlen(comma2+1)+1));
		/* XXX check malloc return */
		(void) strcpy(unsubs[unind].zsub_recipient,comma2+1);
		unind++;
	    } else if (*subline == '-') {	/* an suppression */
		punts[puntind].zsub_class =
		    (char *)malloc((unsigned)(strlen(subline)));
		/* XXX check malloc return */
		/* skip the leading '-' */
		(void) strcpy(punts[puntind].zsub_class,subline+1);
		punts[puntind].zsub_classinst =
		    (char *)malloc((unsigned)(strlen(comma+1)+1));
		/* XXX check malloc return */
		(void) strcpy(punts[puntind].zsub_classinst,comma+1);
		punts[puntind].zsub_recipient =
		    (char *)malloc((unsigned)(strlen(comma2+1)+1));
		/* XXX check malloc return */
		(void) strcpy(punts[puntind].zsub_recipient,comma2+1);
		puntind++;
	    } else {
		subs[ind].zsub_class =
		    (char *)malloc((unsigned)(strlen(subline)+1));
		/* XXX check malloc return */
		(void) strcpy(subs[ind].zsub_class,subline);
		subs[ind].zsub_classinst =
		    (char *)malloc((unsigned)(strlen(comma+1)+1));
		/* XXX check malloc return */
		(void) strcpy(subs[ind].zsub_classinst,comma+1);
		subs[ind].zsub_recipient =
		    (char *)malloc((unsigned)(strlen(comma2+1)+1));
		/* XXX check malloc return */
		(void) strcpy(subs[ind].zsub_recipient,comma2+1);
		ind++;
	    }
	    if (ind == SUBSATONCE) {
		fix_macros(subs,subs2,ind);
		if ((retval = (type == SUB)?
		     ZSubscribeTo(galaxy, subs2,ind,(u_short)wgport):
		     ZUnsubscribeTo(galaxy, subs2,ind,(u_short)wgport)) !=
		    ZERR_NONE) {
		    goto cleanup;
		}
		for (i=0;i<ind;i++) {
		    free(subs[i].zsub_class);
		    free(subs[i].zsub_classinst);
		    free(subs[i].zsub_recipient);
		} 
		ind = 0;
	    }
	    if (unind == SUBSATONCE) {
		fix_macros(unsubs,subs2,unind);
		if ((retval = ZUnsubscribeTo(galaxy, subs2,unind,(u_short)wgport)) != ZERR_NONE) {
		    goto cleanup;
		}
		for (i=0;i<unind;i++) {
		    free(unsubs[i].zsub_class);
		    free(unsubs[i].zsub_classinst);
		    free(unsubs[i].zsub_recipient);
		} 
		unind = 0;
	    }
	    if (puntind) {
		fix_macros(punts,subs2,puntind);

		if (retval = xpunt(punts[0].zsub_class,
				   punts[0].zsub_classinst,
				   punts[0].zsub_recipient,
				   (type == SUB)?PUNT:UNPUNT))
			goto cleanup;

		free(punts[0].zsub_class);
		free(punts[0].zsub_classinst);
		free(punts[0].zsub_recipient);

		puntind = 0;
	    }
	}
    }

    if (type != LIST) {
	/* even if we have no subscriptions, be sure to send
	   an empty packet to trigger the default subscriptions */
	fix_macros(subs,subs2,ind);
	if ((retval = (type == SUB)?ZSubscribeTo(galaxy, subs2,ind,(u_short)wgport):
	     ZUnsubscribeTo(galaxy, subs2,ind,(u_short)wgport)) != ZERR_NONE) {
	    goto cleanup;
	}
	if (unind) {
	    fix_macros(unsubs,subs2,unind);
	    if ((retval =
		 ZUnsubscribeTo(galaxy, subs2,unind,(u_short)wgport)) != ZERR_NONE) {
		goto cleanup;
	    }
	}
    }

    retval = 0;

cleanup:
    for (i=0;i<ind;i++) {
	free(subs[i].zsub_class);
	free(subs[i].zsub_classinst);
	free(subs[i].zsub_recipient);
    } 
    for (i=0;i<unind;i++) {
	free(unsubs[i].zsub_class);
	free(unsubs[i].zsub_classinst);
	free(unsubs[i].zsub_recipient);
    } 
    for (i=0;i<puntind;i++) {
	free(unsubs[i].zsub_class);
	free(unsubs[i].zsub_classinst);
	free(unsubs[i].zsub_recipient);
    } 

    if (fp)
	(void) fclose(fp);	/* ignore errs--file is read-only */
    return(retval);
}

Code_t load_all_sub_files(type, basefile)
	int type;
	char *basefile;
{
    Code_t retval, code;
    int i, cnt;
    char *galaxy, *exp;
    char fn[MAXPATHLEN];

    if (retval = ZGetGalaxyCount(&cnt))
	return(retval);

    for (i=0; i<cnt; i++) {
	if (retval = ZGetGalaxyName(i, &galaxy))
	    return(retval);

	strcpy(fn, "exposure-");
	strcat(fn, galaxy);

	if ((((exp = ZGetVariable(fn)) == NULL) &&
	     ((exp = ZGetVariable("exposure")) == NULL)) ||
	    (strcasecmp(exp, EXPOSE_NONE) == 0))
	    /* skip this galaxy */
	    continue;

	if (basefile) {
	    strcpy(fn, basefile);
	    strcat(fn, "-");
	    strcat(fn, galaxy);
	}

	if (type == LIST)
	    printf("For galaxy %s:\n", galaxy);

	if ((i == 0) && basefile) {
	    code = load_sub_file(type, basefile, galaxy);
	    if ((code != ZERR_NONE) &&
		(code != ENOENT))
		retval = code;
	}

	code = load_sub_file(type, basefile?fn:NULL, galaxy);
	if ((code != ZERR_NONE) &&
	    (code != ENOENT))
	    retval = code;

	if (type == LIST)
		printf("\n");
    }
    return((retval == KRBET_AD_NOTGT)?ZERR_NONE:retval);
}
