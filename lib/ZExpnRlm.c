#include <internal.h>
#include <sys/param.h>
#include <ctype.h>

char *
ZExpandRealm(realm)
char *realm;
{
        char *cp1, *cp2;
        static char expand[REALM_SZ];
#ifdef  HAVE_KRB5
	krb5_error_code result;
	char **list_realms;
	result = krb5_get_host_realm(Z_krb5_ctx, realm, &list_realms);
	if (result) {
		/* Error, just return upper-cased realm */
		cp2 = realm;
       		cp1 = expand;
        	while (*cp2) {
                	*cp1++ = toupper(*cp2++);
        	}
        	*cp1 = '\0';
		return expand;
	}
	strncpy(expand, list_realms[0], sizeof(expand));
	expand[sizeof(expand)-1] = '\0';
	result = krb5_free_host_realm(Z_krb5_ctx, list_realms);
	return expand;
#else
#ifndef HAVE_KRB4
        struct hostent *he;

        he = gethostbyname(realm);

        if (!he || !he->h_name)
                /* just use the raw realm */
                cp2 = realm;
        else
                cp2 = he->h_name;

        cp1 = expand;
        while (*cp2) {
                *cp1++ = toupper(*cp2++);
        }
        *cp1 = '\0';

        return(expand);
#else
	int retval;
	FILE *rlm_file;
	char krb_host[MAXHOSTNAMELEN+1];
        static char krb_realm[REALM_SZ+1];
	char linebuf[BUFSIZ];
	char scratch[64];

/* upcase what we got */
	cp2 = realm;
        cp1 = expand;
        while (*cp2) {
                *cp1++ = toupper(*cp2++);
        }
        *cp1 = '\0';

	if ((rlm_file = fopen("/etc/krb.conf", "r")) == (FILE *) 0) {
                return(expand);
        }
	
	if (fgets(linebuf, BUFSIZ, rlm_file) == NULL) {
	  /* error reading */
	  (void) fclose(rlm_file);
	  return(expand);
	}

	if (sscanf(linebuf, "%s", krb_realm) < 1) {
	  /* error reading */
	  (void) fclose(rlm_file);
	  return(expand);
	}

	if (!strncmp(krb_realm, expand, strlen(expand))) {
	  (void) fclose(rlm_file);
	  return(krb_realm);
	}

	while (1) {
	  /* run through the file, looking for admin host */
	  if (fgets(linebuf, BUFSIZ, rlm_file) == NULL) {
            (void) fclose(rlm_file);
            return(expand);
	  }

	  if (sscanf(linebuf, "%s %s admin %s", krb_realm, krb_host, scratch)
	      < 2)
            continue;
	  if (!strncmp(krb_realm, expand, strlen(expand))) {
	    (void) fclose(rlm_file);
	    return(krb_realm);
	  }
	}
#endif /* HAVE_KRB4 */
#endif
}
