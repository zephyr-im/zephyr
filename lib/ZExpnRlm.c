#include <internal.h>
#include <sys/param.h>
#include <ctype.h>

char *
ZExpandRealm(char *realm)
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
#endif
}
