/* This file is part of the Project Athena Zephyr Notification System.
 * It contains source for the session dump and restore function.
 *
 *	Created by:	David Benjamin
 *
 *	$Id$
 *
 *	Copyright (c) 2013 by the Massachusetts Institute of Technology.
 *	For copying and distribution information, see the file
 *	"mit-copyright.h".
 */

#ifndef lint
static const char rcsid_ZDumpSession_c[] = "$Id$";
#endif

#include <internal.h>

#define SESSION_VERSION 1

Code_t
ZDumpSession(char **buffer,
             int *ret_len)
{
#ifdef HAVE_KRB5
    struct _Z_SessionKey *key;
    uint32_t num_keys = 0;
#endif
    char *ptr;
    int len;

    /*
     * We serialize the port number and all keys. All numbers are
     * stored in big-endian. Byte strings are prefixed with a 32-bit
     * length. First field is 16-bit version number. Keys are stored
     * in reverse.
     */

    len = 2 + 2;  /* version, port number */
#ifdef HAVE_KRB5
    len += 4;  /* num_keys */
    for (key = Z_keys_head; key != NULL; key = key->next) {
	num_keys++;
	len += 4 + 4;  /* enctype, length */
	len += Z_keylen(key->keyblock);  /* contents */
    }
#endif

    *ret_len = len;
    if (!(*buffer = (char *) malloc((unsigned)*ret_len)))
	return (ENOMEM);

    ptr = *buffer;
    *((uint16_t*) ptr) = htons(SESSION_VERSION); ptr += 2;
    *((uint16_t*) ptr) = htons(__Zephyr_port); ptr += 2;
#ifdef HAVE_KRB5
    *((uint32_t *)ptr) = htonl(num_keys); ptr += 4;
    for (key = Z_keys_tail; key != NULL; key = key->prev) {
	*((uint32_t*) ptr) = htonl(Z_enctype(key->keyblock)); ptr += 4;
	*((uint32_t*) ptr) = htonl(Z_keylen(key->keyblock)); ptr += 4;
	memcpy(ptr, Z_keydata(key->keyblock), Z_keylen(key->keyblock));
	ptr += Z_keylen(key->keyblock);
    }
#endif

    return (ZERR_NONE);
}

Code_t
ZLoadSession(char *buffer, int len)
{
#ifdef HAVE_KRB5
    struct _Z_SessionKey *key;
    uint32_t num_keys, keylength;
    krb5_enctype enctype;
    int i;
#endif
    Code_t ret;
    uint16_t version, port;

    if (len < 2) return (EINVAL);
    version = ntohs(*((uint16_t *) buffer)); buffer += 2; len -= 2;
    if (version != SESSION_VERSION)
	return (EINVAL);

    if (len < 2) return (EINVAL);
    port = ntohs(*((uint16_t *) buffer)); buffer += 2; len -= 2;
    if ((ret = ZOpenPort(&port)) != ZERR_NONE)
	return ret;

#ifdef HAVE_KRB5
    if (len < 4) return (EINVAL);
    num_keys = ntohl(*((uint32_t *) buffer)); buffer += 4; len -= 4;

    for (i = 0; i < num_keys; i++) {
	key = (struct _Z_SessionKey *)malloc(sizeof(struct _Z_SessionKey));
	if (!key)
	    return (ENOMEM);
	if (len < 4) {
	    free(key);
	    return (EINVAL);
	}
	enctype = ntohl(*((uint32_t *) buffer)); buffer += 4; len -= 4;
	if (len < 4) {
	    free(key);
	    return (EINVAL);
	}
	keylength = ntohl(*((uint32_t *) buffer)); buffer += 4; len -= 4;
	if (len < keylength) {
	    free(key);
	    return (EINVAL);
	}
	ret = Z_krb5_init_keyblock(Z_krb5_ctx, enctype, keylength, &key->keyblock);
	if (ret) {
	    free(key);
	    return ret;
	}
	memcpy((char *)Z_keydata(key->keyblock), buffer, keylength);
	buffer += keylength; len -= keylength;
	/* Just set recent times. It means we might not be able to
	   retire the keys, but that's fine. */
	key->send_time = time(NULL);
	key->first_use = time(NULL);
	/* Prepend to the key list. */
	key->prev = NULL;
	key->next = Z_keys_head;
	if (Z_keys_head)
	    Z_keys_head->prev = key;
	Z_keys_head = key;
	if (!Z_keys_tail)
	    Z_keys_tail = key;
    }
#endif

    if (len)
	return (EINVAL);
    return (ZERR_NONE);
}
