/* Coypright 1987, Massachusetts Institute of Technology */
/*
 *	$Source$
 *	$Header$
 */

/* definitions for the Zephyr server */

typedef struct _ZClientDesc_t {
    struct _ZClientDesc_t *q_forw;
    struct _ZClientDesc_t *q_back;
} ZClientDesc_t;

typedef struct _ZEntity_t {
    char *filler;			/* fill this in later */
} ZEntity_t;

/* Function declarations */

extern char *strsave();

/* server internal error codes */
#define	ZERR_S_FIRST	2000
#define ZERR_S_BADASSOC	2000		/* client not associated with class */
