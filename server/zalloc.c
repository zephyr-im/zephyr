/*
 * Memory allocator for Zephyr server.
 */

#include <stdio.h>
#include "zalloc.h"

#ifndef MPROF
/*
 * What's the maximum number of words to expect to allocate through
 * this mechanism?  (Larger requests will be fed to malloc.)
 */
const int max_size = 32;

static void *free_space;
static int free_space_size;
static void *buckets[max_size];
#ifdef ZALLOC_STATS
enum zalloc_memtype {
    FREE=0, ALLOCATED,
    N_zalloc_memtype
};
static int count[max_size][(int) N_zalloc_memtype];
#endif

struct dummy {
    int a;
    virtual int i() { return a; }
};

union misc_types {		/* used only for its size */
    void *void_p;
    int i;
    long l;
    double d;
    int (dummy::* member_p) ();
    /* Can't just use a `dummy' object, because it has an invisible
       constructor.  */
    char cc[sizeof (dummy)];
};

const unsigned int sz = sizeof (misc_types);

/*
 * Pick some size here that will help keep down the number of calls to
 * malloc, but doesn't waste too much space.  To avoid waste of space,
 * we leave some overhead before the next power of two.
 */
const int alloc_size = ((16384 - 32) / sz) * sz;

inline unsigned int round (unsigned int size) {
    size += sz - 1;
    size -= (size % sz);
    return size;
}
#define ROUND(size)	(size = round (size))
inline int BUCKET (unsigned int size) {
    ROUND (size);
    return size / sz - 1;
}

extern "C" {
    void * malloc (unsigned int);
    void free (void *);
    void abort ();
    void bzero (void *, unsigned int);
}

static inline void memset (void *ptr, int size, int fill) {
#ifdef ZALLOC_DEBUG
    char *cptr = (char *) ptr;
    while (size--)
	cptr[size] = fill;
#endif
}

void *zalloc (unsigned int size) {
    ROUND (size);

    int bucket = BUCKET (size);
    if (bucket < 0 || bucket >= max_size)
	return malloc (size);

    void *ret;
    void **ptr = &buckets[bucket];
#ifdef ZALLOC_DEBUG_PRINT
    fprintf (stderr, "zalloc(%d); looking in bucket %d, found %08X\n",
	     size, bucket, *ptr);
#endif
    if (*ptr) {
	ret = *ptr;
	*ptr = *(void**)ret;
	goto return_it;
    }

    if (free_space_size < size) {
	if (free_space_size > 0) {
	    ptr = &buckets[BUCKET (free_space_size)];
	    *(void**)free_space = *ptr;
	    *ptr = free_space;
#ifdef ZALLOC_DEBUG_PRINT
	    fprintf (stderr, "tossing %08X into bucket %d\n",
		     free_space, bucket);
#endif
#ifdef ZALLOC_STATS
	    count[BUCKET (free_space_size)][FREE]++;
#endif
	}

	free_space_size = alloc_size;
	free_space = malloc (free_space_size);
	if (!free_space)
	    abort ();
#ifdef ZALLOC_DEBUG_PRINT
	fprintf (stderr, "grabbing more free store at %08X\n", free_space);
#endif
    }

    ret = free_space;
    free_space = (char *) free_space + size;
    free_space_size -= size;
return_it:
#ifdef ZALLOC_DEBUG_PRINT
    fprintf (stderr, "returning %08X\n", ret);
#endif
    memset (ret, size, 0xe5);
#ifdef ZALLOC_STATS
    count[bucket][FREE]--, count[bucket][ALLOCATED]++;
#endif
    return ret;
}

void zfree (void *ptr, unsigned int size) {
    ROUND (size);

    int bucket = BUCKET (size);
    if (bucket < 0 || bucket >= max_size) {
	free (ptr);
	return;
    }

    void **b = &buckets[bucket];
    memset (ptr, size, 0xe5);
    *(void **) ptr = *b;
    *b = ptr;
#ifdef ZALLOC_DEBUG
#ifdef ZALLOC_DEBUG_PRINT
    fprintf (stderr, "putting %08X into bucket %d\n",
	     ptr, bucket);
    fprintf (stderr, "bucket %d:");
    for (ptr = buckets[bucket]; ptr; ptr=*(void**)ptr)
	fprintf (stderr, " %X", ptr);
    fprintf (stderr, "\n");
#else
    for (ptr = buckets[bucket]; ptr; ptr=*(void**)ptr)
	/* do nothing, just read value */;
#endif
#endif

#ifdef ZALLOC_STATS
    count[bucket][FREE]++, count[bucket][ALLOCATED]--;
#endif
}
#endif
