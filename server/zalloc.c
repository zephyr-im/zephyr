/*
 * Memory allocator for Zephyr server.
 */

#include <stdio.h>
#include <zephyr/zephyr.h>
#include "unix.h"
#include "zalloc.h"

#ifndef MPROF
/*
 * What's the maximum number of words to expect to allocate through
 * this mechanism?  (Larger requests will be fed to malloc.)
 */
#define MAX_SIZE 32

static void *free_space;
static unsigned int free_space_size;
static void *buckets[MAX_SIZE];
#ifdef ZALLOC_STATS
enum zalloc_memtype {
    FREE=0, ALLOCATED,
    N_zalloc_memtype
};
static int zalloc_count[MAX_SIZE][(int) N_zalloc_memtype];
#endif

/* 
  union misc_types {
    void *void_p;
    int i;
    long l;
    double d;
  };
*/
/* SZ = sizeof(misc_types) */
#define SZ 32

/*
 * Pick some size here that will help keep down the number of calls to
 * malloc, but doesn't waste too much space.  To avoid waste of space,
 * we leave some overhead before the next power of two.
 */


/* ALLOC_SIZE = ((16384 - 32) / SZ) * SZ      */
#define ALLOC_SIZE 16352

unsigned int round (size)
     unsigned int size;
{
    size += SZ - 1;
    size -= (size % SZ);
    return size;
}

#define ROUND(size)	(size = round (size))
int BUCKET (size)
     unsigned int size;
{
    ROUND (size);
    return size / SZ - 1;
}

static void
zmemset (ptr, size, fill)
     void *ptr;
     int size;
     int fill;
{
#ifdef ZALLOC_DEBUG
    char *cptr = (char *) ptr;
    while (size--)
	cptr[size] = fill;
#endif
}

void *
zalloc (size)
     unsigned int size;
{
    int bucket;
    void *ret;
    void **ptr;

    ROUND (size);
    bucket = BUCKET (size);
    if (bucket < 0 || bucket >= MAX_SIZE)
	return (void *) malloc (size);

    ptr = &buckets[bucket];
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
	    zalloc_count[BUCKET (free_space_size)][FREE]++;
#endif
	}

	free_space_size = ALLOC_SIZE;
	free_space = (void *) malloc (free_space_size);
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
    zmemset (ret, size, 0xe5);
#ifdef ZALLOC_STATS
    zalloc_count[bucket][FREE]--, zalloc_count[bucket][ALLOCATED]++;
#endif
    return ret;
}

void zfree (ptr, size)
     void *ptr;
     unsigned int size;
{
    int bucket;
    void **b;

    ROUND (size);
    bucket = BUCKET (size);
    if (bucket < 0 || bucket >= MAX_SIZE) {
	free (ptr);
	return;
    }

    b = &buckets[bucket];
    zmemset (ptr, size, 0xe5);
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
    zalloc_count[bucket][FREE]++, zalloc_count[bucket][ALLOCATED]--;
#endif
}
#endif
