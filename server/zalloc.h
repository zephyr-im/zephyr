/*
 */

#ifndef __zalloc_h
#define __zalloc_h __FILE__
#ifdef MPROF
#define zalloc(sz) malloc(sz)
#define zfree(p,sz) free(p)
#else

#ifdef __STDC__
# define        P(s) s
#else
# define P(s) ()
#endif /* STDC */

extern void * zalloc P((unsigned int));
extern void zfree P((void *, unsigned int));

#undef P
#endif /* MPROF */
#endif /* __zalloc_h */
