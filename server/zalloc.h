/*
 */

#ifdef MPROF
inline void * zalloc (unsigned int sz) {
    return malloc (sz);
}
inline void zfree (void *ptr, unsigned int sz) {
    free (ptr);
}
#else
extern void * zalloc (unsigned int);
extern void zfree (void *, unsigned int);
#endif
