#ifndef pointer_MODULE
#define pointer_MODULE

#if defined(mips) && defined(ultrix)
typedef char *pointer;
#else
typedef void *pointer;
#endif

#endif
