/* This file is part of the Project Athena Zephyr Notification System.
 * It is one of the source files comprising zwgc, the Zephyr WindowGram
 * client.
 *
 *      Created by:     Marc Horowitz <marc@athena.mit.edu>
 *
 *      $Source$
 *      $Author$
 *	$Id$
 *
 *      Copyright (c) 1989 by the Massachusetts Institute of Technology.
 *      For copying and distribution information, see the file
 *      "mit-copyright.h".
 */

/* This entire module goes out the window in saber */
#if !defined(SABER) && (defined(DEBUG) || defined(DEBUG_MEMORY))

#ifndef memory_MODULE
#define memory_MODULE

extern char *memory__malloc();           /* PRIVATE */
extern char *memory__realloc();          /* PRIVATE */
extern char *memory__calloc();           /* PRIVATE */
extern void memory__free();              /* PRIVATE */

#ifdef DEBUG_MEMORY

#define  CHECK_FIELD_VALUE     0xe5e7e3e9

typedef struct _memory_block_header {
    unsigned size;
    char *creating_module;
    int line_number_in_creating_module;
    unsigned int check_field;
} memory_block_header;

#define  memory__size_of_header    (sizeof(struct _memory_block_header))

#define  memory__get_header(block) \
  ((struct _memory_block_header *)((block)-memory__size_of_header))

#define  memory__on_heap_p(block)  \
  (memory__get_header(block)->check_field==CHECK_FIELD_VALUE)

#else

#define  memory__size_of_header     0

#define  memory__on_heap_p(block)   1

#endif

/*
 *    int string_Length(string s):
 *        Effects: Returns the number of non-null characters in s.
 */

#ifndef memory__PROVIDER
#ifdef  DEBUG_MEMORY

extern char *current_module;
extern void set_module();

#define  malloc(size)               (set_module(__FILE__,__LINE__),\
				     memory__malloc(size))
#define  realloc(ptr, size)         (set_module(__FILE__,__LINE__),\
				     memory__realloc((char *) ptr, size))
#define  calloc(nelem, elsize)      (set_module(__FILE__,__LINE__),\
				     memory__calloc(nelem, elsize))
#define  free(ptr)                  (set_module(__FILE__,__LINE__),\
				     memory__free((char *) ptr))
#else

#define  malloc(size)               memory__malloc(size)
#define  realloc(ptr, size)         memory__realloc((char *) ptr, size)
#define  calloc(nelem, elsize)      memory__calloc(nelem, elsize)
#define  free(ptr)                  memory__free((char *) ptr)

#endif  /* DEBUG_MEMORY */

#endif  /* memory__PROVIDER */

#endif  /* memory_MODULE */

#endif  /* SABER */
