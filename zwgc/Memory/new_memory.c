/* This file is part of the Project Athena Zephyr Notification System.
 * It is one of the source files comprising zwgc, the Zephyr WindowGram
 * client.
 *
 *      Created by:     Marc Horowitz <marc@athena.mit.edu>
 *
 *      $Source$
 *      $Author$
 *
 *      Copyright (c) 1989 by the Massachusetts Institute of Technology.
 *      For copying and distribution information, see the file
 *      "mit-copyright.h".
 */

#if !defined(SABER) && (defined(DEBUG) || defined(MEMORY_DEBUG))

#if (!defined(lint) && !defined(SABER))
static char rcsid_new_memory_c[] = "$Id$";
#endif

/*
 * memory - module wrapping debugging code around normal malloc/free/etc.
 *          routines.
 *
 * Overview:
 *
 *        ...
 */

#define  memory__PROVIDER
#include "new_memory.h"

/*
 *
 */
extern char *malloc();
extern char *realloc();
char *calloc();
extern int free();

/*
 *
 */
#ifdef DEBUG
#define  assert(x)          if (!(x)) abort()
#else
#define  assert(x)          
#endif

/*
 *
 */
#ifdef DEBUG_MEMORY

#include <stdio.h>

extern void record_request();
char *current_module = 0;
int current_line = -1;

#endif

/*
 *    string string_CreateFromData(char *data, int length):
 *        Requires: data[0], data[1], ..., data[length-1] != 0
 *        Effects: Takes the first length characters at data and
 *                 creates a string containing them.  The returned string
 *                 is on the heap & must be freed eventually.
 *                 I.e., if passed "foobar" and 3, it would return
 *                 string_Copy("foo").
 */

char *memory__malloc(size)
     unsigned size;
{
    char *result;

    result = malloc(size + memory__size_of_header);
    if (!result)
      abort();       /* <<<>>> */

#ifdef DEBUG_MEMORY
    ((memory_block_header *)result)->size = size;
    ((memory_block_header *)result)->creating_module = current_module;
    ((memory_block_header *)result)->line_number_in_creating_module =
      current_line;
    ((memory_block_header *)result)->check_field = CHECK_FIELD_VALUE;
    result += memory__size_of_header;

    record_request(current_module, current_line, 1, size);
#endif

    return(result);
}

char *memory__realloc(ptr, size)
     char *ptr;
     unsigned size;
{
    char *result;

    assert(ptr);

#ifdef DEBUG_MEMORY
    if (!memory__on_heap_p(ptr)) {
	printf("realloced non-memory block in %s on line %d!\n",
	       current_module, current_line);
	fflush(stdout);
	return(realloc(ptr, size));
    }
#endif

    result = realloc(ptr-memory__size_of_header, size+memory__size_of_header);
    if (!result)
      abort(); /* <<<>>> */

    return(result+memory__size_of_header);
}

char *memory__calloc(nelem, elsize)
     unsigned nelem;
     unsigned elsize;
{
    char *result;

#ifdef DEBUG_MEMORY
    printf("in calloc\n"); fflush(stdout);
#endif

    abort();

#ifdef FRED
    result = calloc(nelem, elsize);
    if (!result)
      abort();

    record_request(1);
#endif

    return(result);
}

void memory__free(ptr)
     char *ptr;
{
    assert(ptr);

#ifdef DEBUG_MEMORY
    if (!memory__on_heap_p(ptr)) {
	printf("freed non-memory block in %s on line %d!\n", current_module,
	       current_line);
	fflush(stdout);
	(void)free(ptr);
	return;
    }

    record_request(memory__get_header(ptr)->creating_module,
		   memory__get_header(ptr)->line_number_in_creating_module,
		   -1,
		   memory__get_header(ptr)->size);
#endif

    (void)free(ptr-memory__size_of_header);
}

#ifdef DEBUG_MEMORY

#include "../Dictionary/int_dictionary.h"

static int request_off = 0;
static int_dictionary requests = 0;
static int outstanding_requests = 0;
static int outstanding_memory = 0;

void record_request(module, line_number, dir, size)
     char *module;
     int line_number;
     int dir;
     unsigned int size;
{
    int_dictionary_binding *binding;
    int already_exists;
#ifdef LINE
    char buffer[20];
#endif

    if (request_off)
      return;
    request_off = 1;

    if (!requests)
      requests = int_dictionary_Create(101);

#ifdef LINE
    module = string_Concat(module, ":");
    sprintf(buffer, "%d", line_number);
    module = string_Concat2(module, buffer);
#endif

    binding = int_dictionary_Define(requests, module, &already_exists);
    if (!already_exists)
      binding->value = 0;

#ifdef LINE
    free(module);
#endif

    binding->value += dir;
    outstanding_requests += dir;
    outstanding_memory += size*dir;

    request_off = 0;
}

void proc(binding)
     int_dictionary_binding *binding;
{
    if (binding->value)
      printf("    %-30s %6d blocks allocated\n", binding->key, binding->value);
}

void report_memory_usage()
{
    printf("\n# of blocks on the heap = %d\n", outstanding_requests);
    printf("Total heap space in use: %d bytes\n", outstanding_memory);

    printf("\nHeap Allocations by module:\n");
    int_dictionary_Enumerate(requests, proc);
    printf("\n");

    fflush(stdout);
}

void set_module(file, line)
     char *file;
     int line;
{
    if (request_off)
      return;

    if (!strcmp(file, "new_string.c"))
      return;
    if (!strcmp(file, "string_dictionary_aux.c"))
      return;

    current_line = line;
    current_module = file;
}

#endif

#endif /* SABER */
