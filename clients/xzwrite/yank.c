#include "xzwrite.h"

static Yank yank_buffer;
extern Defaults defs;

static int read_index, write_index, highest;

void yank_init()
{
     yank_buffer = (Yank) Malloc(defs.max_yanks*sizeof(YankRec),
				   "while allocating yank buffer", NULL);
     _BZERO((char *) yank_buffer, defs.max_yanks*sizeof(YankRec));

     read_index = write_index = 0;
     highest = -1;
}

Yank yank_prev()
{
     if (highest == -1)
	  return NULL;
     
     if (--read_index < 0) read_index = highest;
     return &yank_buffer[read_index];
}

Yank yank_next()
{
     if (highest == -1)
	  return NULL;
     
     if (++read_index > highest) read_index = 0;
     return &yank_buffer[read_index];
}

void yank_store(dest, msg)
   Dest dest;
   char *msg;
{
     yank_buffer[write_index].dest = *dest;
     if (yank_buffer[write_index].msg)
	 free(yank_buffer[write_index].msg);
     yank_buffer[write_index].msg = (char *) Malloc(strlen(msg) + 1,
						    "while yanking message",
						    NULL);
     strcpy(yank_buffer[write_index].msg, msg);

     /*
      * read_index  = write_index + 1 so that if I follow the store by
      * a yank_prev I will get the message just stored (since
      * read_index is decremented before being used).  If I do a
      * yank_next, then read_index will be > highest and reset to zero.
      */
     read_index = write_index + 1;
     if (write_index > highest)
	  highest = write_index;
     write_index = (write_index + 1) % defs.max_yanks;
}
