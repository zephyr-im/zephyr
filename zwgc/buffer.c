#include "new_memory.h"
#include "buffer.h"

static char *buffer = 0;

string buffer_to_string()
{
    return(buffer);
}

void clear_buffer()
{
    if (buffer)
      free(buffer);

    buffer = string_Copy("");
}

void append_buffer(str)
     char *str;
{
    buffer = string_Concat2(buffer, str);
}
