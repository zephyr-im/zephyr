#include "character_class.h"

static character_class cache;

character_class *string_to_character_class(str)
     string str;
{
    int i;

    bzero(cache, sizeof(cache));

    for (i=0; i<strlen(str); i++)
      cache[str[i]] = 1;

    return(&cache);
}
