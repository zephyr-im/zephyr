#include "new_memory.h"
#include "text_operations.h"
#include "char_stack.h"

string lany(text_ptr, str)
     string *text_ptr;
     string str;
{
    string result, whats_left;
    char *p = *text_ptr;

    while (*p && *str) p++, str++;

    result = string_CreateFromData(*text_ptr, p - *text_ptr);
    whats_left = string_Copy(p);
    free(*text_ptr);
    *text_ptr = whats_left;

    return(result);
}

string lbreak(text_ptr, set)
     string *text_ptr;
     character_class *set;
{
    string result, whats_left;
    char *p = *text_ptr;

    while (*p && !(*set)[*p]) p++;

    result = string_CreateFromData(*text_ptr, p - *text_ptr);
    whats_left = string_Copy(p);
    free(*text_ptr);
    *text_ptr = whats_left;

    return(result);
}

string lspan(text_ptr, set)
     string *text_ptr;
     character_class *set;
{
    string result, whats_left;
    char *p = *text_ptr;

    while (*p && (*set)[*p]) p++;

    result = string_CreateFromData(*text_ptr, p - *text_ptr);
    whats_left = string_Copy(p);
    free(*text_ptr);
    *text_ptr = whats_left;

    return(result);
}

string rany(text_ptr, str)
     string *text_ptr;
     string str;
{
    string result, whats_left;
    string text = *text_ptr;
    char *p = text + strlen(text);

    while (text<p && *str) p--, str++;

    result = string_Copy(p);
    whats_left = string_CreateFromData(text, p - text);
    free(text);
    *text_ptr = whats_left;

    return(result);
}

string rbreak(text_ptr, set)
     string *text_ptr;
     character_class *set;
{
    string result, whats_left;
    string text = *text_ptr;
    char *p = text + strlen(text);

    while (text<p && !(*set)[p[-1]]) p--;

    result = string_Copy(p);
    whats_left = string_CreateFromData(text, p - text);
    free(text);
    *text_ptr = whats_left;

    return(result);
}

string rspan(text_ptr, set)
     string *text_ptr;
     character_class *set;
{
    string result, whats_left;
    string text = *text_ptr;
    char *p = text + strlen(text);

    while (text<p && (*set)[p[-1]]) p--;

    result = string_Copy(p);
    whats_left = string_CreateFromData(text, p - text);
    free(text);
    *text_ptr = whats_left;

    return(result);
}
