#ifndef character_class_TYPE
#define character_class_TYPE

#include "new_string.h"

#define  NUMBER_OF_CHARACTERS   256

typedef char character_class[NUMBER_OF_CHARACTERS];

extern character_class *string_to_character_class();

#endif
