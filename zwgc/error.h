#ifndef error_MODULE
#define error_MODULE

#include <stdio.h>

extern int errno;
extern int error_code;
extern void com_err();

#define  FATAL_TRAP(function_call, message) \
                                           { error_code = (function_call);\
					    if (error_code) {\
						com_err("zwgc", error_code,\
							message);\
						exit(3);\
					    }\
					   }

#define  TRAP(function_call, message) \
                                          { error_code = (function_call);\
					    if (error_code) {\
						com_err("zwgc", error_code,\
							message);\
					    }\
					   }

#define  ERROR(a)                { fprintf(stderr, "zwgc: "); \
				   fprintf(stderr, a);\
				   fflush(stderr); }

#define  ERROR2(a,b)             { fprintf(stderr, "zwgc: "); \
				   fprintf(stderr, a, b);\
				   fflush(stderr); }

#define  ERROR3(a,b,c)           { fprintf(stderr, "zwgc: "); \
				   fprintf(stderr, a, b, c);\
				   fflush(stderr); }

#define  ERROR4(a,b,c,d)         { fprintf(stderr, "zwgc: "); \
				   fprintf(stderr, a, b, c, d);\
				   fflush(stderr); }

#endif
