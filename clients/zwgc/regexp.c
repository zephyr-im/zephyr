#include <stdio.h>
#include "regexp.h"

extern char *re_comp();
extern int re_exec();

int ed_regexp_match_p(test_string, pattern)
     string test_string;
     string pattern;
{
    char *comp_retval;
    int exec_retval;

    if (comp_retval = re_comp(pattern)) {
	fprintf(stderr,"%s in regex %s\n",comp_retval,pattern);
	return(0);
    }
    if ((exec_retval=re_exec(test_string)) == -1) {
	fprintf(stderr,"Internal error in re_exec()");
	return(0);
    }

    return(exec_retval);
}
