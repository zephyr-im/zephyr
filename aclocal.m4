AC_DEFUN(ZEPHYR_FUNC_REGCOMP,
[AC_MSG_CHECKING(for working regcomp)
AC_CACHE_VAL(zephyr_cv_func_regcomp,
[AC_TRY_RUN([
#include <sys/types.h>
#include <regex.h>
int main()
{
    regex_t reg;
    int retval;
    char errbuf[512];

    retval = regcomp(&reg, "[Ff]rom:", REG_EXTENDED | REG_NOSUB);
    exit(retval != 0);
}
], zephyr_cv_func_regcomp=yes, zephyr_cv_func_regcomp=no,
   zephyr_cv_func_regcomp=no)])dnl
AC_MSG_RESULT($zephyr_cv_func_regcomp)
if test $zephyr_cv_func_regcomp = yes; then
  AC_DEFINE(HAVE_REGCOMP)
fi])
