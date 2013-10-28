dnl Process this file with autoconf to produce a configure script.
AC_INIT([zephyr],[3.1.2])
AC_CONFIG_MACRO_DIR([m4])

test -d h || mkdir h
test -d h/zephyr || mkdir h/zephyr

test -z "$lbindir" && lbindir='${bindir}'
test -z "$lsbindir" && lsbindir='${sbindir}'
AC_SUBST(lbindir)
AC_SUBST(lsbindir)

AC_CANONICAL_SYSTEM
AC_CANONICAL_TARGET
AC_DEFINE_UNQUOTED(MACHINE_TYPE, "$host", [Define to the type of the host system.])

dnl Checks for programs.
AC_PROG_CC
AC_PROG_YACC
AC_PROG_LEX
AC_PROG_INSTALL
AC_PROG_LIBTOOL

AC_MSG_CHECKING(location of temporary directory)
if test -d /var/tmp; then
	found_tmp=/var/tmp/
elif test -d /usr/tmp; then
	found_tmp=/usr/tmp/
else
	found_tmp=/tmp/
fi
AC_DEFINE_UNQUOTED(FOUND_TMP, "${found_tmp}", [Define to a temporary directory on your system.])
AC_MSG_RESULT(${found_tmp})

dnl Checks for header files.
AC_PATH_XTRA
AC_HEADER_STDC
AC_HEADER_SYS_WAIT
AC_CHECK_HEADERS(fcntl.h paths.h sgtty.h unistd.h malloc.h)
AC_CHECK_HEADERS(sys/filio.h sys/ioctl.h sys/time.h sys/file.h sys/utsname.h)
AC_CHECK_HEADERS(sys/select.h sys/msgbuf.h sys/cdefs.h krb5_err.h termcap.h)
AC_CHECK_HEADERS(arpa/nameser_compat.h stdbool.h termio.h curses.h)
AC_CHECK_HEADERS([term.h], [], [],
[#ifdef HAVE_CURSES_H
#include <curses.h>
#endif
])

if test "$no_x" != "yes"; then
	ZWGC_LIBX11=-lX11
fi
AC_SUBST(XCLIENTS)
AC_SUBST(ZWGC_LIBX11)

dnl Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIGNAL
AC_TYPE_UID_T
AC_CHECK_SIZEOF(short)
AC_CHECK_SIZEOF(int)
AC_CHECK_SIZEOF(long)
AC_MSG_CHECKING(for 32-bit integer type)
if test "$ac_cv_sizeof_long" = 4; then
	int32=long
elif test "$ac_cv_sizeof_int" = 4; then
	int32=int
elif test "$ac_cv_sizeof_short" = 4; then
	int32=short
else
	AC_WARN([Can't find 32-bit type, using long])
	int32=long
fi
AC_DEFINE_UNQUOTED(ZEPHYR_INT32, ${int32}, [Define to a signed 32-bit integral type.])
AC_MSG_RESULT(${int32})

AC_CHECK_LIB(w, wslen)
# XXX? AC_CHECK_LIB(dl, dlopen)

AC_CHECK_MEMBER([struct sockaddr_in.sin_len],
		[AC_DEFINE(HAVE_SOCKADDR_IN_SIN_LEN, 1,
		 [sockaddr_in has sin_len member])],
		[], [
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
])

AC_CHECK_MEMBER([struct sockaddr_in6.sin6_len],
		[AC_DEFINE(HAVE_SOCKADDR_IN6_SIN6_LEN, 1,
		 [sockaddr_in6 has sin6_len member])],
		[], [
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
])

AC_SEARCH_LIBS(gethostbyname, nsl)
AC_SEARCH_LIBS(socket, socket)

AC_CHECK_LIB(44bsd, strerror)

AC_ARG_WITH(libiconv,
        [  --with-libiconv=PREFIX  Location for libiconv],
        [libiconv="$withval"], [libiconv=no])
if test "$libiconv" != no; then
        CPPFLAGS="$CPPFLAGS -I$libiconv/include"
        LDFLAGS="$LDFLAGS -L$libiconv/lib"
        AC_CHECK_LIB(iconv, iconv_open, [LIBICONV=-liconv; AC_SUBST(LIBICONV)])
else
        AC_CHECK_FUNC(iconv_open, :,
                      AC_CHECK_LIB(iconv, iconv_open, [LIBICONV=-liconv; AC_SUBST(LIBICONV)]))
fi
AC_SUBST(LIBICONV)

AC_CHECK_LIB(curses, tgetstr, [TLIB=-lcurses], [TLIB=-ltermcap])
AC_SUBST(TLIB)

AC_ARG_WITH(krb4,
	[  --with-krb4=PREFIX      Use Kerberos 4],
	[krb4="$withval"], [krb4=no])
if test "$krb4" != no; then
	AC_CHECK_FUNC(gethostbyname, :, AC_CHECK_LIB(nsl, gethostbyname))
	AC_CHECK_FUNC(socket, :, AC_CHECK_LIB(socket, socket))
	AC_CHECK_LIB(gen, compile)
	if test "$krb4" != yes; then
	   CPPFLAGS="$CPPFLAGS -I$krb4/include"
	   if test -d "$krb4/include/kerberosIV"; then
	      CPPFLAGS="$CPPFLAGS -I$krb4/include/kerberosIV"
	   fi
	   LDFLAGS="$LDFLAGS -L$krb4/lib"
	fi
	AC_CHECK_LIB(krb4, krb_rd_req,
	     [KRB4_LIBS="-lkrb4 -ldes425 -lkrb5 -lk5crypto -lcom_err"],
	     [AC_CHECK_LIB(des, des_quad_cksum,
			   [KRB4_DES_LIBS="-ldes"],,,)
	     AC_CHECK_LIB(krb, krb_rd_req,
			   [KRB4_LIBS="-lkrb $KRB4_DES_LIBS"],
			   [AC_MSG_ERROR(Kerberos 4 libraries not found)],
			   $KRB4_DES_LIBS)],
	     -ldes425 -lkrb5 -lk5crypto -lcom_err)
	AC_DEFINE(HAVE_KRB4, 1, [Define to compile with Kerberos support.])
	LIBZEPHYR_LIBS="$LIBZEPHYR_LIBS $KRB4_LIBS"
fi
AC_SUBST(KRB4_LIBS)

AC_ARG_WITH(krb5,
	    [  --with-krb5=PREFIX      Use Kerberos 5],
	    [krb5="$withval"], [krb5=no])
if test "$krb5" != no; then
   AC_SEARCH_LIBS(gethostbyname, nsl)
   AC_SEARCH_LIBS(socket, socket)
   AC_CHECK_LIB(gen, compile)
   if test "$krb5" != yes; then
      PATH="$krb5/bin:$PATH"
   fi
   AC_CHECK_PROG(krb5config, krb5-config,yes)
   if test "$krb5config" = yes; then
      CPPFLAGS="$CPPFLAGS $(krb5-config --cflags krb5)"
      KRB5_LIBS="$(krb5-config --libs krb5)"
   else
      if test "$krb5" != yes; then
      	 CPPFLAGS="$CPPFLAGS -I$krb5/include"
      	 LDFLAGS="$LDFLAGS -L$krb5/lib"
      fi
      KRB5_LIBS="-lkrb5 -lk5crypto -lcom_err"
   fi
   AC_CHECK_HEADER(krb5.h, :, [AC_MSG_ERROR(Kerberos 5 headers not found)])
   local_save_LIBS=$LIBS
   LIBS="$libs $KRB5_LIBS"
   AC_CHECK_FUNC(krb5_init_context, :,
	           [AC_MSG_ERROR(Kerberos 5 libraries not found)])
   LIBS="$local_save_LIBS"
   AC_DEFINE(HAVE_KRB5, 1, [Define to compile with Kerberos 5 support.])
   LIBZEPHYR_LIBS="$LIBZEPHYR_LIBS $KRB5_LIBS"
   # the zephyr library needs -lresolv if it's built with krb5
   AC_CHECK_FUNC(res_send, :,
                 AC_CHECK_LIB(resolv, res_send, LIBZEPHYR_LIBS="-lresolv $LIBZEPHYR_LIBS",
                              AC_CHECK_LIB(resolv, __res_send, LIBZEPHYR_LIBS="-lresolv $LIBZEPHYR_LIBS",
                                           AC_MSG_ERROR(Zephyr requires libresolv along with Kerberos V.))))
   case "$target_os" in 
      darwin*) KRB5_LIBS="$KRB5_LIBS -framework Kerberos" ;;
   esac 
fi
AC_SUBST(KRB5_LIBS)

AC_SUBST(LIBZEPHYR_LIBS)

AC_ARG_WITH(hesiod,
	[  --with-hesiod=PREFIX    Use Hesiod],
	[hesiod="$withval"], [hesiod=no])
if test "$hesiod" != no; then
	AC_CHECK_FUNC(res_send, :, AC_CHECK_LIB(resolv, res_send))
        if test "$hesiod" != yes; then
        	CPPFLAGS="$CPPFLAGS -I$hesiod/include"
        	LDFLAGS="$LDFLAGS -L$hesiod/lib"
        fi
        AC_CHECK_FUNC(hes_resolve, :,
                      AC_CHECK_LIB(hesiod, hes_resolve, HESIOD_LIBS="-lhesiod",
                                   [AC_MSG_ERROR(Hesiod library not found)],$LIBS))
	AC_DEFINE(HAVE_HESIOD, 1, [Define to compile with Hesiod support.])
fi

AC_SUBST(HESIOD_LIBS)

AC_ARG_WITH(regex,
	[  --with-regex=PREFIX     Use installed regex library],
	[regex="$withval"], [regex=no])
if test "$regex" != no; then
	if test "$regex" != yes; then
		CPPFLAGS="$CPPFLAGS -I$regex/include"
		LDFLAGS="$LDFLAGS -L$regex/lib"
	fi
	AC_CHECK_LIB(regex, regcomp, REGEX_LIBS=-lregex,
		     [AC_MSG_ERROR(regex library not found)])
else
	AC_CHECK_FUNC(regcomp, :,
		      [AC_MSG_ERROR(can't find POSIX regexp support)])
fi
AC_SUBST(REGEX_LIBS)

AC_ARG_WITH(com_err,
	[  --with-com_err=PREFIX   Specify location of com_err],
	[com_err="$withval"], [com_err=yes])
if test "$com_err" != no; then
	if test "$com_err" != yes; then
		CPPFLAGS="$CPPFLAGS -I$com_err/include"
		LDFLAGS="$LDFLAGS -L$com_err/lib"
	fi
	AC_CHECK_LIB(com_err, com_err, :,
		     [AC_MSG_ERROR(com_err library not found)])
else
	AC_MSG_ERROR(This package requires com_err.)
fi

AC_ARG_WITH(ss,
	[  --with-ss=PREFIX        Specify location of ss (requires com_err)],
	[ss="$withval"], [ss=maybe])
if test "$ss" != no; then
	if test "$ss" != yes -a "$ss" != maybe; then
		CPPFLAGS="$CPPFLAGS -I$ss/include"
		LDFLAGS="$LDFLAGS -L$ss/lib"
	fi
	AC_CHECK_LIB(ss, ss_perror, 
                     [SS_LIBS="-lss"
                     AC_DEFINE(HAVE_SS, 1, [Define if we are building with the ss library])],
		     AS_IF([test "x$ss" != "xmaybe"], AC_MSG_ERROR(ss library not found)),
                     -lcom_err)
        SS_OBJS='${SS_OBJS}'
fi
AC_SUBST(SS_LIBS)
AC_SUBST(SS_OBJS)

LIBS="$KRB5_LIBS $KRB4_LIBS $LIBS"

dnl Checks for library functions.
#XXX more looking for res_send
#AC_CHECK_FUNC(res_send, :, AC_CHECK_LIB(resolv, res_send))

AC_ARG_WITH([cares], AS_HELP_STRING([--with-cares], [Use libcares]))
if test "x$with_ares" != "xno"; then
   AC_CHECK_LIB(cares, ares_getnameinfo,
		       [ARES_LIBS="-lcares"
		       AC_DEFINE(HAVE_ARES, 1, [Define to compile with c-ares support.])],
		       AS_IF([test "x$with_ares" = "xyes"],
			     AC_MSG_ERROR(libcares not found)))
fi
AC_SUBST(ARES_LIBS)
		    
AC_PROG_GCC_TRADITIONAL
AC_FUNC_VPRINTF
AC_FUNC_GETPGRP
AC_FUNC_SETPGRP
AC_CHECK_FUNCS(putenv strchr memcpy memmove waitpid getlogin strerror random)
AC_CHECK_FUNCS(lrand48 gethostid getsid getpgid etext)
AC_CHECK_FUNCS(krb_get_err_text krb_log)
AC_CHECK_FUNCS(krb5_free_data krb5_c_make_checksum krb5_cc_set_default_name)
AC_CHECK_FUNCS(krb5_crypto_init krb5_c_decrypt krb5_free_unparsed_name)

AC_MSG_CHECKING(krb5_auth_con_getauthenticator out argument type)
AC_CACHE_VAL(ac_cv_krb5_auth_con_getauthenticator_takes_double_pointer, [
local_save_CPPFLAGS="$CPPFLAGS"
CPPFLAGS="${CPPFLAGS} ${KRB5_INC_FLAGS}"
AC_TRY_COMPILE(
[#include <krb5.h>
krb5_error_code
krb5_auth_con_getauthenticator(krb5_context context,
                           krb5_auth_context auth_context,
                           krb5_authenticator *authenticator);],
[krb5_error_code foo = krb5_auth_con_getauthenticator(0, 0, 0);],
ac_cv_krb5_auth_con_getauthenticator_takes_double_pointer=no,
[AC_TRY_COMPILE(
[#include <krb5.h>
krb5_error_code
krb5_auth_con_getauthenticator(krb5_context context,
                           krb5_auth_context auth_context,
                           krb5_authenticator **authenticator);],
[krb5_error_code foo = krb5_auth_con_getauthenticator(0, 0, 0);],
ac_cv_krb5_auth_con_getauthenticator_takes_double_pointer=yes,
[AC_MSG_ERROR([Cannot identify krb5_auth_con_getauthenticator function signature])]
)])
CPPFLAGS="${local_save_CPPFLAGS}"
])
krb5_authent_type='krb5_authenticator *'
if test "$ac_cv_krb5_auth_con_getauthenticator_takes_double_pointer" = yes; then
        AC_DEFINE(KRB5_AUTH_CON_GETAUTHENTICATOR_TAKES_DOUBLE_POINTER, 1,
                  [Define if `krb5_auth_con_getauthenticator' takes a double pointer third arg.])dnl
        krb5_authent_type='krb5_authenticator **'
fi
AC_MSG_RESULT($krb5_authent_type)

AC_CACHE_CHECK([krb5_auth_con_getflags out argument type],
	       [ac_cv_krb5_auth_con_flags_type], [
local_save_CPPFLAGS="$CPPFLAGS"
CPPFLAGS="${CPPFLAGS} ${KRB5_INC_FLAGS}"
for t in krb5_flags int32_t ; do
   AC_TRY_COMPILE(
      [#include <krb5.h>
       extern krb5_error_code
       krb5_auth_con_getflags(krb5_context, krb5_auth_context, $t *);],
       [krb5_error_code foo = krb5_auth_con_getflags(0, 0, 0);],
       [ac_cv_krb5_auth_con_flags_type=$t; break])
done
CPPFLAGS="${local_save_CPPFLAGS}"
if test "x$ac_cv_krb5_auth_con_flags_type" = x ; then
   AC_MSG_ERROR([Cannot identify krb5_auth_con_getflags function signature])
fi
])
AC_DEFINE_UNQUOTED([KRB5_AUTH_CON_FLAGS_TYPE],
		   [$ac_cv_krb5_auth_con_flags_type],
		   [krb5_auth_con_getflags() output arg type])

AC_MSG_CHECKING(for enc_part2 in struct krb5_ticket)
AC_CACHE_VAL(ac_cv_have_krb5_ticket_enc_part2, [
local_save_CPPFLAGS="$CPPFLAGS"
CPPFLAGS="${CPPFLAGS} ${KRB5_INC_FLAGS}"
AC_TRY_COMPILE(
[#include <krb5.h>], [krb5_ticket _tkt; _tkt.enc_part2;],
ac_cv_have_krb5_ticket_enc_part2=yes,
ac_cv_have_krb5_ticket_enc_part2=no)
])
CPPFLAGS="${local_save_CPPFLAGS}"
if test "$ac_cv_have_krb5_ticket_enc_part2" = yes; then
	AC_DEFINE(HAVE_KRB5_TICKET_ENC_PART2, 1,
                  [Define to 1 if `enc_part2' is member of `krb5_ticket'.])dnl
fi
AC_MSG_RESULT($ac_cv_have_krb5_ticket_enc_part2)

AC_MSG_CHECKING(for enctype in struct krb5_keyblock)
AC_CACHE_VAL(ac_cv_have_krb5_creds_keyblock_enctype, [
local_save_CPPFLAGS="$CPPFLAGS"
CPPFLAGS="${CPPFLAGS} ${KRB5_INC_FLAGS}"
AC_TRY_COMPILE(
[#include <krb5.h>], [krb5_creds _creds; _creds.keyblock.enctype;],
ac_cv_have_krb5_creds_keyblock_enctype=yes,
ac_cv_have_krb5_creds_keyblock_enctype=no)
])
CPPFLAGS="${local_save_CPPFLAGS}"
if test "$ac_cv_have_krb5_creds_keyblock_enctype" = yes; then
	AC_DEFINE(HAVE_KRB5_CREDS_KEYBLOCK_ENCTYPE, 1,
                  [Define if `keyblock.enctype' is member of `krb5_creds'.])dnl
fi
AC_MSG_RESULT($ac_cv_have_krb5_creds_keyblock_enctype)

AC_ARG_ENABLE(cmu-zwgcplus,
[  --enable-cmu-zwgcplus   enable CMU zwgcplus extensions],[
if test "$enableval" = "yes"; then
        AC_DEFINE(CMU_ZWGCPLUS, 1, [Define to enable zwgcplus support])
fi
])

AC_ARG_ENABLE(cmu-zctl-punt,
[  --enable-cmu-zctl-punt  enable CMU zctl punt extensions],[
if test "$enableval" = "yes"; then
        AC_DEFINE(CMU_ZCTL_PUNT, 1,
                  [Define to pull in CMU zctl punt backward compat foo])
fi
])

AC_ARG_ENABLE(cmu-hm-flush-restrict,
[  --enable-cmu-hm-flush-restrict   enable CMU zctl hm flush restriction],[
if test "$enableval" = "yes"; then
        AC_DEFINE(HM_FLUSH_RESTRICT, 1,
                  [Define to get hm_flush restrictions in zctl])
fi
])

AC_ARG_ENABLE(cmu-opstaff-locate-self,
[  --enable-cmu-opstaff-locate-self enable CMU opstaff locate-self ability],[
if test "$enableval" = "yes"; then
        AC_DEFINE(OPSTAFF_LOCATE_SELF, 1,
                  [Define to allow users to locate themselves if they are opstaff])
fi
])

AC_CONFIG_HEADER(h/config.h)
AC_OUTPUT(Makefile clients/Makefile clients/zaway/Makefile
          clients/zctl/Makefile clients/zleave/Makefile
          clients/zlocate/Makefile clients/znol/Makefile
          clients/zshutdown_notify/Makefile clients/zstat/Makefile
          clients/zwrite/Makefile lib/Makefile
          server/Makefile zhm/Makefile zwgc/Makefile
          zephyr.pc
          )
