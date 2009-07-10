SHELL = /bin/sh

prefix=/usr/local
exec_prefix=${prefix}
datadir=${prefix}/share
sysconfdir=${prefix}/etc
sbindir=${exec_prefix}/sbin
lsbindir=${sbindir}

includedir=${prefix}/include
mandir=${prefix}/man
libdir=${exec_prefix}/lib
top_builddir=..

srcdir=.
top_srcdir=..
BUILDTOP=..

LIBTOOL=$(SHELL) $(top_builddir)/libtool
CC=gcc
INSTALL=/usr/bin/install -c

LIBZEPHYR=${BUILDTOP}/lib/libzephyr.la
CPPFLAGS=-I/usr/include/kerberosIV -I/usr/include/et
CFLAGS=-g -O0
ALL_CFLAGS=${CFLAGS} -DSYSCONFDIR=\"${sysconfdir}\" -I${top_srcdir}/h \
	-I${BUILDTOP}/h -I. ${CPPFLAGS}
LDFLAGS=
LIBS=${LIBZEPHYR} -lkrb5 -lk5crypto -lcom_err -lkrb4 -ldes425 -lkrb5 -lk5crypto -lcom_err  -lreadline -lcurses -ldl  -lcom_err

OBJS=	zsrv_err.o access.o acl_files.o bdump.o class.o client.o common.o \
	dispatch.o kstuff.o main.o server.o subscr.o timer.o uloc.o \
	zstring.o realm.o version.o

all: zephyrd

zephyrd: ${OBJS} ${LIBZEPHYR}
	${LIBTOOL} --mode=link ${CC} ${LDFLAGS} -o $@ ${OBJS} ${LIBS}

zsrv_err.c zsrv_err.h: zsrv_err.et
	compile_et ${srcdir}/zsrv_err.et

version.o: version.h

version.h: always
	sh ${srcdir}/new_vers.sh

.c.o:
	${CC} -c ${ALL_CFLAGS} $<

check:

# No dependency on zephyrd, to avoid rebuilding version.o.
install:
	${LIBTOOL} --mode=install ${INSTALL} -m 755 zephyrd \
	  ${DESTDIR}${sbindir}
	${INSTALL} -m 644 ${srcdir}/zephyrd.8 ${DESTDIR}${mandir}/man8
	${INSTALL} -m 644 ${srcdir}/default.subscriptions \
		${DESTDIR}${sysconfdir}/zephyr

clean:
	${LIBTOOL} --mode=clean rm -f zephyrd
	rm -f ${OBJS} zsrv_err.[ch]

always:

${OBJS}: zserver.h zsrv_err.h timer.h zsrv_conf.h zstring.h access.h acl.h
${OBJS}: ${top_srcdir}/h/internal.h ${top_srcdir}/h/sysdep.h
${OBJS}: ${BUILDTOP}/h/config.h ${BUILDTOP}/h/zephyr/zephyr.h
${OBJS}: ${BUILDTOP}/h/zephyr/zephyr_err.h

.PHONY: all check install clean always

