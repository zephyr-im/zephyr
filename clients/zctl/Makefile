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
bindir=${exec_prefix}/bin
top_builddir=../..

srcdir=.
top_srcdir=../..
BUILDTOP=../..

LIBTOOL=$(SHELL) $(top_builddir)/libtool
CC=gcc
INSTALL=/usr/bin/install -c

LIBZEPHYR=${BUILDTOP}/lib/libzephyr.la
CPPFLAGS=-I/usr/include/kerberosIV -I/usr/include/et
CFLAGS=-g -O0
ALL_CFLAGS=${CFLAGS} -I${top_srcdir}/h -I${BUILDTOP}/h  ${CPPFLAGS}
LDFLAGS=
LIBS=${LIBZEPHYR} -lss -lreadline -lhistory -lcurses -lkrb5 -lk5crypto -lcom_err -lkrb4 -ldes425 -lkrb5 -lk5crypto -lcom_err  -lreadline -lcurses -ldl  -lcom_err

OBJS=	zctl.o zctl_cmds.o

all: zctl

zctl: ${OBJS} ${LIBZEPHYR}
	${LIBTOOL} --mode=link ${CC} ${LDFLAGS} -o $@ ${OBJS} ${LIBS}

zctl_cmds.c: zctl_cmds.ct
	mk_cmds ${srcdir}/zctl_cmds.ct

.c.o:
	${CC} -c ${ALL_CFLAGS} $<

check:

install: zctl
	${LIBTOOL} --mode=install ${INSTALL} -m 755 zctl ${DESTDIR}${bindir}
	${INSTALL} -m 644 ${srcdir}/zctl.1 ${DESTDIR}${mandir}/man1

clean:
	${LIBTOOL} --mode=clean rm -f zctl
	rm -f ${OBJS} zctl_cmds.c

${OBJS}: ${top_srcdir}/h/sysdep.h ${BUILDTOP}/h/config.h
${OBJS}: ${BUILDTOP}/h/zephyr/zephyr.h ${BUILDTOP}/h/zephyr/zephyr_err.h

.PHONY: all check install clean

