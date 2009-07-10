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
ALL_CFLAGS=${CFLAGS} -I${top_srcdir}/h -I${BUILDTOP}/h ${CPPFLAGS}
LDFLAGS=
LIBS=${LIBZEPHYR} -lkrb5 -lk5crypto -lcom_err -lkrb4 -ldes425 -lkrb5 -lk5crypto -lcom_err  -lreadline -lcurses -ldl  -lcom_err

OBJS=	timer.o queue.o zhm.o zhm_client.o zhm_server.o

all: zhm

zhm: ${OBJS} ${LIBZEPHYR}
	${LIBTOOL} --mode=link ${CC} ${LDFLAGS} -o $@ ${OBJS} ${LIBS}

.c.o:
	${CC} -c ${ALL_CFLAGS} $<

check:

install: zhm
	${LIBTOOL} --mode=install ${INSTALL} -m 755 zhm ${DESTDIR}${lsbindir}
	${INSTALL} -m 644 ${srcdir}/zhm.8 ${DESTDIR}${mandir}/man8

clean:
	${LIBTOOL} --mode=clean rm -f zhm
	rm -f ${OBJS}

${OBJS}: zhm.h timer.h ${top_srcdir}/h/internal.h ${top_srcdir}/h/sysdep.h
${OBJS}: ${BUILDTOP}/h/config.h ${BUILDTOP}/h/zephyr/zephyr.h
${OBJS}: ${BUILDTOP}/h/zephyr/zephyr_err.h

.PHONY: all check install clean

