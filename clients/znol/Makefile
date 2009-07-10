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
ALL_CFLAGS=${CFLAGS} -I${top_srcdir}/h -I${BUILDTOP}/h ${CPPFLAGS}
LDFLAGS=
LIBS=${LIBZEPHYR} -lkrb5 -lk5crypto -lcom_err -lkrb4 -ldes425 -lkrb5 -lk5crypto -lcom_err  -lreadline -lcurses -ldl  -lcom_err

OBJS=	znol.o

all: znol

znol: ${OBJS} ${LIBZEPHYR}
	${LIBTOOL} --mode=link ${CC} ${LDFLAGS} -o $@ ${OBJS} ${LIBS}

.c.o:
	${CC} -c ${ALL_CFLAGS} $<

check:

install: znol
	${LIBTOOL} --mode=install ${INSTALL} -m 755 znol ${DESTDIR}${bindir}
	${INSTALL} -m 644 ${srcdir}/znol.1 ${DESTDIR}${mandir}/man1

clean:
	${LIBTOOL} --mode=clean rm -f znol
	rm -f ${OBJS}

${OBJS}: ${top_srcdir}/h/sysdep.h ${BUILDTOP}/h/config.h
${OBJS}: ${BUILDTOP}/h/zephyr/zephyr.h ${BUILDTOP}/h/zephyr/zephyr_err.h

.PHONY: all check install clean

