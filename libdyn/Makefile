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

srcdir=.
top_srcdir=..
BUILDTOP=..

CC=gcc
RANLIB=ranlib

CPPFLAGS=-I/usr/include/kerberosIV -I/usr/include/et
CFLAGS=-g -O0
ALL_CFLAGS=${CFLAGS} -I${top_srcdir}/h -I${BUILDTOP}/h ${CPPFLAGS}

OBJS =	dyn_append.o dyn_create.o dyn_debug.o dyn_delete.o dyn_insert.o \
	dyn_paranoid.o dyn_put.o dyn_realloc.o dyn_size.o

all: libdyn.a dyntest

libdyn.a: ${OBJS}
	ar cru $@ ${OBJS}
	${RANLIB} $@

dyntest: libdyn.a dyntest.o
	${CC} ${LDFLAGS} -o $@ dyntest.o libdyn.a

.c.o:
	${CC} -c ${ALL_CFLAGS} $<

check:

install:

clean:
	rm -f ${OBJS} libdyn.a dyntest.o dyntest

${OBJS} dyntest.o: dynP.h ${top_srcdir}/h/dyn.h ${top_srcdir}/h/sysdep.h
${OBJS} dyntest.o: ${BUILDTOP}/h/config.h

.PHONY: all check install clean

