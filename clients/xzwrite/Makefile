SHELL = /bin/sh

prefix=/usr/local
exec_prefix=${prefix}
datadir=${prefix}/share
sysconfdir=${prefix}/etc
sbindir=${exec_prefix}/sbin
lsbindir=${sbindir}
top_builddir=../..

includedir=${prefix}/include
mandir=${prefix}/man
libdir=${exec_prefix}/lib
bindir=${exec_prefix}/bin

srcdir=.
top_srcdir=../..
BUILDTOP=../..

LIBTOOL=$(SHELL) $(top_builddir)/libtool
CC=gcc
INSTALL=/usr/bin/install -c
at=@

LIBZEPHYR=${BUILDTOP}/lib/libzephyr.la
LIBDYN=${BUILDTOP}/libdyn/libdyn.a
CPPFLAGS=-I/usr/include/kerberosIV -I/usr/include/et
CFLAGS=-g -O0
ALL_CFLAGS=${CFLAGS} -DDATADIR=\"${datadir}\" -I${top_srcdir}/h \
	-I${BUILDTOP}/h  ${CPPFLAGS}
LDFLAGS= -L/usr/lib64 
LIBS=${LIBZEPHYR} ${LIBDYN} -lXaw -lXmu -lXt  -lSM -lICE -lX11 -lXext \
	 -lkrb5 -lk5crypto -lcom_err -lkrb4 -ldes425 -lkrb5 -lk5crypto -lcom_err  -lreadline -lcurses -ldl  -lcom_err

OBJS=	interface.o resource.o destlist.o util.o bfgets.o gethomedir.o \
	dest_window.o xzwrite.o edit_window.o zephyr.o GetString.o Popup.o \
	yank.o menu_window.o logins.o

all: xzwrite XZwrite

xzwrite: ${OBJS} ${LIBZEPHYR} ${LIBDYN}
	${LIBTOOL} --mode=link ${CC} ${LDFLAGS} -o $@ ${OBJS} ${LIBS}

.c.o:
	${CC} -c ${ALL_CFLAGS} $<

XZwrite: XZwrite.in
	rm -f XZwrite
	sed -e 's,$(at)datadir$(at),$(datadir),' < ${srcdir}/XZwrite.in \
		> XZwrite

check:

install: xzwrite XZwrite
	${LIBTOOL} --mode=install ${INSTALL} -m 755 xzwrite ${DESTDIR}${bindir}
	${INSTALL} -m 644 ${srcdir}/xzwrite.1 ${DESTDIR}${mandir}/man1
	${INSTALL} -m 644 XZwrite ${DESTDIR}${datadir}/zephyr
	${INSTALL} -m 644 ${srcdir}/xzwrite.bitmap ${DESTDIR}${datadir}/zephyr

clean:
	${LIBTOOL} --mode=clean rm -f xzwrite
	rm -f ${OBJS}

${OBJS}: xzwrite.h xzwrite-proto.h ${top_srcdir}/h/sysdep.h
${OBJS}: ${BUILDTOP}/h/config.h ${BUILDTOP}/h/zephyr/zephyr.h
${OBJS}: ${BUILDTOP}/h/zephyr/zephyr_err.h
destlist.o logins.o xzwrite.o zephyr.o: ${top_srcdir}/h/dyn.h

.PHONY: all check install clean

