SHELL = /bin/sh

prefix=/usr/local
exec_prefix=${prefix}
datadir=${prefix}/share
sysconfdir=${prefix}/etc
sbindir=${exec_prefix}/sbin

includedir=${prefix}/include
mandir=${prefix}/man
bindir=${exec_prefix}/bin
libdir=${exec_prefix}/lib

srcdir=.
top_srcdir=.
ENSUREDIR=${srcdir}/ensure-dir.sh
INSTALL=/usr/bin/install -c

SUBDIRS=lib libdyn clients server zhm zwgc

all:
	for i in ${SUBDIRS}; do (cd $$i; ${MAKE} $@) || exit 1; done

check clean:
	for i in ${SUBDIRS}; do (cd $$i; ${MAKE} $@) || exit 1; done

install:
	${ENSUREDIR} ${DESTDIR}${prefix} 755
	${ENSUREDIR} ${DESTDIR}${exec_prefix} 755
	${ENSUREDIR} ${DESTDIR}${bindir} 755
	${ENSUREDIR} ${DESTDIR}${libdir} 755
	${ENSUREDIR} ${DESTDIR}${datadir} 755
	${ENSUREDIR} ${DESTDIR}${datadir}/zephyr 755
	${ENSUREDIR} ${DESTDIR}${sysconfdir} 755
	${ENSUREDIR} ${DESTDIR}${sysconfdir}/zephyr/acl 755
	${ENSUREDIR} ${DESTDIR}${sbindir} 755
	${ENSUREDIR} ${DESTDIR}${includedir} 755
	${ENSUREDIR} ${DESTDIR}${includedir}/zephyr 755
	${ENSUREDIR} ${DESTDIR}${mandir} 755
	${ENSUREDIR} ${DESTDIR}${mandir}/man1 755
	${ENSUREDIR} ${DESTDIR}${mandir}/man3 755
	${ENSUREDIR} ${DESTDIR}${mandir}/man8 755
	${INSTALL} -m 644 ${srcdir}/h/zephyr/mit-copyright.h \
		${DESTDIR}${includedir}/zephyr
	${INSTALL} -m 644 ${srcdir}/h/zephyr/zephyr.h \
		${DESTDIR}${includedir}/zephyr
	${INSTALL} -m 644 h/zephyr/zephyr_err.h ${DESTDIR}${includedir}/zephyr
	for i in ${SUBDIRS}; do (cd $$i; ${MAKE} $@) || exit 1; done

.PHONY: all check install clean

