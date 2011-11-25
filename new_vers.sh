#!/bin/sh
#
top_srcdir=${1:-`pwd`}

u=${USER-the_zephyr_builder}
h=`hostname`
t=`date`
v=`sh ${top_srcdir}/get_vers.sh ${top_srcdir}`

umask 002
/bin/echo "#define ZEPHYR_VERSION_STRING \"${v} (${t}) ${u}@${h}\"" > h/zephyr_version.h
