#!/bin/sh
#
top_srcdir=${1:-`pwd`}

v=`sh ${top_srcdir}/get_vers.sh ${top_srcdir}`

umask 002
/bin/echo "#define ZEPHYR_VERSION_STRING \"${v}\"" > h/zephyr_version.h
