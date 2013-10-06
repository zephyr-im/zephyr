#!/bin/sh

top_srcdir=${1:-`pwd`}

if test -f ${top_srcdir}/VERSION; then
    VERSION=`cat ${top_srcdir}/VERSION`
elif test -d ${top_srcdir}/.git; then
    VERSION=`(cd $top_srcdir; git describe --abbrev=6 --dirty | sed -e 's/%7E/~/')`
fi

if test -z "$VERSION"; then
    VERSION='FROM SPACE'
fi

echo $VERSION
