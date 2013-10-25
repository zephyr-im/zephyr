#!/bin/sh

top_srcdir=${1:-`pwd`}

if test -f ${top_srcdir}/VERSION; then
    VERSION=`cat ${top_srcdir}/VERSION`
elif test -d ${top_srcdir}/.git; then
    VERSION=`(cd $top_srcdir; git describe --abbrev=6 --dirty | sed -e 's/%7E/~/')`

    if test "$(git symbolic-ref HEAD)" != refs/heads/master; then
        REF=$(git symbolic-ref --short HEAD)
	if test "$REF" = "fatal: ref HEAD is not a symbolic ref"; then
            VERSION="$VERSION: detached head"
	else
	    VERSION="$VERSION $(echo $REF | awk -F/ '{print $NF}' | tr 'a-z-' 'A-Z ')"
        fi
    fi
fi

if test -z "$VERSION"; then
    VERSION='FROM SPACE'
fi

echo $VERSION
