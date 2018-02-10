#!/bin/bash

cd $(dirname "$0")

if test -z "$LIBTOOLIZE" && test "$(uname)" = "Darwin"; then
  LIBTOOLIZE=glibtoolize
fi

ACLOCAL=${ACLOCAL:-aclocal}
AUTOCONF=${AUTOCONF:-autoconf}
AUTOMAKE=${AUTOMAKE:-automake}
LIBTOOLIZE=${LIBTOOLIZE:-libtoolize}

set -ex

pushd cares
if ! test -f configure; then
  ./buildconf
fi
popd

pushd uv
if ! test -f configure; then
  ./autogen.sh
fi
popd

"$LIBTOOLIZE" --copy
"$ACLOCAL" -I m4
"$AUTOCONF"
"$AUTOMAKE" --add-missing --copy
