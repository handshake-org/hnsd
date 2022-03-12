#!/bin/bash

cd $(dirname "$0")

if test -z "$LIBTOOLIZE" && test "$(uname)" = "Darwin"; then
  LIBTOOLIZE=glibtoolize
fi

ACLOCAL=${ACLOCAL:-aclocal}
AUTOCONF=${AUTOCONF:-autoconf}
AUTORECONF=${AUTORECONF:-autoreconf}
AUTOMAKE=${AUTOMAKE:-automake}
AUTOHEADER=${AUTOHEADER:-autoheader}
LIBTOOLIZE=${LIBTOOLIZE:-libtoolize}

set -ex

pushd uv
if ! test -f configure; then
  ./autogen.sh
fi
popd

"$LIBTOOLIZE" --copy
"$ACLOCAL" -I m4
"$AUTOCONF"
"$AUTOHEADER"
"$AUTOMAKE" --add-missing --copy
