# AUTOMAKE_OPTIONS = foreign
# CFLAGS = -Wall -std=gnu11 -O2
# LDFLAGS =

SUBDIRS = uv ldns unbound

ACLOCAL_AMFLAGS = -I m4

AM_CPPFLAGS = -I$(top_builddir)                  \
              -I$(top_srcdir)/include            \
              -I$(top_srcdir)/src                \
              -I$(top_srcdir)/uv/include         \
              -I$(top_srcdir)/ldns/include       \
              -I$(top_srcdir)/unbound/libunbound

include_HEADERS = include/hsk.h           \
                  include/hsk-chain.h     \
                  include/hsk-constants.h \
                  include/hsk-cuckoo.h    \
                  include/hsk-error.h     \
                  include/hsk-hash.h      \
                  include/hsk-header.h    \
                  include/hsk-map.h       \
                  include/hsk-proof.h     \
                  include/hsk-resource.h

CLEANFILES =

lib_LTLIBRARIES = libhsk.la

# libhsk_la_LIBADD = -luv -lldns -lssl -lcrypto -lunbound
libhsk_la_LIBADD = -lssl                                       \
                   -lcrypto                                    \
                   $(top_builddir)/uv/.libs/libuv.la           \
                   $(top_builddir)/ldns/.libs/libldns.la

libhsk_la_CFLAGS = @CFLAGS@
libhsk_la_LDFLAGS = -no-undefined -version-info 0:0:0
libhsk_la_SOURCES = src/blake2b.c  \
                    src/bn.c       \
                    src/chain.c    \
                    src/cuckoo.c   \
                    src/dns.c      \
                    src/dnssec.c   \
                    src/hash.c     \
                    src/header.c   \
                    src/map.c      \
                    src/msg.c      \
                    src/pool.c     \
                    src/proof.c    \
                    src/resource.c \
                    src/sha256.c   \
                    src/siphash.c  \
                    src/utils.c

EXTRA_DIST = include   \
             README.md \
             LICENSE

PROGS = hsk
noinst_PROGRAMS = $(PROGS)

hsk_SOURCES = src/daemon.c \
              src/ns.c     \
              src/rs.c

hsk_LDADD = $(top_builddir)/libhsk.la                   \
            $(top_builddir)/unbound/.libs/libunbound.la

hsk_LDFLAGS = -static
hsk_CFLAGS = $(AM_CFLAGS)
hsk_CPPFLAGS = $(AM_CPPFLAGS)

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = @PACKAGE_NAME@.pc
