AUTOMAKE_OPTIONS = foreign
CFLAGS = -Wall -Wno-unused-function -std=gnu11 -O2 $(SANITIZER_FLAGS)
LDFLAGS = $(SANITIZER_FLAGS)

SUBDIRS = uv

ACLOCAL_AMFLAGS = -I m4

AM_CPPFLAGS = -I$(top_builddir)             \
              -I$(top_srcdir)/src           \
              -I$(top_srcdir)/src/chacha20  \
              -I$(top_srcdir)/src/poly1305  \
              -I$(top_srcdir)/uv/include    \
              -I$(top_srcdir)/src/secp256k1

include_HEADERS =

CLEANFILES =

lib_LTLIBRARIES = libhsk.la

libhsk_la_LIBADD = $(top_builddir)/uv/libuv.la   \
                   $(LIB_WINBCRYPT)

libhsk_la_CFLAGS = -DHSK_BUILD @CFLAGS@
libhsk_la_LDFLAGS = -no-undefined -version-info $(LINKER_VERSION)
libhsk_la_SOURCES = src/addr.c                   \
                    src/addrmgr.c                \
                    src/aead.c                   \
                    src/base32.c                 \
                    src/blake2b.c                \
                    src/bn.c                     \
                    src/brontide.c               \
                    src/chacha20/chacha20.c      \
                    src/chain.c                  \
                    src/dns.c                    \
                    src/dnssec.c                 \
                    src/ecc.c                    \
                    src/ec.c                     \
                    src/error.c                  \
                    src/hash.c                   \
                    src/header.c                 \
                    src/hesiod.c                 \
                    src/map.c                    \
                    src/msg.c                    \
                    src/poly1305/poly1305.c      \
                    src/pool.c                   \
                    src/proof.c                  \
                    src/random.c                 \
                    src/req.c                    \
                    src/resource.c               \
                    src/sha256.c                 \
                    src/sha3.c                   \
                    src/sig0.c                   \
                    src/siphash.c                \
                    src/store.c                  \
                    src/timedata.c               \
                    src/utils.c                  \
                    src/secp256k1/secp256k1.c

EXTRA_DIST = README.md \
             LICENSE

bin_PROGRAMS = hnsd

hnsd_SOURCES = src/cache.c  \
               src/daemon.c \
               src/ns.c     \
               src/rs.c     \
               src/rs_worker.c \
               src/signals.c

hnsd_LDADD = $(LIB_UNBOUND)             \
             $(top_builddir)/libhsk.la

hnsd_LDFLAGS = -static
hnsd_CFLAGS = -DHSK_BUILD $(INC_UNBOUND) $(AM_CFLAGS)
hnsd_CPPFLAGS = $(AM_CPPFLAGS)

noinst_PROGRAMS = test_hnsd

test_hnsd_SOURCES = test/hnsd-test.c     \
                    test/base32-test.c   \
                    test/dns-test.c      \
                    test/resource-test.c

test_hnsd_LDFLAGS = -static
test_hnsd_CPPFLAGS = $(AM_CPPFLAGS)

test_hnsd_LDADD = $(LIB_UNBOUND)             \
                  $(top_builddir)/libhsk.la

# pkgconfigdir = $(libdir)/pkgconfig
# pkgconfig_DATA = @PACKAGE_NAME@.pc

.PHONY: e2e
e2e:
	npm --prefix ./integration/ install
	npm --prefix ./integration/ run test
