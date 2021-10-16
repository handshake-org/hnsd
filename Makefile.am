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

hskincludedir =  $(includedir)/hsk

hskinclude_HEADERS = src/hsk.h                    \
                     src/addr.h                   \
                     src/addrmgr.h                \
                     src/aead.h                   \
                     src/base32.h                 \
                     src/blake2b.h                \
                     src/bn.h                     \
                     src/brontide.h               \
                     src/chain.h                  \
                     src/dns.h                    \
                     src/dnssec.h                 \
                     src/ecc.h                    \
                     src/ec.h                     \
                     src/error.h                  \
                     src/hash.h                   \
                     src/header.h                 \
                     src/map.h                    \
                     src/msg.h                    \
                     src/pool.h                   \
                     src/proof.h                  \
                     src/random.h                 \
                     src/req.h                    \
                     src/resource.h               \
                     src/sha256.h                 \
                     src/sha3.h                   \
                     src/sig0.h                   \
                     src/siphash.h                \
                     src/timedata.h               \
                     src/utils.h                  \
                     src/platform-net.h           \
                     src/constants.h              \
                     src/genesis.h                \
                     src/proof-radix.h

poly1305includedir = $(includedir)/hsk/poly1305
poly1305include_HEADERS = src/poly1305/poly1305.h    \
                          src/poly1305/poly1305-8.h  \
                          src/poly1305/poly1305-16.h \
                          src/poly1305/poly1305-32.h \
                          src/poly1305/poly1305-64.h

chacha20includedir = $(includedir)/hsk/chacha20
chacha20include_HEADERS = src/chacha20/chacha20.h

secp256k1includedir = $(includedir)/hsk/secp256k1
secp256k1include_HEADERS = src/secp256k1/secp256k1.h               \
                           src/secp256k1/ecdh.h                    \
                           src/secp256k1/ecdh_impl.h               \
                           src/secp256k1/ecdsa.h                   \
                           src/secp256k1/ecdsa_impl.h              \
                           src/secp256k1/eckey.h                   \
                           src/secp256k1/eckey_impl.h              \
                           src/secp256k1/ecmult.h                  \
                           src/secp256k1/ecmult_const.h            \
                           src/secp256k1/ecmult_const_impl.h       \
                           src/secp256k1/ecmult_gen.h              \
                           src/secp256k1/ecmult_gen_impl.h         \
                           src/secp256k1/ecmult_impl.h             \
                           src/secp256k1/ecmult_static_context.h   \
                           src/secp256k1/elligator.h               \
                           src/secp256k1/elligator_impl.h          \
                           src/secp256k1/field.h                   \
                           src/secp256k1/field_10x26.h             \
                           src/secp256k1/field_10x26_impl.h        \
                           src/secp256k1/field_5x52.h              \
                           src/secp256k1/field_5x52_asm_impl.h     \
                           src/secp256k1/field_5x52_impl.h         \
                           src/secp256k1/field_5x52_int128_impl.h  \
                           src/secp256k1/field_impl.h              \
                           src/secp256k1/group.h                   \
                           src/secp256k1/group_impl.h              \
                           src/secp256k1/hash.h                    \
                           src/secp256k1/hash_impl.h               \
                           src/secp256k1/num.h                     \
                           src/secp256k1/num_impl.h                \
                           src/secp256k1/recovery.h                \
                           src/secp256k1/recovery_impl.h           \
                           src/secp256k1/scalar.h                  \
                           src/secp256k1/scalar_4x64.h             \
                           src/secp256k1/scalar_4x64_impl.h        \
                           src/secp256k1/scalar_8x32.h             \
                           src/secp256k1/scalar_8x32_impl.h        \
                           src/secp256k1/scalar_impl.h             \
                           src/secp256k1/scalar_low.h              \
                           src/secp256k1/scalar_low_impl.h         \
                           src/secp256k1/scratch.h                 \
                           src/secp256k1/scratch_impl.h            \
                           src/secp256k1/secp256k1.h               \
                           src/secp256k1/util.h


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

bin_PROGRAMS =

if BUILD_HNSD

bin_PROGRAMS += hnsd

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

endif


# pkgconfigdir = $(libdir)/pkgconfig
# pkgconfig_DATA = @PACKAGE_NAME@.pc

.PHONY: e2e
e2e:
	npm --prefix ./integration/ install
	npm --prefix ./integration/ run test
