# AUTOMAKE_OPTIONS = foreign
# CFLAGS = -Wall -std=gnu11 -O2
# LDFLAGS =

SUBDIRS = cares

ACLOCAL_AMFLAGS = -I m4

AM_CPPFLAGS = -I$(top_builddir) \
              -I$(top_srcdir)/include \
              -I$(top_srcdir)/src

include_HEADERS = include/hsk.h \
                  include/hsk-cuckoo.h \
                  include/hsk-name.h \
                  include/hsk-error.h \
                  include/hsk-proof.h \
                  include/hsk-resource.h

CLEANFILES =

lib_LTLIBRARIES = libhsk.la

libhsk_la_LIBADD = -lcares
libhsk_la_CFLAGS = @CFLAGS@
libhsk_la_LDFLAGS = -no-undefined -version-info 0:0:0
libhsk_la_SOURCES = src/b64.c \
                    src/blake2b.c \
                    src/cuckoo.c \
                    src/name.c \
                    src/proof.c \
                    src/resource.c \
                    src/siphash.c

EXTRA_DIST = include \
             README.md \
             LICENSE

# TESTS = test/run-tests
# check_PROGRAMS = test/run-tests
# test_run_tests_CFLAGS =
# test_run_tests_LDFLAGS =
# test_run_tests_SOURCES = test/test.c
# test_run_tests_LDADD = libhsk.la

# DIST_SUBDIRS = test

PROGS = hsk
noinst_PROGRAMS = $(PROGS)
hsk_SOURCES = test/hsk.c
hsk_LDADD = $(top_builddir)/libhsk.la
hsk_CFLAGS = $(AM_CFLAGS)
hsk_CPPFLAGS = $(AM_CPPFLAGS)

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = @PACKAGE_NAME@.pc
