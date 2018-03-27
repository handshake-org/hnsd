AC_PREREQ([2.57])
AC_INIT([libhsk], [0.0.0], [chjj@handshake.org])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([-Wall -Werror foreign subdir-objects])

AC_CANONICAL_HOST
AC_ENABLE_SHARED
AC_ENABLE_STATIC
AC_PROG_CXX
AC_PROG_CC

m4_ifdef([AM_PROG_AR], [AM_PROG_AR])
AC_PROG_LIBTOOL
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])
LT_INIT

AH_TOP([#ifndef _HSK_CONFIG_H])
AH_TOP([#define _HSK_CONFIG_H])
AH_BOTTOM([#endif /* _HSK_CONFIG_H */])

AC_CONFIG_SRCDIR([src/bio.h])
AC_CONFIG_HEADERS([src/config.h])
AC_CONFIG_FILES([Makefile libhsk.pc])
AC_CONFIG_SUBDIRS([uv secp256k1])

dnl PKG_PROG_PKG_CONFIG

AC_C_BIGENDIAN(
  [AC_DEFINE(HSK_BIG_ENDIAN, 1, [define this if built for a big endian system])],
  ,
  [AC_MSG_WARN([falling back to little endian])]
)

AC_CHECK_HEADER_STDBOOL
AC_C_INLINE
AC_TYPE_SIZE_T
AC_TYPE_UINT8_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_INT8_T
AC_TYPE_INT16_T
AC_TYPE_INT32_T
AC_TYPE_INT64_T
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_SYS_LARGEFILE
AC_CHECK_FUNCS([gethostbyname memset select strdup strtol])

AC_CHECK_HEADERS([ \
  arpa/inet.h \
  limits.h \
  netdb.h \
  netinet/in.h \
  stddef.h \
  stdint.h \
  stdlib.h \
  string.h \
  strings.h \
  sys/socket.h \
  sys/time.h \
  unistd.h \
])

AC_OUTPUT
