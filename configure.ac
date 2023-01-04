# Package version (semver)
define(MAJOR, 2)
define(MINOR, 99)
define(PATCH, 0)

# Shared library version
# see: https://www.gnu.org/software/libtool/manual/html_node/Updating-version-info.html
define(CURRENT, 2)
define(REVISION, 0)
define(AGE, 0)

AC_PREREQ([2.57])
AC_INIT([hnsd], m4_join([.], MAJOR, MINOR, PATCH), [chjj@handshake.org])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([-Wall -Werror foreign subdir-objects])

AC_SUBST(LINKER_VERSION, m4_join([:], CURRENT, REVISION, AGE))

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
AC_CONFIG_FILES([Makefile])
AC_CONFIG_SUBDIRS([uv])

dnl PKG_PROG_PKG_CONFIG

AC_C_BIGENDIAN(
  [AC_DEFINE(HSK_BIG_ENDIAN, 1, [define if built for a big endian system])],
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

AC_CHECK_FUNCS([ \
  memset \
  strcasecmp \
  strdup \
  strchr \
  getrandom \
  arc4random \
  random \
])

AC_CHECK_HEADERS([ \
  arpa/inet.h \
  fcntl.h \
  limits.h \
  netinet/in.h \
  stddef.h \
  stdint.h \
  stdlib.h \
  string.h \
  strings.h \
  sys/random.h \
  unistd.h \
])

AC_ARG_WITH([network],
  [AS_HELP_STRING(
    [--with-network=main|testnet|regtest|simnet],
    [Specify network. Default is main.]
  )],
  [hsk_network=$withval],
  [hsk_network=main])

case $hsk_network in
  main | yes)
    AC_DEFINE(HSK_NETWORK, HSK_MAIN,
      [Define this symbol to choose a network])
  ;;
  testnet)
    AC_DEFINE(HSK_NETWORK, HSK_TESTNET,
      [Define this symbol to choose a network])
  ;;
  regtest)
    AC_DEFINE(HSK_NETWORK, HSK_REGTEST,
      [Define this symbol to choose a network])
  ;;
  simnet)
    AC_DEFINE(HSK_NETWORK, HSK_SIMNET,
      [Define this symbol to choose a network])
  ;;
  *)
    AC_MSG_ERROR([invalid network])
  ;;
esac

dnl
dnl Secp256k1
dnl

AX_PROG_CC_FOR_BUILD
AM_PROG_CC_C_O
AC_PROG_CC_C89
if test x"$ac_cv_prog_cc_c89" = x"no"; then
  AC_MSG_ERROR([c89 compiler support required])
fi
AM_PROG_AS

AC_ARG_ENABLE(endomorphism,
  AS_HELP_STRING(
    [--enable-endomorphism],
    [Enable endomorphism. Default is yes.)]
  ),
  [use_endomorphism=$enableval],
  [use_endomorphism=no])

AC_ARG_ENABLE(ecmult_static_precomputation,
  AS_HELP_STRING(
    [--enable-ecmult-static-precomputation],
    [Enable precomputed ecmult table for signing. Default is yes.)]
  ),
  [use_precomp=$enableval],
  [use_precomp=yes])

AC_ARG_WITH([field],
  [AS_HELP_STRING(
    [--with-field=64bit|32bit|auto],
    [Specify Field Implementation. Default is auto.]
  )],
  [req_field=$withval],
  [req_field=auto])

AC_ARG_WITH([scalar],
  [AS_HELP_STRING(
    [--with-scalar=64bit|32bit|auto],
    [Specify scalar implementation. Default is auto.]
  )],
  [req_scalar=$withval],
  [req_scalar=auto])

AC_ARG_WITH([asm],
  [AS_HELP_STRING(
    [--with-asm=x86_64|arm|no|auto]
    [Specify assembly optimizations to use. Default is auto.]
  )],
  [req_asm=$withval],
  [req_asm=auto])

AC_ARG_WITH([unbound],
  [AS_HELP_STRING(
    [--with-unbound=path]
    [Use libunbound installed at path. Default is to search system paths.]
  )],
  [libunbound_path=$withval],
  [libunbound_path=yes])

AC_ARG_WITH([sanitizers],
  [AS_HELP_STRING(
    [--with-sanitizers]
    [comma separated list of extra sanitizers to build with (default is none)]
  )],
  [SANITIZER_FLAGS="-g -fsanitize=$withval"])

AC_SUBST(SANITIZER_FLAGS, ${SANITIZER_FLAGS})

AC_CHECK_TYPES([__int128])

AC_MSG_CHECKING([for __builtin_expect])
AC_COMPILE_IFELSE(
  [AC_LANG_SOURCE([[void myfunc() {__builtin_expect(0,0);}]])],
  [
    AC_MSG_RESULT([yes]);
    AC_DEFINE(HAVE_BUILTIN_EXPECT, 1,
      [Define this symbol if __builtin_expect is available])
  ],
  [ AC_MSG_RESULT([no]) ]
)

if test x"$req_asm" = x"auto"; then
  SECP_64BIT_ASM_CHECK
  if test x"$has_64bit_asm" = x"yes"; then
    set_asm=x86_64
  fi
  if test x"$set_asm" = x; then
    set_asm=no
  fi
else
  set_asm=$req_asm
  case $set_asm in
    x86_64)
      SECP_64BIT_ASM_CHECK
      if test x"$has_64bit_asm" != x"yes"; then
        AC_MSG_ERROR([x86_64 assembly optimization requested but not available])
      fi
    ;;
    arm)
    ;;
    no)
    ;;
    *)
      AC_MSG_ERROR([invalid assembly optimization selection])
    ;;
  esac
fi

if test x"$req_field" = x"auto"; then
  if test x"set_asm" = x"x86_64"; then
    set_field=64bit
  fi
  if test x"$set_field" = x; then
    SECP_INT128_CHECK
    if test x"$has_int128" = x"yes"; then
      set_field=64bit
    fi
  fi
  if test x"$set_field" = x; then
    set_field=32bit
  fi
else
  set_field=$req_field
  case $set_field in
    64bit)
      if test x"$set_asm" != x"x86_64"; then
        SECP_INT128_CHECK
        if test x"$has_int128" != x"yes"; then
          AC_MSG_ERROR([Neither __int128 support or x86_64 assembly available])
        fi
      fi
    ;;
    32bit)
    ;;
    *)
      AC_MSG_ERROR([invalid field implementation selection])
    ;;
  esac
fi

if test x"$req_scalar" = x"auto"; then
  SECP_INT128_CHECK
  if test x"$has_int128" = x"yes"; then
    set_scalar=64bit
  fi
  if test x"$set_scalar" = x; then
    set_scalar=32bit
  fi
else
  set_scalar=$req_scalar
  case $set_scalar in
  64bit)
    SECP_INT128_CHECK
    if test x"$has_int128" != x"yes"; then
      AC_MSG_ERROR([__int128 support not available])
    fi
    ;;
  32bit)
    ;;
  *)
    AC_MSG_ERROR([invalid scalar implementation selected])
    ;;
  esac
fi

use_external_asm=no

case $set_asm in
  x86_64)
    AC_DEFINE(HSK_USE_ASM_X86_64, 1,
      [Define this symbol to enable x86_64 assembly optimizations])
  ;;
  arm)
    use_external_asm=yes
  ;;
  no)
  ;;
  *)
    AC_MSG_ERROR([invalid assembly optimizations])
  ;;
esac

case $set_field in
  64bit)
    AC_DEFINE(HSK_USE_FIELD_5X52, 1,
      [Define this symbol to use the FIELD_5X52 implementation])
  ;;
  32bit)
    AC_DEFINE(HSK_USE_FIELD_10X26, 1,
      [Define this symbol to use the FIELD_10X26 implementation])
  ;;
  *)
    AC_MSG_ERROR([invalid field implementation])
  ;;
esac

case $set_scalar in
  64bit)
    AC_DEFINE(HSK_USE_SCALAR_4X64, 1,
      [Define this symbol to use the 4x64 scalar implementation])
  ;;
  32bit)
    AC_DEFINE(HSK_USE_SCALAR_8X32, 1,
      [Define this symbol to use the 8x32 scalar implementation])
  ;;
  *)
    AC_MSG_ERROR([invalid scalar implementation])
  ;;
esac

if test x"$use_endomorphism" = x"yes"; then
  AC_DEFINE(HSK_USE_ENDOMORPHISM, 1,
    [Define this symbol to use endomorphism optimization])
fi

if test x"$use_precomp" = x"yes"; then
  AC_DEFINE(HSK_USE_ECMULT_STATIC_PRECOMPUTATION, 1,
    [Define this symbol to use a statically generated ecmult table])
fi

if test x"$use_external_asm" = x"yes"; then
  AC_DEFINE(HSK_USE_EXTERNAL_ASM, 1,
    [Define this symbol if an external assembly implementation is used])
fi

dnl Find libunbound, and define LIB_UNBOUND/INC_UNBOUND for hnsd.
dnl Don't add these to the default libs/includes, they're not needed by the
dnl other targets.
case $libunbound_path in
  no)
    AC_MSG_ERROR([libunbound is required])
    ;;
  yes)
    AC_CHECK_LIB(unbound, ub_ctx_create, LIB_UNBOUND="-lunbound",
      AC_MSG_ERROR([Unable to find libunbound]))
    AC_CHECK_HEADER(unbound.h, INC_UNBOUND="",
      AC_MSG_ERROR([Unable to found unbound.h]))
    ;;
  *)
    LIB_UNBOUND="-L${libunbound_path}/lib -lunbound"
    INC_UNBOUND="-I${libunbound_path}/include"
    ;;
esac
AC_SUBST(LIB_UNBOUND, ${LIB_UNBOUND})
AC_SUBST(INC_UNBOUND, ${INC_UNBOUND})

dnl Platform-specific libraries
case "${host_os}" in
  mingw*)
    AC_SUBST(LIB_WINBCRYPT, "-lbcrypt")
    ;;
esac

AC_MSG_NOTICE([Using endomorphism optimizations: $use_endomorphism])
AC_MSG_NOTICE([Using static precomputation: $use_precomp])
AC_MSG_NOTICE([Using assembly optimizations: $set_asm])
AC_MSG_NOTICE([Using field implementation: $set_field])
AC_MSG_NOTICE([Using scalar implementation: $set_scalar])
AC_MSG_NOTICE([Linker flags for libunbound: $LIB_UNBOUND])
AC_MSG_NOTICE([Compiler flags for libunbound: $INC_UNBOUND])

AM_CONDITIONAL(
  [HSK_USE_ECMULT_STATIC_PRECOMPUTATION],
  [test x"$use_precomp" = x"yes"])

AM_CONDITIONAL([HSK_USE_EXTERNAL_ASM], [test x"$use_external_asm" = x"yes"])
AM_CONDITIONAL([HSK_USE_ASM_ARM], [test x"$set_asm" = x"arm"])

dnl
dnl /Secp256k1
dnl

AC_OUTPUT
