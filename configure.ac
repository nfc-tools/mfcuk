AC_INIT([mfcuk], [0.3.8], [zveriu@gmail.com])

AM_INIT_AUTOMAKE

AC_PROG_CC

AC_CONFIG_HEADERS([config.h])

m4_ifdef([AM_SILENT_RULES],[AM_SILENT_RULES([yes])])

# Checks for pkg-config modules.
LIBNFC_REQUIRED_VERSION=1.7.0
PKG_CHECK_MODULES([libnfc], [libnfc >= $LIBNFC_REQUIRED_VERSION], [], [AC_MSG_ERROR([libnfc >= $LIBNFC_REQUIRED_VERSION is mandatory.])])

PKG_CONFIG_REQUIRES="libnfc"
AC_SUBST([PKG_CONFIG_REQUIRES])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_INLINE
AC_HEADER_STDBOOL
AC_TYPE_SIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_REALLOC

AC_CHECK_FUNCS([memset strchr strtoul])

# Checks for endianness convertion
AC_CHECK_HEADERS([endian.h sys/endian.h CoreFoundation/CoreFoundation.h])
if test $ac_cv_header_endian_h = "no" -a $ac_cv_header_sys_endian_h = "no" -a $ac_cv_header_CoreFoundation_CoreFoundation_h = "no"; then
  AC_MSG_ERROR(["Can't locate usable header file for endianness convertions."]);
fi

AC_CHECK_HEADERS([byteswap.h])

AC_CHECK_HEADERS([unistd.h])
AM_CONDITIONAL([HAVE_UNISTD], [test $ac_cv_header_unistd_h = "yes"])

AC_DEFINE([_XOPEN_SOURCE], [600], [Define to 500 if Single Unix conformance is wanted, 600 for sixth revision.])

# Help us to write great code ;-)
CFLAGS="$CFLAGS -Wall -pedantic -Wextra -std=c99"

AC_CONFIG_FILES([Makefile
                 src/Makefile])
AC_OUTPUT
