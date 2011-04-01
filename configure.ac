AC_INIT([mfcuk], [0.3.2], [zveriu@gmail.com])

AC_CONFIG_MACRO_DIR([m4])

AC_PROG_CC

AC_CONFIG_HEADERS([config.h])

AM_INIT_AUTOMAKE

m4_ifdef([AM_SILENT_RULES],[AM_SILENT_RULES([yes])])

# Checks for libnfc.
WITH_NFC=0
## Search libnfc with command line option (default prefix: auto)
LIBNFC_PREFIX="auto"
AC_ARG_WITH(libnfc,[--with-libnfc=DIR     	location of the libnfc],
	[if test "$withval" != no; then
		if test "$withval" != yes; then
			LIBNFC_PREFIX=$withval
		fi
	 fi])
if test x"$LIBNFC_PREFIX" != "xauto"; then
  LIBNFC_CFLAGS="-L$LIBNFC_PREFIX/lib/ -I$LIBNFC_PREFIX/include/"
  LIBNFC_LIBS="-lnfc"
fi

# Search using pkg-config
AC_PATH_PROG(PKG_CONFIG, pkg-config, [AC_MSG_WARN([pkg-config not found.])])
if test x"$WITH_NFC" = "x0"; then
  if test x"$PKG_CONFIG" != "x"; then
    LIBNFC_REQUIRED_VERSION=1.4.2
    PKG_CHECK_MODULES([LIBNFC], [libnfc >= $LIBNFC_REQUIRED_VERSION], [WITH_NFC=1], [WITH_NFC=0])
  fi
fi
CFLAGS="$CFLAGS $LIBNFC_CFLAGS"
AC_CHECK_HEADERS([nfc/nfc.h],[WITH_NFC=1], AC_MSG_ERROR([A version of libnfc greater than or equal to $LIBNFC_REQUIRED_VERSION is required]))

if test x"$WITH_NFC" = "x0"; then
  AC_MSG_ERROR([A version of libnfc greater than or equal to $LIBNFC_REQUIRED_VERSION is required.])
fi

# Checks for programs.
AC_PROG_CC

# Checks for libraries.
AC_CHECK_LIB([nfc], [nfc_version])

# Checks for header files.
AC_CHECK_HEADERS([byteswap.h])
AC_CHECK_HEADERS([endian.h sys/endian.h CoreFoundation/CoreFoundation.h])
AC_CHECK_HEADERS([stdint.h stdlib.h string.h sys/time.h unistd.h])

AC_DEFINE(_XOPEN_SOURCE, 600, [Enable POSIX extensions if present])

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL
AC_TYPE_SIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_CHECK_FUNCS([memset strchr])

# Help us to write great code ;-)
CFLAGS="$CFLAGS -Wall -pedantic -Wextra -std=c99"

AC_CONFIG_FILES([Makefile
                 src/Makefile])
AC_OUTPUT
