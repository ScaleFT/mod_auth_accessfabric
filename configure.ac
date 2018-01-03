
AC_PREREQ([2.69])
AC_INIT([mod_auth_accessfabric], [1.0.1])
AC_CONFIG_MACRO_DIRS([m4])
AC_CONFIG_SRCDIR([src/mod_auth_accessfabric.c])
AM_INIT_AUTOMAKE([subdir-objects foreign])

AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_MAKE_SET

LT_INIT
AC_SUBST([LIBTOOL_DEPS])

AC_CHECK_HEADERS([malloc.h stddef.h stdint.h stdlib.h string.h])

AC_TYPE_SIZE_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T

AC_FUNC_MALLOC
AC_CHECK_FUNCS([memset setenv strdup strrchr])

AX_WITH_APXS()

if test "x${APXS}" = "x"; then
    AC_MSG_ERROR("apxs not found. apache2-dev is required to build.")
fi

AC_SUBST(APXS)

AC_MSG_NOTICE([Found APXS=$APXS])

LIBEXEC_DIR=$($APXS -q LIBEXECDIR)
AC_MSG_NOTICE([Reading from apxs: LIBEXEC_DIR=$LIBEXEC_DIR (module installation path)])
AC_SUBST(LIBEXEC_DIR)

APR_CONFIG=$($APXS -q APR_CONFIG)
AC_MSG_NOTICE([Reading from apxs: APR_CONFIG=$APR_CONFIG])
APU_CONFIG=$($APXS -q APU_CONFIG)
AC_MSG_NOTICE([Reading from apxs: APU_CONFIG=$APU_CONFIG])

APXS_LIBDIR=$($APXS -q libdir)
AC_MSG_NOTICE([Reading from apxs: APXS_LIBDIR=$APXS_LIBDIR])

APXS_INCLUDEDIR=$($APXS -q includedir)
AC_MSG_NOTICE([Reading from apxs: APXS_INCLUDEDIR=$APXS_INCLUDEDIR])

APR_CPPFLAGS=$(${APR_CONFIG} --cflags --cppflags --includes)
APU_CPPFLAGS=$(${APU_CONFIG} --includes)
APXS_EXTRA_CFLAGS=$(${APXS} -q EXTRA_CFLAGS)
APXS_EXTRA_CPPFLAGS=$(${APXS} -q EXTRA_CPPFLAGS)

HTTPD_CPPFLAGS="${APR_CPPFLAGS} ${APU_CPPFLAGS} ${APXS_EXTRA_CFLAGS} ${APXS_EXTRA_CPPFLAGS}"
AC_MSG_NOTICE([Reading from apxs: HTTPD_CPPFLAGS=$HTTPD_CPPFLAGS])

LDFLAGS="$LDFLAGS -L$APXS_LIBDIR"
CPPFLAGS="$CPPFLAGS -I$APXS_INCLUDEDIR ${HTTPD_CPPFLAGS}"

AX_CHECK_OPENSSL(
  [have_openssl=yes],
  [AC_MSG_ERROR([OpenSSL is required])]
)

if test "x$have_openssl" = "xyes"; then
  LIBS="$LIBS $OPENSSL_LIBS"
  CFLAGS="$CFLAGS $OPENSSL_INCLUDES"
  LDFLAGS="$LDFLAGS $OPENSSL_LDFLAGS"
fi

AC_CHECK_LIB([crypto],[EVP_PKEY_free], [], [AC_MSG_ERROR([OpenSSL libraries required])])
AC_CHECK_HEADERS([openssl/evp.h],[],[AC_MSG_ERROR([OpenSSL headers required])])

AC_ARG_WITH([jansson],
    [AS_HELP_STRING([--with-jansson=DIR],
    [Path to Jansson])],
    [with_jansson=$withval],
    [])

AS_IF([test "x$with_jansson" != "x"],
    [AC_MSG_NOTICE([Found --with-jansson=${with_jansson}])])

AS_IF([test "x$with_jansson" != "x"],
    [CPPFLAGS="$CPPFLAGS -I${with_jansson}/include"])
AS_IF([test "x$with_jansson" != "x"],
    [LDFLAGS="$LDFLAGS -L${with_jansson}/lib -Wl,-rpath,${with_jansson}/lib"])

AX_CHECK_LIBRARY([JANSSON],[jansson.h],[jansson], [],
    [AC_MSG_ERROR([Unable to find libjansson])])

if test "x$ax_cv_have_JANSSON" = "xyes"; then
  CFLAGS="$CFLAGS $JANSSON_CPPFLAGS"
  LDFLAGS="$LDFLAGS $JANSSON_LDFLAGS"
fi
AC_CHECK_LIB([jansson],[json_true], [], [AC_MSG_ERROR([Jansson libraries required. Try adding --with-jansson=DIR])])

AC_ARG_WITH([curl],
    [AS_HELP_STRING([--with-curl=DIR],
    [Path to curl])],
    [with_curl=$withval],
    [])

AS_IF([test "x$with_curl" != "x"],
    [AC_MSG_NOTICE([Found --with-curl=${with_curl}])])

AS_IF([test "x$with_curl" != "x"],
    [CPPFLAGS="$CPPFLAGS -I${with_curl}/include"])
AS_IF([test "x$with_curl" != "x"],
    [LDFLAGS="$LDFLAGS -L${with_curl}/lib -Wl,-rpath,${with_curl}/lib"])

AX_CHECK_LIBRARY([CURL],[curl/curl.h],[curl], [],
    [AC_MSG_ERROR([Unable to find libcurl])])

if test "x$ax_cv_have_CURL" = "xyes"; then
  CFLAGS="$CFLAGS $CURL_CPPFLAGS"
  LDFLAGS="$LDFLAGS $CURL_LDFLAGS"
fi
AC_CHECK_LIB([curl],[curl_version], [], [AC_MSG_ERROR([curl libraries required. Try adding --with-curl=DIR])])


AC_ARG_WITH([xjwt],
    [AS_HELP_STRING([--with-xjwt=DIR],
    [Path to libxjwt])],
    [with_xjwt=$withval],
    [])

AS_IF([test "x$with_jansson" != "x"],
    [AC_MSG_NOTICE([Found --with-xjwt=${with_xjwt}/])])

AS_IF([test "x$with_xjwt" != "x"],
    [CPPFLAGS="$CPPFLAGS -I${with_xjwt}/include"])
AS_IF([test "x$with_xjwt" != "x"],
    [LDFLAGS="$LDFLAGS -L${with_xjwt}/lib -Wl,-rpath,${with_xjwt}/lib"])

AX_CHECK_LIBRARY([XJWT],[xjwt/xjwt.h],[xjwt], [],
    [AC_MSG_ERROR([Unable to find libxjwt.  Try adding --with-xjwt=DIR])])

if test "x$ax_cv_have_XJWT" = "xyes"; then
  CFLAGS="$CFLAGS $XJWT_CPPFLAGS"
  LDFLAGS="$LDFLAGS $XJWT_LDFLAGS"
fi
AC_CHECK_LIB([xjwt],[xjwt_keyset_destroy], [], [AC_MSG_ERROR([libxjwt libraries required])])

AC_CONFIG_FILES([Makefile])
AC_CONFIG_HEADERS(src/autoconf_config.h)
AC_OUTPUT
