dnl Process this file with autoconf to produce a configure script.

AC_PREREQ(2.59)
AC_INIT(dv2sub, 0.3, http://dv2sub.sourceforge.net/)
AC_CONFIG_AUX_DIR(autotools)
AC_CONFIG_SRCDIR(src/dv2sub.c)
AM_CONFIG_HEADER(src/config.h)
AM_INIT_AUTOMAKE(AC_PACKAGE_NAME, AC_PACKAGE_VERSION)

dnl Checks for programs.
AC_PROG_CC
test "x$GCC" = "xyes" && C99MODE_FLAG="-std=c99"
AC_SUBST(C99MODE_FLAG)
AM_PROG_CC_STDC
AC_C_BIGENDIAN
AC_PROG_INSTALL

dnl Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS(fcntl.h unistd.h stdio.h time.h)

dnl Checks for libraries.
PKG_CHECK_MODULES(LIBDV, libdv >= 0.103,
        [
                AC_DEFINE(HAVE_LIBDV, 1, [Define to 1 if you have libdv.])
                AC_SUBST(LIBDV_CFLAGS)
                AC_SUBST(LIBDV_LIBS)
        ],
        [AC_MSG_ERROR([libdv not installed; libdv 0.103 or newer needed.])]
)
PKG_CHECK_MODULES(LIBSQLITE, sqlite3 >= 3.0,
        [
                AC_DEFINE(HAVE_LIBSQLITE, 1, [Define to 1 if you have libsqlite3.])
                AC_SUBST(LIBSQLITE_CFLAGS)
                AC_SUBST(LIBSQLITE_LIBS)
        ],
        [AC_MSG_ERROR([libsqlite not installed; libsqlite 3.0 or newer needed.])]
)
PKG_CHECK_MODULES(LIBSSL, libssl >= 0.9,
        [
                AC_DEFINE(HAVE_LIBSSL, 1, [Define to 1 if you have libssl.])
                AC_SUBST(LIBSSL_CFLAGS)
                AC_SUBST(LIBSSL_LIBS)
        ],
        [AC_MSG_ERROR([libssl not installed; libssl 0.9 or newer needed.])]
)

dnl Checks for typedefs, structures, and compiler characteristics.
AC_MSG_CHECKING([whether compiler accepts some C99 extensions])
save_CFLAGS="$CFLAGS"
CFLAGS="$C99MODE_FLAG"
AC_TRY_COMPILE(,
	[void foo(void) { for(int i=0; i<10; i++) {} }],
	[AC_MSG_RESULT(yes)],
	[c99_fail=1
	AC_MSG_RESULT(no)])
if test "x$c99_fail" = "x1"
then
    AC_MSG_ERROR(ANSI/ISO C99 compiler not found or not in this mode!)
fi
CFLAGS="$save_CFLAGS"

dnl Arrange for large-file support
AC_SYS_LARGEFILE

dnl Checks for library functions.
AC_FUNC_MMAP
AC_CHECK_FUNC([strptime], [], [AC_MSG_ERROR([strptime() is required])])

AC_OUTPUT(Makefile
	src/Makefile
	doc/Makefile)
