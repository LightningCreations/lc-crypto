AC_INIT

AC_CONFIG_MACRO_DIRS([m4/])

AC_CANONICAL_HOST

AC_PROG_CC

AC_PROG_INSTALL

LCRUST_PROG_RUSTC
LCRUST_RUSTC_VERSION

AC_ARG_ENABLE([native-instructions],[Generate code for the current system, or set the system to target.],[
    case x$enableval in
        xyes )
            RUSTFLAGS="$RUSTFLAGS -C target-cpu=native"
            ;;
        xno )
            ;;
        x* )
            RUSTFLAGS="$RUSTFLAGS -C target-cpu=$enableval"
            ;;
        esac
],[
    RUSTFLAGS="$RUSTFLAGS -C target-cpu=native"
])

AC_ARG_ENABLE([hardware-random],[Force use of the hardware random generator if it is available, even if unset],[
    if x$enableval \= xyes
    then
        RUSTFLAGS="$RUSTFLAGS --cfg feature=\"hardware-rand\""
    fi
])

LCRUST_CHECK_EDITION([2018],[
    AC_MSG_ERROR([lc-crypto requires rust edition 2018])
])

AC_MSG_CHECKING([what the host system is])
AC_MSG_RESULT([$host_os])

# case x$host_os in
#     xlinux* )
#         libc=libc
#         AC_CONFIG_SUBDIRS([vendor/libc])
#     ;;
#     * )
#     ;;
# esac

AC_SUBST([libc])

AC_CONFIG_SUBDIRS([vendor/bytemuck vendor/zeroize])
AC_CONFIG_FILES([Makefile])

AC_OUTPUT