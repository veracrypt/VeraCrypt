#ifndef HAD_CONFIG_H
#define HAD_CONFIG_H
#ifndef _HAD_ZIPCONF_H
#include "zipconf.h"
#endif
/* BEGIN DEFINES */
#define ENABLE_FDOPEN
/* #undef HAVE___PROGNAME */
#define HAVE__CLOSE
#define HAVE__DUP
#define HAVE__FDOPEN
#define HAVE__FILENO
#define HAVE__SETMODE
#if defined(_MSC_VER) && _MSC_VER < 1900
#define HAVE__SNPRINTF
#else
/* #undef HAVE__SNPRINTF */
#endif
#define HAVE__SNPRINTF_S
#define HAVE__SNWPRINTF_S
#define HAVE__STRDUP
#define HAVE__STRICMP
#define HAVE__STRTOI64
#define HAVE__STRTOUI64
#define HAVE__UNLINK
/* #undef HAVE_ARC4RANDOM */
/* #undef HAVE_CLONEFILE */
/* #undef HAVE_COMMONCRYPTO */
#define HAVE_CRYPTO
/* #undef HAVE_FICLONERANGE */
#define HAVE_FILENO
/* #undef HAVE_FCHMOD */
/* #undef HAVE_FSEEKO */
/* #undef HAVE_FTELLO */
/* #undef HAVE_GETPROGNAME */
/* #undef HAVE_GNUTLS */
/* #undef HAVE_LIBBZ2 */
/* #undef HAVE_LIBLZMA */
/* #undef HAVE_LIBZSTD */
/* #undef HAVE_LOCALTIME_R */
#define HAVE_LOCALTIME_S
#define HAVE_MEMCPY_S
/* #undef HAVE_MBEDTLS */
/* #undef HAVE_MKSTEMP */
/* #undef HAVE_NULLABLE */
/* #undef HAVE_OPENSSL */
#define HAVE_SETMODE
#if defined(_MSC_VER) && _MSC_VER < 1900
/* #undef HAVE_SNPRINTF */
#else
#define HAVE_SNPRINTF
#endif
/* #undef HAVE_SNPRINTF_S */
/* #undef HAVE_STRCASECMP */
#define HAVE_STRDUP
#define HAVE_STRERROR_S
/* #undef HAVE_STRERRORLEN_S */
#define HAVE_STRICMP
#define HAVE_STRNCPY_S
#if defined(_MSC_VER) && _MSC_VER < 1800
/* #undef HAVE_STRTOLL */
/* #undef HAVE_STRTOULL */
#else
#define HAVE_STRTOLL
#define HAVE_STRTOULL
#endif
/* #undef HAVE_STRUCT_TM_TM_ZONE */
#if defined(_MSC_VER) && _MSC_VER < 1800
/* #undef HAVE_STDBOOL_H */
#else
#define HAVE_STDBOOL_H
#endif
/* #undef HAVE_STRINGS_H */
/* #undef HAVE_UNISTD_H */
#define HAVE_WINDOWS_CRYPTO
#define SIZEOF_OFF_T 4
#ifdef _WIN64
#define SIZEOF_SIZE_T 8
#else
#define SIZEOF_SIZE_T 4
#endif
/* #undef HAVE_DIRENT_H */
/* #undef HAVE_FTS_H */
/* #undef HAVE_NDIR_H */
/* #undef HAVE_SYS_DIR_H */
/* #undef HAVE_SYS_NDIR_H */
/* #undef WORDS_BIGENDIAN */
#define HAVE_SHARED
/* END DEFINES */
#define PACKAGE "libzip"
#define VERSION "1.10.1"

#endif /* HAD_CONFIG_H */
