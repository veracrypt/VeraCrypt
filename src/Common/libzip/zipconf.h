/*
   This file was generated automatically by C:\dev\prj\Github\VeraCrypt\src\Common\libzip\make_zip_err_str.sh
   from C:\dev\libraries\libzip\build\config.h; make changes there.
 */

#ifndef _HAD_ZIPCONF_H
#define _HAD_ZIPCONF_H

extern const char * const _zip_err_str[];

extern const int _zip_nerr_str;

#define N ZIP_ET_NONE
#define S ZIP_ET_SYS
#define Z ZIP_ET_ZLIB

extern const int _zip_err_type[];


typedef signed char zip_int8_t;
typedef unsigned char zip_uint8_t;
typedef signed short zip_int16_t;
typedef unsigned short zip_uint16_t;
typedef signed int zip_int32_t;
typedef unsigned int zip_uint32_t;
typedef signed long long zip_int64_t;
typedef unsigned long long zip_uint64_t;

#define ZIP_INT8_MIN	-0x80
#define ZIP_INT8_MAX	 0x7f
#define ZIP_UINT8_MAX	 0xff

#define ZIP_INT16_MIN	-0x8000
#define ZIP_INT16_MAX	 0x7fff
#define ZIP_UINT16_MAX	 0xffff

#define ZIP_INT32_MIN	-0x80000000L
#define ZIP_INT32_MAX	 0x7fffffffL
#define ZIP_UINT32_MAX	 0xffffffffLU

#define ZIP_INT64_MIN	 (-ZIP_INT64_MAX-1LL)
#define ZIP_INT64_MAX	 0x7fffffffffffffffLL
#define ZIP_UINT64_MAX	 0xffffffffffffffffULL

#endif /* zipconf.h */

