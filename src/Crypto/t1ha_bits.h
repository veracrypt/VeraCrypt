/*
 *  Copyright (c) 2016-2018 Positive Technologies, https://www.ptsecurity.com,
 *  Fast Positive Hash.
 *
 *  Portions Copyright (c) 2010-2018 Leonid Yuriev <leo@yuriev.ru>,
 *  The 1Hippeus project (t1h).
 *
 *  This software is provided 'as-is', without any express or implied
 *  warranty. In no event will the authors be held liable for any damages
 *  arising from the use of this software.
 *
 *  Permission is granted to anyone to use this software for any purpose,
 *  including commercial applications, and to alter it and redistribute it
 *  freely, subject to the following restrictions:
 *
 *  1. The origin of this software must not be misrepresented; you must not
 *     claim that you wrote the original software. If you use this software
 *     in a product, an acknowledgement in the product documentation would be
 *     appreciated but is not required.
 *  2. Altered source versions must be plainly marked as such, and must not be
 *     misrepresented as being the original software.
 *  3. This notice may not be removed or altered from any source distribution.
 */

/*
 * t1ha = { Fast Positive Hash, aka "Позитивный Хэш" }
 * by [Positive Technologies](https://www.ptsecurity.ru)
 *
 * Briefly, it is a 64-bit Hash Function:
 *  1. Created for 64-bit little-endian platforms, in predominantly for x86_64,
 *     but portable and without penalties it can run on any 64-bit CPU.
 *  2. In most cases up to 15% faster than City64, xxHash, mum-hash, metro-hash
 *     and all others portable hash-functions (which do not use specific
 *     hardware tricks).
 *  3. Not suitable for cryptography.
 *
 * The Future will Positive. Всё будет хорошо.
 *
 * ACKNOWLEDGEMENT:
 * The t1ha was originally developed by Leonid Yuriev (Леонид Юрьев)
 * for The 1Hippeus project - zerocopy messaging in the spirit of Sparta!
 */

#pragma once

#if defined(_MSC_VER)
#pragma warning(disable : 4201) /* nameless struct/union */
#if _MSC_VER > 1800
#pragma warning(disable : 4464) /* relative include path contains '..' */
#endif                          /* 1800 */
#endif                          /* MSVC */
#include "t1ha.h"

#ifndef T1HA_USE_FAST_ONESHOT_READ
/* Define it to 1 for little bit faster code.
 * Unfortunately this may triggering a false-positive alarms from Valgrind,
 * AddressSanitizer and other similar tool.
 * So, define it to 0 for calmness if doubt. */
#define T1HA_USE_FAST_ONESHOT_READ 1
#endif /* T1HA_USE_FAST_ONESHOT_READ */

/*****************************************************************************/

#include <assert.h>  /* for assert() */
#include <string.h>  /* for memcpy() */

#if __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__ &&                               \
    __BYTE_ORDER__ != __ORDER_BIG_ENDIAN__
#error Unsupported byte order.
#endif

#define T1HA_UNALIGNED_ACCESS__UNABLE 0
#define T1HA_UNALIGNED_ACCESS__SLOW 1
#define T1HA_UNALIGNED_ACCESS__EFFICIENT 2

#ifndef T1HA_SYS_UNALIGNED_ACCESS
#if defined(CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS)
#define T1HA_SYS_UNALIGNED_ACCESS T1HA_UNALIGNED_ACCESS__EFFICIENT
#elif defined(__ia32__)
#define T1HA_SYS_UNALIGNED_ACCESS T1HA_UNALIGNED_ACCESS__EFFICIENT
#elif defined(__e2k__)
#define T1HA_SYS_UNALIGNED_ACCESS T1HA_UNALIGNED_ACCESS__SLOW
#elif defined(__ARM_FEATURE_UNALIGNED)
#define T1HA_SYS_UNALIGNED_ACCESS T1HA_UNALIGNED_ACCESS__EFFICIENT
#else
#define T1HA_SYS_UNALIGNED_ACCESS T1HA_UNALIGNED_ACCESS__UNABLE
#endif
#endif /* T1HA_SYS_UNALIGNED_ACCESS */

#define ALIGNMENT_16 2
#define ALIGNMENT_32 4
#if UINTPTR_MAX > 0xffffFFFFul || ULONG_MAX > 0xffffFFFFul
#define ALIGNMENT_64 8
#else
#define ALIGNMENT_64 4
#endif

#ifndef PAGESIZE
#define PAGESIZE 4096
#endif /* PAGESIZE */

/***************************************************************************/

#ifndef __has_builtin
#define __has_builtin(x) (0)
#endif

#ifndef __has_warning
#define __has_warning(x) (0)
#endif

#ifndef __has_feature
#define __has_feature(x) (0)
#endif

#ifndef __has_extension
#define __has_extension(x) (0)
#endif

#ifndef __has_attribute
#define __has_attribute(x) (0)
#endif

#if __has_feature(address_sanitizer)
#define __SANITIZE_ADDRESS__ 1
#endif

#ifndef __optimize
#if defined(__clang__) && !__has_attribute(optimize)
#define __optimize(ops)
#elif defined(__GNUC__) || __has_attribute(optimize)
#define __optimize(ops) __attribute__((optimize(ops)))
#else
#define __optimize(ops)
#endif
#endif /* __optimize */

#ifndef __cold
#if defined(__OPTIMIZE__)
#if defined(__e2k__)
#define __cold __optimize(1) __attribute__((cold))
#elif defined(__clang__) && !__has_attribute(cold)
/* just put infrequently used functions in separate section */
#define __cold __attribute__((section("text.unlikely"))) __optimize("Os")
#elif defined(__GNUC__) || __has_attribute(cold)
#define __cold __attribute__((cold)) __optimize("Os")
#else
#define __cold __optimize("Os")
#endif
#else
#define __cold
#endif
#endif /* __cold */


#if defined(_MSC_VER)

#pragma warning(push, 1)

#include <stdlib.h>
#define likely(cond) (cond)
#define unlikely(cond) (cond)
#define unreachable() __assume(0)
#define bswap64(v) byteswap_64(v)
#define bswap32(v) byteswap_32(v)
#define bswap16(v) byteswap_16(v)
#define rot64(v, s) rotr64(v, s)
#define rot32(v, s) rotr32(v, s)
#define __always_inline __forceinline

#ifdef TC_WINDOWS_DRIVER
#undef assert
#define assert ASSERT
#endif

#if defined(_M_X64) || defined(_M_IA64)
#pragma intrinsic(_umul128)
#define mul_64x64_128(a, b, ph) _umul128(a, b, ph)
#endif

#if defined(_M_ARM64) || defined(_M_X64) || defined(_M_IA64)
#pragma intrinsic(__umulh)
#define mul_64x64_high(a, b) __umulh(a, b)
#endif

#pragma warning(pop)
#pragma warning(disable : 4514) /* 'xyz': unreferenced inline function         \
                                   has been removed */
#pragma warning(disable : 4710) /* 'xyz': function not inlined */
#pragma warning(disable : 4711) /* function 'xyz' selected for                 \
                                   automatic inline expansion */
#pragma warning(disable : 4127) /* conditional expression is constant */
#pragma warning(disable : 4702) /* unreachable code */

#define __GNUC_PREREQ(a,b) 0
#ifndef UINT64_C
#define UINT64_C(value)   value ## ULL
#endif

#endif                          /* Compiler */

#ifndef likely
#define likely(cond) (cond)
#endif
#ifndef unlikely
#define unlikely(cond) (cond)
#endif
#ifndef __maybe_unused
#define __maybe_unused
#endif
#ifndef __always_inline
#define __always_inline __inline
#endif
#ifndef unreachable
#define unreachable()                                                          \
  do {                                                                         \
  } while (1)
#endif



#ifndef read_unaligned
#if defined(__GNUC__) || __has_attribute(packed)
typedef struct {
  uint8_t unaligned_8;
  uint16_t unaligned_16;
  uint32_t unaligned_32;
  uint64_t unaligned_64;
} __attribute__((packed)) t1ha_unaligned_proxy;
#define read_unaligned(ptr, bits)                                              \
  (((const t1ha_unaligned_proxy *)((const uint8_t *)(ptr)-offsetof(            \
        t1ha_unaligned_proxy, unaligned_##bits)))                              \
       ->unaligned_##bits)
#elif defined(_MSC_VER)
#pragma warning(                                                               \
    disable : 4235) /* nonstandard extension used: '__unaligned'               \
                     * keyword not supported on this architecture */
#define read_unaligned(ptr, bits) (*(const __unaligned uint##bits##_t *)(ptr))
#else
#pragma pack(push, 1)
typedef struct {
  uint8_t unaligned_8;
  uint16_t unaligned_16;
  uint32_t unaligned_32;
  uint64_t unaligned_64;
} t1ha_unaligned_proxy;
#pragma pack(pop)
#define read_unaligned(ptr, bits)                                              \
  (((const t1ha_unaligned_proxy *)((const uint8_t *)(ptr)-offsetof(            \
        t1ha_unaligned_proxy, unaligned_##bits)))                              \
       ->unaligned_##bits)
#endif
#endif /* read_unaligned */

#ifndef read_aligned
#if __GNUC_PREREQ(4, 8) || __has_builtin(__builtin_assume_aligned)
#define read_aligned(ptr, bits)                                                \
  (*(const uint##bits##_t *)__builtin_assume_aligned(ptr, ALIGNMENT_##bits))
#elif (__GNUC_PREREQ(3, 3) || __has_attribute(aligned)) && !defined(__clang__)
#define read_aligned(ptr, bits)                                                \
  (*(const uint##bits##_t __attribute__((aligned(ALIGNMENT_##bits))) *)(ptr))
#elif __has_attribute(assume_aligned)

static __always_inline const
    uint16_t *__attribute__((assume_aligned(ALIGNMENT_16)))
    cast_aligned_16(const void *ptr) {
  return (const uint16_t *)ptr;
}
static __always_inline const
    uint32_t *__attribute__((assume_aligned(ALIGNMENT_32)))
    cast_aligned_32(const void *ptr) {
  return (const uint32_t *)ptr;
}
static __always_inline const
    uint64_t *__attribute__((assume_aligned(ALIGNMENT_64)))
    cast_aligned_64(const void *ptr) {
  return (const uint64_t *)ptr;
}

#define read_aligned(ptr, bits) (*cast_aligned_##bits(ptr))

#elif defined(_MSC_VER)
#define read_aligned(ptr, bits)                                                \
  (*(const __declspec(align(ALIGNMENT_##bits)) uint##bits##_t *)(ptr))
#else
#define read_aligned(ptr, bits) (*(const uint##bits##_t *)(ptr))
#endif
#endif /* read_aligned */

#ifndef prefetch
#if (__GNUC_PREREQ(4, 0) || __has_builtin(__builtin_prefetch)) &&              \
    !defined(__ia32__)
#define prefetch(ptr) __builtin_prefetch(ptr)
#elif defined(_M_ARM64) || defined(_M_ARM)
#define prefetch(ptr) __prefetch(ptr)
#else
#define prefetch(ptr)                                                          \
  do {                                                                         \
    (void)(ptr);                                                               \
  } while (0)
#endif
#endif /* prefetch */

#if __has_warning("-Wconstant-logical-operand")
#if defined(__clang__)
#pragma clang diagnostic ignored "-Wconstant-logical-operand"
#elif defined(__GNUC__)
#pragma GCC diagnostic ignored "-Wconstant-logical-operand"
#else
#pragma warning disable "constant-logical-operand"
#endif
#endif /* -Wconstant-logical-operand */

#if __has_warning("-Wtautological-pointer-compare")
#if defined(__clang__)
#pragma clang diagnostic ignored "-Wtautological-pointer-compare"
#elif defined(__GNUC__)
#pragma GCC diagnostic ignored "-Wtautological-pointer-compare"
#else
#pragma warning disable "tautological-pointer-compare"
#endif
#endif /* -Wtautological-pointer-compare */

/***************************************************************************/

#if __GNUC_PREREQ(4, 0)
#pragma GCC visibility push(hidden)
#endif /* __GNUC_PREREQ(4,0) */

/*---------------------------------------------------------- Little Endian */

#ifndef fetch16_le_aligned
static __always_inline uint16_t fetch16_le_aligned(const void *v) {
  assert(((uintptr_t)v) % ALIGNMENT_16 == 0);
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
  return read_aligned(v, 16);
#else
  return bswap16(read_aligned(v, 16));
#endif
}
#endif /* fetch16_le_aligned */

#ifndef fetch16_le_unaligned
static __always_inline uint16_t fetch16_le_unaligned(const void *v) {
#if T1HA_SYS_UNALIGNED_ACCESS == T1HA_UNALIGNED_ACCESS__UNABLE
  const uint8_t *p = (const uint8_t *)v;
  return p[0] | (uint16_t)p[1] << 8;
#elif __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
  return read_unaligned(v, 16);
#else
  return bswap16(read_unaligned(v, 16));
#endif
}
#endif /* fetch16_le_unaligned */

#ifndef fetch32_le_aligned
static __always_inline uint32_t fetch32_le_aligned(const void *v) {
  assert(((uintptr_t)v) % ALIGNMENT_32 == 0);
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
  return read_aligned(v, 32);
#else
  return bswap32(read_aligned(v, 32));
#endif
}
#endif /* fetch32_le_aligned */

#ifndef fetch32_le_unaligned
static __always_inline uint32_t fetch32_le_unaligned(const void *v) {
#if T1HA_SYS_UNALIGNED_ACCESS == T1HA_UNALIGNED_ACCESS__UNABLE
  return fetch16_le_unaligned(v) |
         (uint32_t)fetch16_le_unaligned((const uint8_t *)v + 2) << 16;
#elif __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
  return read_unaligned(v, 32);
#else
  return bswap32(read_unaligned(v, 32));
#endif
}
#endif /* fetch32_le_unaligned */

#ifndef fetch64_le_aligned
static __always_inline uint64_t fetch64_le_aligned(const void *v) {
  assert(((uintptr_t)v) % ALIGNMENT_64 == 0);
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
  return read_aligned(v, 64);
#else
  return bswap64(read_aligned(v, 64));
#endif
}
#endif /* fetch64_le_aligned */

#ifndef fetch64_le_unaligned
static __always_inline uint64_t fetch64_le_unaligned(const void *v) {
#if T1HA_SYS_UNALIGNED_ACCESS == T1HA_UNALIGNED_ACCESS__UNABLE
  return fetch32_le_unaligned(v) |
         (uint64_t)fetch32_le_unaligned((const uint8_t *)v + 4) << 32;
#elif __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
  return read_unaligned(v, 64);
#else
  return bswap64(read_unaligned(v, 64));
#endif
}
#endif /* fetch64_le_unaligned */

static __always_inline uint64_t tail64_le_aligned(const void *v, size_t tail) {
  const uint8_t *const p = (const uint8_t *)v;
#if T1HA_USE_FAST_ONESHOT_READ && !defined(__SANITIZE_ADDRESS__)
  /* We can perform a 'oneshot' read, which is little bit faster. */
  const unsigned shift = ((8 - tail) & 7) << 3;
  return fetch64_le_aligned(p) & ((~UINT64_C(0)) >> shift);
#else
  uint64_t r = 0;
  switch (tail & 7) {
  default:
    unreachable();
/* fall through */
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
  /* For most CPUs this code is better when not needed byte reordering. */
  case 0:
    return fetch64_le_aligned(p);
  case 7:
    r = (uint64_t)p[6] << 8;
  /* fall through */
  case 6:
    r += p[5];
    r <<= 8;
  /* fall through */
  case 5:
    r += p[4];
    r <<= 32;
  /* fall through */
  case 4:
    return r + fetch32_le_aligned(p);
  case 3:
    r = (uint64_t)p[2] << 16;
  /* fall through */
  case 2:
    return r + fetch16_le_aligned(p);
  case 1:
    return p[0];
#else
  case 0:
    r = p[7] << 8;
  /* fall through */
  case 7:
    r += p[6];
    r <<= 8;
  /* fall through */
  case 6:
    r += p[5];
    r <<= 8;
  /* fall through */
  case 5:
    r += p[4];
    r <<= 8;
  /* fall through */
  case 4:
    r += p[3];
    r <<= 8;
  /* fall through */
  case 3:
    r += p[2];
    r <<= 8;
  /* fall through */
  case 2:
    r += p[1];
    r <<= 8;
  /* fall through */
  case 1:
    return r + p[0];
#endif
  }
#endif /* T1HA_USE_FAST_ONESHOT_READ */
}

#if T1HA_USE_FAST_ONESHOT_READ &&                                              \
    T1HA_SYS_UNALIGNED_ACCESS != T1HA_UNALIGNED_ACCESS__UNABLE &&              \
    defined(PAGESIZE) && PAGESIZE > 42 && !defined(__SANITIZE_ADDRESS__)
#define can_read_underside(ptr, size)                                          \
  (((PAGESIZE - (size)) & (uintptr_t)(ptr)) != 0)
#endif /* T1HA_USE_FAST_ONESHOT_READ */

static __always_inline uint64_t tail64_le_unaligned(const void *v,
                                                    size_t tail) {
  const uint8_t *p = (const uint8_t *)v;
#if defined(can_read_underside) &&                                             \
    (UINTPTR_MAX > 0xffffFFFFul || ULONG_MAX > 0xffffFFFFul)
  /* On some systems (e.g. x86_64) we can perform a 'oneshot' read, which
   * is little bit faster. Thanks Marcin Żukowski <marcin.zukowski@gmail.com>
   * for the reminder. */
  const unsigned offset = (8 - tail) & 7;
  const unsigned shift = offset << 3;
  if (likely(can_read_underside(p, 8))) {
    p -= offset;
    return fetch64_le_unaligned(p) >> shift;
  }
  return fetch64_le_unaligned(p) & ((~UINT64_C(0)) >> shift);
#else
  uint64_t r = 0;
  switch (tail & 7) {
  default:
    unreachable();
/* fall through */
#if T1HA_SYS_UNALIGNED_ACCESS == T1HA_UNALIGNED_ACCESS__EFFICIENT &&           \
    __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
  /* For most CPUs this code is better when not needed
   * copying for alignment or byte reordering. */
  case 0:
    return fetch64_le_unaligned(p);
  case 7:
    r = (uint64_t)p[6] << 8;
  /* fall through */
  case 6:
    r += p[5];
    r <<= 8;
  /* fall through */
  case 5:
    r += p[4];
    r <<= 32;
  /* fall through */
  case 4:
    return r + fetch32_le_unaligned(p);
  case 3:
    r = (uint64_t)p[2] << 16;
  /* fall through */
  case 2:
    return r + fetch16_le_unaligned(p);
  case 1:
    return p[0];
#else
  /* For most CPUs this code is better than a
   * copying for alignment and/or byte reordering. */
  case 0:
    r = p[7] << 8;
  /* fall through */
  case 7:
    r += p[6];
    r <<= 8;
  /* fall through */
  case 6:
    r += p[5];
    r <<= 8;
  /* fall through */
  case 5:
    r += p[4];
    r <<= 8;
  /* fall through */
  case 4:
    r += p[3];
    r <<= 8;
  /* fall through */
  case 3:
    r += p[2];
    r <<= 8;
  /* fall through */
  case 2:
    r += p[1];
    r <<= 8;
  /* fall through */
  case 1:
    return r + p[0];
#endif
  }
#endif /* can_read_underside */
}

/*------------------------------------------------------------- Big Endian */

#ifndef fetch16_be_aligned
static __maybe_unused __always_inline uint16_t
fetch16_be_aligned(const void *v) {
  assert(((uintptr_t)v) % ALIGNMENT_16 == 0);
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
  return read_aligned(v, 16);
#else
  return bswap16(read_aligned(v, 16));
#endif
}
#endif /* fetch16_be_aligned */

#ifndef fetch16_be_unaligned
static __maybe_unused __always_inline uint16_t
fetch16_be_unaligned(const void *v) {
#if T1HA_SYS_UNALIGNED_ACCESS == T1HA_UNALIGNED_ACCESS__UNABLE
  const uint8_t *p = (const uint8_t *)v;
  return (uint16_t)p[0] << 8 | p[1];
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
  return read_unaligned(v, 16);
#else
  return bswap16(read_unaligned(v, 16));
#endif
}
#endif /* fetch16_be_unaligned */

#ifndef fetch32_be_aligned
static __maybe_unused __always_inline uint32_t
fetch32_be_aligned(const void *v) {
  assert(((uintptr_t)v) % ALIGNMENT_32 == 0);
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
  return read_aligned(v, 32);
#else
  return bswap32(read_aligned(v, 32));
#endif
}
#endif /* fetch32_be_aligned */

#ifndef fetch32_be_unaligned
static __maybe_unused __always_inline uint32_t
fetch32_be_unaligned(const void *v) {
#if T1HA_SYS_UNALIGNED_ACCESS == T1HA_UNALIGNED_ACCESS__UNABLE
  return (uint32_t)fetch16_be_unaligned(v) << 16 |
         fetch16_be_unaligned((const uint8_t *)v + 2);
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
  return read_unaligned(v, 32);
#else
  return bswap32(read_unaligned(v, 32));
#endif
}
#endif /* fetch32_be_unaligned */

#ifndef fetch64_be_aligned
static __maybe_unused __always_inline uint64_t
fetch64_be_aligned(const void *v) {
  assert(((uintptr_t)v) % ALIGNMENT_64 == 0);
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
  return read_aligned(v, 64);
#else
  return bswap64(read_aligned(v, 64));
#endif
}
#endif /* fetch64_be_aligned */

#ifndef fetch64_be_unaligned
static __maybe_unused __always_inline uint64_t
fetch64_be_unaligned(const void *v) {
#if T1HA_SYS_UNALIGNED_ACCESS == T1HA_UNALIGNED_ACCESS__UNABLE
  return (uint64_t)fetch32_be_unaligned(v) << 32 |
         fetch32_be_unaligned((const uint8_t *)v + 4);
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
  return read_unaligned(v, 64);
#else
  return bswap64(read_unaligned(v, 64));
#endif
}
#endif /* fetch64_be_unaligned */

static __maybe_unused __always_inline uint64_t tail64_be_aligned(const void *v,
                                                                 size_t tail) {
  const uint8_t *const p = (const uint8_t *)v;
#if T1HA_USE_FAST_ONESHOT_READ && !defined(__SANITIZE_ADDRESS__)
  /* We can perform a 'oneshot' read, which is little bit faster. */
  const unsigned shift = ((8 - tail) & 7) << 3;
  return fetch64_be_aligned(p) >> shift;
#else
  switch (tail & 7) {
  default:
    unreachable();
/* fall through */
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
  /* For most CPUs this code is better when not byte reordering. */
  case 1:
    return p[0];
  case 2:
    return fetch16_be_aligned(p);
  case 3:
    return (uint32_t)fetch16_be_aligned(p) << 8 | p[2];
  case 4:
    return fetch32_be_aligned(p);
  case 5:
    return (uint64_t)fetch32_be_aligned(p) << 8 | p[4];
  case 6:
    return (uint64_t)fetch32_be_aligned(p) << 16 | fetch16_be_aligned(p + 4);
  case 7:
    return (uint64_t)fetch32_be_aligned(p) << 24 |
           (uint32_t)fetch16_be_aligned(p + 4) << 8 | p[6];
  case 0:
    return fetch64_be_aligned(p);
#else
  case 1:
    return p[0];
  case 2:
    return p[1] | (uint32_t)p[0] << 8;
  case 3:
    return p[2] | (uint32_t)p[1] << 8 | (uint32_t)p[0] << 16;
  case 4:
    return p[3] | (uint32_t)p[2] << 8 | (uint32_t)p[1] << 16 |
           (uint32_t)p[0] << 24;
  case 5:
    return p[4] | (uint32_t)p[3] << 8 | (uint32_t)p[2] << 16 |
           (uint32_t)p[1] << 24 | (uint64_t)p[0] << 32;
  case 6:
    return p[5] | (uint32_t)p[4] << 8 | (uint32_t)p[3] << 16 |
           (uint32_t)p[2] << 24 | (uint64_t)p[1] << 32 | (uint64_t)p[0] << 40;
  case 7:
    return p[6] | (uint32_t)p[5] << 8 | (uint32_t)p[4] << 16 |
           (uint32_t)p[3] << 24 | (uint64_t)p[2] << 32 | (uint64_t)p[1] << 40 |
           (uint64_t)p[0] << 48;
  case 0:
    return p[7] | (uint32_t)p[6] << 8 | (uint32_t)p[5] << 16 |
           (uint32_t)p[4] << 24 | (uint64_t)p[3] << 32 | (uint64_t)p[2] << 40 |
           (uint64_t)p[1] << 48 | (uint64_t)p[0] << 56;
#endif
  }
#endif /* T1HA_USE_FAST_ONESHOT_READ */
}

static __maybe_unused __always_inline uint64_t
tail64_be_unaligned(const void *v, size_t tail) {
  const uint8_t *p = (const uint8_t *)v;
#if defined(can_read_underside) &&                                             \
    (UINTPTR_MAX > 0xffffFFFFul || ULONG_MAX > 0xffffFFFFul)
  /* On some systems (e.g. x86_64) we can perform a 'oneshot' read, which
   * is little bit faster. Thanks Marcin Żukowski <marcin.zukowski@gmail.com>
   * for the reminder. */
  const unsigned offset = (8 - tail) & 7;
  const unsigned shift = offset << 3;
  if (likely(can_read_underside(p, 8))) {
    p -= offset;
    return fetch64_be_unaligned(p) & ((~UINT64_C(0)) >> shift);
  }
  return fetch64_be_unaligned(p) >> shift;
#else
  switch (tail & 7) {
  default:
    unreachable();
/* fall through */
#if T1HA_SYS_UNALIGNED_ACCESS == T1HA_UNALIGNED_ACCESS__EFFICIENT &&           \
    __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
  /* For most CPUs this code is better when not needed
   * copying for alignment or byte reordering. */
  case 1:
    return p[0];
  case 2:
    return fetch16_be_unaligned(p);
  case 3:
    return (uint32_t)fetch16_be_unaligned(p) << 8 | p[2];
  case 4:
    return fetch32_be(p);
  case 5:
    return (uint64_t)fetch32_be_unaligned(p) << 8 | p[4];
  case 6:
    return (uint64_t)fetch32_be_unaligned(p) << 16 |
           fetch16_be_unaligned(p + 4);
  case 7:
    return (uint64_t)fetch32_be_unaligned(p) << 24 |
           (uint32_t)fetch16_be_unaligned(p + 4) << 8 | p[6];
  case 0:
    return fetch64_be_unaligned(p);
#else
  /* For most CPUs this code is better than a
   * copying for alignment and/or byte reordering. */
  case 1:
    return p[0];
  case 2:
    return p[1] | (uint32_t)p[0] << 8;
  case 3:
    return p[2] | (uint32_t)p[1] << 8 | (uint32_t)p[0] << 16;
  case 4:
    return p[3] | (uint32_t)p[2] << 8 | (uint32_t)p[1] << 16 |
           (uint32_t)p[0] << 24;
  case 5:
    return p[4] | (uint32_t)p[3] << 8 | (uint32_t)p[2] << 16 |
           (uint32_t)p[1] << 24 | (uint64_t)p[0] << 32;
  case 6:
    return p[5] | (uint32_t)p[4] << 8 | (uint32_t)p[3] << 16 |
           (uint32_t)p[2] << 24 | (uint64_t)p[1] << 32 | (uint64_t)p[0] << 40;
  case 7:
    return p[6] | (uint32_t)p[5] << 8 | (uint32_t)p[4] << 16 |
           (uint32_t)p[3] << 24 | (uint64_t)p[2] << 32 | (uint64_t)p[1] << 40 |
           (uint64_t)p[0] << 48;
  case 0:
    return p[7] | (uint32_t)p[6] << 8 | (uint32_t)p[5] << 16 |
           (uint32_t)p[4] << 24 | (uint64_t)p[3] << 32 | (uint64_t)p[2] << 40 |
           (uint64_t)p[1] << 48 | (uint64_t)p[0] << 56;
#endif
  }
#endif /* can_read_underside */
}

/***************************************************************************/

#ifndef rot64
static __always_inline uint64_t rot64(uint64_t v, unsigned s) {
  return (v >> s) | (v << (64 - s));
}
#endif /* rot64 */

#ifndef mul_32x32_64
static __always_inline uint64_t mul_32x32_64(uint32_t a, uint32_t b) {
  return a * (uint64_t)b;
}
#endif /* mul_32x32_64 */

#ifndef add64carry_first
static __maybe_unused __always_inline unsigned
add64carry_first(uint64_t base, uint64_t addend, uint64_t *sum) {
#if __has_builtin(__builtin_addcll)
  unsigned long long carryout;
  *sum = __builtin_addcll(base, addend, 0, &carryout);
  return (unsigned)carryout;
#else
  *sum = base + addend;
  return *sum < addend;
#endif /* __has_builtin(__builtin_addcll) */
}
#endif /* add64carry_fist */

#ifndef add64carry_next
static __maybe_unused __always_inline unsigned
add64carry_next(unsigned carry, uint64_t base, uint64_t addend, uint64_t *sum) {
#if __has_builtin(__builtin_addcll)
  unsigned long long carryout;
  *sum = __builtin_addcll(base, addend, carry, &carryout);
  return (unsigned)carryout;
#else
  *sum = base + addend + carry;
  return *sum < addend || (carry && *sum == addend);
#endif /* __has_builtin(__builtin_addcll) */
}
#endif /* add64carry_next */

#ifndef add64carry_last
static __maybe_unused __always_inline void
add64carry_last(unsigned carry, uint64_t base, uint64_t addend, uint64_t *sum) {
#if __has_builtin(__builtin_addcll)
  unsigned long long carryout;
  *sum = __builtin_addcll(base, addend, carry, &carryout);
  (void)carryout;
#else
  *sum = base + addend + carry;
#endif /* __has_builtin(__builtin_addcll) */
}
#endif /* add64carry_last */

#ifndef mul_64x64_128
static __maybe_unused __always_inline uint64_t mul_64x64_128(uint64_t a,
                                                             uint64_t b,
                                                             uint64_t *h) {
#if defined(__SIZEOF_INT128__) ||                                              \
    (defined(_INTEGRAL_MAX_BITS) && _INTEGRAL_MAX_BITS >= 128)
  __uint128_t r = (__uint128_t)a * (__uint128_t)b;
  /* modern GCC could nicely optimize this */
  *h = (uint64_t)(r >> 64);
  return (uint64_t)r;
#elif defined(mul_64x64_high)
  *h = mul_64x64_high(a, b);
  return a * b;
#else
  /* performs 64x64 to 128 bit multiplication */
  const uint64_t ll = mul_32x32_64((uint32_t)a, (uint32_t)b);
  const uint64_t lh = mul_32x32_64(a >> 32, (uint32_t)b);
  const uint64_t hl = mul_32x32_64((uint32_t)a, b >> 32);
  const uint64_t hh = mul_32x32_64(a >> 32, b >> 32);

  /* Few simplification are possible here for 32-bit architectures,
   * but thus we would lost compatibility with the original 64-bit
   * version.  Think is very bad idea, because then 32-bit t1ha will
   * still (relatively) very slowly and well yet not compatible. */
  uint64_t l;
  add64carry_last(add64carry_first(ll, lh << 32, &l), hh, lh >> 32, h);
  add64carry_last(add64carry_first(l, hl << 32, &l), *h, hl >> 32, h);
  return l;
#endif
}
#endif /* mul_64x64_128() */

#ifndef mul_64x64_high
static __maybe_unused __always_inline uint64_t mul_64x64_high(uint64_t a,
                                                              uint64_t b) {
  uint64_t h;
  mul_64x64_128(a, b, &h);
  return h;
}
#endif /* mul_64x64_high */

/***************************************************************************/

/* 'magic' primes */
static const uint64_t prime_0 = UINT64_C(0xEC99BF0D8372CAAB);
static const uint64_t prime_1 = UINT64_C(0x82434FE90EDCEF39);
static const uint64_t prime_2 = UINT64_C(0xD4F06DB99D67BE4B);
static const uint64_t prime_3 = UINT64_C(0xBD9CACC22C6E9571);
static const uint64_t prime_4 = UINT64_C(0x9C06FAF4D023E3AB);
static const uint64_t prime_5 = UINT64_C(0xC060724A8424F345);
static const uint64_t prime_6 = UINT64_C(0xCB5AF53AE3AAAC31);

/* xor high and low parts of full 128-bit product */
static __maybe_unused __always_inline uint64_t mux64(uint64_t v,
                                                     uint64_t prime) {
  uint64_t l, h;
  l = mul_64x64_128(v, prime, &h);
  return l ^ h;
}

static __always_inline uint64_t final64(uint64_t a, uint64_t b) {
  uint64_t x = (a + rot64(b, 41)) * prime_0;
  uint64_t y = (rot64(a, 23) + b) * prime_6;
  return mux64(x ^ y, prime_5);
}

static __always_inline void mixup64(uint64_t *__restrict a,
                                    uint64_t *__restrict b, uint64_t v,
                                    uint64_t prime) {
  uint64_t h;
  *a ^= mul_64x64_128(*b + v, prime, &h);
  *b += h;
}
