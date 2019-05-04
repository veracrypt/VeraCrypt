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

/*****************************************************************************
 *
 * PLEASE PAY ATTENTION TO THE FOLLOWING NOTES
 * about macros definitions which controls t1ha behaviour and/or performance.
 *
 *
 * 1) T1HA_SYS_UNALIGNED_ACCESS = Defines the system/platform/CPU/architecture
 *                                abilities for unaligned data access.
 *
 *    By default, when the T1HA_SYS_UNALIGNED_ACCESS not defined,
 *    it will defined on the basis hardcoded knowledge about of capabilities
 *    of most common CPU architectures. But you could override this
 *    default behavior when build t1ha library itself:
 *
 *      // To disable unaligned access at all.
 *      #define T1HA_SYS_UNALIGNED_ACCESS 0
 *
 *      // To enable unaligned access, but indicate that it significally slow.
 *      #define T1HA_SYS_UNALIGNED_ACCESS 1
 *
 *      // To enable unaligned access, and indicate that it effecient.
 *      #define T1HA_SYS_UNALIGNED_ACCESS 2
 *
 *
 * 2) T1HA_USE_FAST_ONESHOT_READ = Controls the data reads at the end of buffer.
 *
 *    When defined to non-zero, t1ha will use 'one shot' method for reading
 *    up to 8 bytes at the end of data. In this case just the one 64-bit read
 *    will be performed even when the available less than 8 bytes.
 *
 *    This is little bit faster that switching by length of data tail.
 *    Unfortunately this will triggering a false-positive alarms from Valgrind,
 *    AddressSanitizer and other similar tool.
 *
 *    By default, t1ha defines it to 1, but you could override this
 *    default behavior when build t1ha library itself:
 *
 *      // For little bit faster and small code.
 *      #define T1HA_USE_FAST_ONESHOT_READ 1
 *
 *      // For calmness if doubt.
 *      #define T1HA_USE_FAST_ONESHOT_READ 0
 *
 *
 * 3) T1HA0_RUNTIME_SELECT = Controls choice fastest function in runtime.
 *
 *    t1ha library offers the t1ha0() function as the fastest for current CPU.
 *    But actual CPU's features/capabilities and may be significantly different,
 *    especially on x86 platform. Therefore, internally, t1ha0() may require
 *    dynamic dispatching for choice best implementation.
 *
 *    By default, t1ha enables such runtime choice and (may be) corresponding
 *    indirect calls if it reasonable, but you could override this default
 *    behavior when build t1ha library itself:
 *
 *      // To enable runtime choice of fastest implementation.
 *      #define T1HA0_RUNTIME_SELECT 1
 *
 *      // To disable runtime choice of fastest implementation.
 *      #define T1HA0_RUNTIME_SELECT 0
 *
 *    When T1HA0_RUNTIME_SELECT is nonzero the t1ha0_resolve() function could
 *    be used to get actual t1ha0() implementation address at runtime. This is
 *    useful for two cases:
 *      - calling by local pointer-to-function usually is little
 *        bit faster (less overhead) than via a PLT thru the DSO boundary.
 *      - GNU Indirect functions (see below) don't supported by environment
 *        and calling by t1ha0_funcptr is not available and/or expensive.
 *
 * 4) T1HA_USE_INDIRECT_FUNCTIONS = Controls usage of GNU Indirect functions.
 *
 *    In continue of T1HA0_RUNTIME_SELECT the T1HA_USE_INDIRECT_FUNCTIONS
 *    controls usage of ELF indirect functions feature. In general, when
 *    available, this reduces overhead of indirect function's calls though
 *    a DSO-bundary (https://sourceware.org/glibc/wiki/GNU_IFUNC).
 *
 *    By default, t1ha engage GNU Indirect functions when it available
 *    and useful, but you could override this default behavior when build
 *    t1ha library itself:
 *
 *      // To enable use of GNU ELF Indirect functions.
 *      #define T1HA_USE_INDIRECT_FUNCTIONS 1
 *
 *      // To disable use of GNU ELF Indirect functions. This may be useful
 *      // if the actual toolchain or the system's loader don't support ones.
 *      #define T1HA_USE_INDIRECT_FUNCTIONS 0
 *
 * 5) T1HA0_AESNI_AVAILABLE = Controls AES-NI detection and dispatching on x86.
 *
 *    In continue of T1HA0_RUNTIME_SELECT the T1HA0_AESNI_AVAILABLE controls
 *    detection and usage of AES-NI CPU's feature. On the other hand, this
 *    requires compiling parts of t1ha library with certain properly options,
 *    and could be difficult or inconvenient in some cases.
 *
 *    By default, t1ha engade AES-NI for t1ha0() on the x86 platform, but
 *    you could override this default behavior when build t1ha library itself:
 *
 *      // To disable detection and usage of AES-NI instructions for t1ha0().
 *      // This may be useful when you unable to build t1ha library properly
 *      // or known that AES-NI will be unavailable at the deploy.
 *      #define T1HA0_AESNI_AVAILABLE 0
 *
 *      // To force detection and usage of AES-NI instructions for t1ha0(),
 *      // but I don't known reasons to anybody would need this.
 *      #define T1HA0_AESNI_AVAILABLE 1
 *
 * 6) T1HA0_DISABLED, T1HA1_DISABLED, T1HA2_DISABLED = Controls availability of
 *    t1ha functions.
 *
 *    In some cases could be useful to import/use only few of t1ha functions
 *    or just the one. So, this definitions allows disable corresponding parts
 *    of t1ha library.
 *
 *      // To disable t1ha0(), t1ha0_32le(), t1ha0_32be() and all AES-NI.
 *      #define T1HA0_DISABLED
 *
 *      // To disable t1ha1_le() and t1ha1_be().
 *      #define T1HA1_DISABLED
 *
 *      // To disable t1ha2_atonce(), t1ha2_atonce128() and so on.
 *      #define T1HA2_DISABLED
 *
 *****************************************************************************/

#define T1HA_VERSION_MAJOR 2
#define T1HA_VERSION_MINOR 1
#define T1HA_VERSION_RELEASE 0

#include "Common/Tcdefs.h"
#include "config.h"
#include "misc.h"

#ifdef __cplusplus
extern "C" {
#endif

#define T1HA_ALIGN_PREFIX CRYPTOPP_ALIGN_DATA(32)
#define T1HA_ALIGN_SUFFIX

#ifdef _MSC_VER
#define uint8_t byte
#define uint16_t uint16
#define uint32_t uint32
#define uint64_t uint64
#endif

typedef union T1HA_ALIGN_PREFIX t1ha_state256 {
  uint8_t bytes[32];
  uint32_t u32[8];
  uint64_t u64[4];
  struct {
    uint64_t a, b, c, d;
  } n;
} t1ha_state256_t T1HA_ALIGN_SUFFIX;

typedef struct t1ha_context {
  t1ha_state256_t state;
  t1ha_state256_t buffer;
  size_t partial;
  uint64_t total;
} t1ha_context_t;

/******************************************************************************
 *
 *  t1ha2 = 64 and 128-bit, SLIGHTLY MORE ATTENTION FOR QUALITY AND STRENGTH.
 *
 *    - The recommended version of "Fast Positive Hash" with good quality
 *      for checksum, hash tables and fingerprinting.
 *    - Portable and extremely efficiency on modern 64-bit CPUs.
 *      Designed for 64-bit little-endian platforms,
 *      in other cases will runs slowly.
 *    - Great quality of hashing and still faster than other non-t1ha hashes.
 *      Provides streaming mode and 128-bit result.
 *
 * Note: Due performance reason 64- and 128-bit results are completely
 *       different each other, i.e. 64-bit result is NOT any part of 128-bit.
 */

/* The at-once variant with 64-bit result */
uint64_t t1ha2_atonce(const void *data, size_t length, uint64_t seed);

/* The at-once variant with 128-bit result.
 * Argument `extra_result` is NOT optional and MUST be valid.
 * The high 64-bit part of 128-bit hash will be always unconditionally
 * stored to the address given by `extra_result` argument. */
uint64_t t1ha2_atonce128(uint64_t *__restrict extra_result,
                                  const void *__restrict data, size_t length,
                                  uint64_t seed);

/* The init/update/final trinity for streaming.
 * Return 64 or 128-bit result depentently from `extra_result` argument. */
void t1ha2_init(t1ha_context_t *ctx, uint64_t seed_x, uint64_t seed_y);
void t1ha2_update(t1ha_context_t *__restrict ctx,
                           const void *__restrict data, size_t length);

/* Argument `extra_result` is optional and MAY be NULL.
 *  - If `extra_result` is NOT NULL then the 128-bit hash will be calculated,
 *    and high 64-bit part of it will be stored to the address given
 *    by `extra_result` argument.
 *  - Otherwise the 64-bit hash will be calculated
 *    and returned from function directly.
 *
 * Note: Due performance reason 64- and 128-bit results are completely
 *       different each other, i.e. 64-bit result is NOT any part of 128-bit. */
uint64_t t1ha2_final(t1ha_context_t *__restrict ctx,
                              uint64_t *__restrict extra_result /* optional */);


int t1ha_selfcheck__t1ha2_atonce(void);
int t1ha_selfcheck__t1ha2_atonce128(void);
int t1ha_selfcheck__t1ha2_stream(void);
int t1ha_selfcheck__t1ha2(void);

#ifdef __cplusplus
}
#endif
