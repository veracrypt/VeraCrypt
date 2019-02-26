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
#if defined(_MSC_VER) && _MSC_VER > 1800
#pragma warning(disable : 4464) /* relative include path contains '..' */
#endif                          /* MSVC */
#include "t1ha.h"

/***************************************************************************/
/* Self-checking */

extern const uint8_t t1ha_test_pattern[64];
int t1ha_selfcheck(uint64_t (*hash)(const void *, size_t, uint64_t),
                   const uint64_t *reference_values);

#ifndef T1HA2_DISABLED
extern const uint64_t t1ha_refval_2atonce[81];
extern const uint64_t t1ha_refval_2atonce128[81];
extern const uint64_t t1ha_refval_2stream[81];
extern const uint64_t t1ha_refval_2stream128[81];
#endif /* T1HA2_DISABLED */

#ifndef T1HA1_DISABLED
extern const uint64_t t1ha_refval_64le[81];
extern const uint64_t t1ha_refval_64be[81];
#endif /* T1HA1_DISABLED */

#ifndef T1HA0_DISABLED
extern const uint64_t t1ha_refval_32le[81];
extern const uint64_t t1ha_refval_32be[81];
#if T1HA0_AESNI_AVAILABLE
extern const uint64_t t1ha_refval_ia32aes_a[81];
extern const uint64_t t1ha_refval_ia32aes_b[81];
#endif /* T1HA0_AESNI_AVAILABLE */
#endif /* T1HA0_DISABLED */
