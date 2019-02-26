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

#include "t1ha_selfcheck.h"
#include "t1ha_bits.h"

const uint8_t t1ha_test_pattern[64] = {
    0,    1,    2,    3,    4,    5,    6,    7,    0xFF, 0x7F, 0x3F,
    0x1F, 0xF,  8,    16,   32,   64,   0x80, 0xFE, 0xFC, 0xF8, 0xF0,
    0xE0, 0xC0, 0xFD, 0xFB, 0xF7, 0xEF, 0xDF, 0xBF, 0x55, 0xAA, 11,
    17,   19,   23,   29,   37,   42,   43,   'a',  'b',  'c',  'd',
    'e',  'f',  'g',  'h',  'i',  'j',  'k',  'l',  'm',  'n',  'o',
    'p',  'q',  'r',  's',  't',  'u',  'v',  'w',  'x'};

static VC_INLINE int probe(uint64_t (*hash)(const void *, size_t, uint64_t),
                           const uint64_t reference, const void *data,
                           unsigned len, uint64_t seed) {
  const uint64_t actual = hash(data, len, seed);
  assert(actual == reference);
  return actual != reference;
}

__cold int t1ha_selfcheck(uint64_t (*hash)(const void *, size_t, uint64_t),
                          const uint64_t *reference_values) {
  int failed = 0;
  uint64_t seed = 1;
  const uint64_t zero = 0;
 uint8_t pattern_long[512];
  int i;
  failed |= probe(hash, /* empty-zero */ *reference_values++, NULL, 0, zero);
  failed |= probe(hash, /* empty-all1 */ *reference_values++, NULL, 0, ~zero);
  failed |= probe(hash, /* bin64-zero */ *reference_values++, t1ha_test_pattern,
                  64, zero);

  for (i = 1; i < 64; i++) {
    /* bin%i-1p%i */
    failed |= probe(hash, *reference_values++, t1ha_test_pattern, i, seed);
    seed <<= 1;
  }

  seed = ~zero;
  for (i = 1; i <= 7; i++) {
    seed <<= 1;
    /* align%i_F%i */;
    failed |=
        probe(hash, *reference_values++, t1ha_test_pattern + i, 64 - i, seed);
  }

 
  for (i = 0; i < sizeof(pattern_long); ++i)
    pattern_long[i] = (uint8_t)i;
  for (i = 0; i <= 7; i++) {
    /* long-%05i */
    failed |=
        probe(hash, *reference_values++, pattern_long + i, 128 + i * 17, seed);
  }

  return failed ? -1 : 0;
}
