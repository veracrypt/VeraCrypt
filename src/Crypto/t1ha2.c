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

#include "t1ha_bits.h"
#include "t1ha_selfcheck.h"

static __always_inline void init_ab(t1ha_state256_t *s, uint64_t x,
                                    uint64_t y) {
  s->n.a = x;
  s->n.b = y;
}

static __always_inline void init_cd(t1ha_state256_t *s, uint64_t x,
                                    uint64_t y) {
  s->n.c = rot64(y, 23) + ~x;
  s->n.d = ~y + rot64(x, 19);
}

/* TODO: C++ template in the next version */
#define T1HA2_UPDATE(ENDIANNES, ALIGNESS, state, v)                            \
  do {                                                                         \
    t1ha_state256_t *const s = state;                                          \
    const uint64_t w0 = fetch64_##ENDIANNES##_##ALIGNESS(v + 0);               \
    const uint64_t w1 = fetch64_##ENDIANNES##_##ALIGNESS(v + 1);               \
    const uint64_t w2 = fetch64_##ENDIANNES##_##ALIGNESS(v + 2);               \
    const uint64_t w3 = fetch64_##ENDIANNES##_##ALIGNESS(v + 3);               \
                                                                               \
    const uint64_t d02 = w0 + rot64(w2 + s->n.d, 56);                          \
    const uint64_t c13 = w1 + rot64(w3 + s->n.c, 19);                          \
    s->n.d ^= s->n.b + rot64(w1, 38);                                          \
    s->n.c ^= s->n.a + rot64(w0, 57);                                          \
    s->n.b ^= prime_6 * (c13 + w2);                                            \
    s->n.a ^= prime_5 * (d02 + w3);                                            \
  } while (0)

static __always_inline void squash(t1ha_state256_t *s) {
  s->n.a ^= prime_6 * (s->n.c + rot64(s->n.d, 23));
  s->n.b ^= prime_5 * (rot64(s->n.c, 19) + s->n.d);
}

/* TODO: C++ template in the next version */
#define T1HA2_LOOP(ENDIANNES, ALIGNESS, state, data, len)                      \
  do {                                                                         \
    const void *detent = (const uint8_t *)data + len - 31;                     \
    do {                                                                       \
      const uint64_t *v = (const uint64_t *)data;                              \
      data = (const uint64_t *)data + 4;                                       \
      prefetch(data);                                                          \
      T1HA2_UPDATE(le, ALIGNESS, state, v);                                    \
    } while (likely(data < detent));                                           \
  } while (0)

/* TODO: C++ template in the next version */
#define T1HA2_TAIL_AB(ENDIANNES, ALIGNESS, state, data, len)                   \
  do {                                                                         \
    t1ha_state256_t *const s = state;                                          \
    const uint64_t *v = (const uint64_t *)data;                                \
    switch (len) {                                                             \
    default:                                                                   \
      mixup64(&s->n.a, &s->n.b, fetch64_##ENDIANNES##_##ALIGNESS(v++),         \
              prime_4);                                                        \
    /* fall through */                                                         \
    case 24:                                                                   \
    case 23:                                                                   \
    case 22:                                                                   \
    case 21:                                                                   \
    case 20:                                                                   \
    case 19:                                                                   \
    case 18:                                                                   \
    case 17:                                                                   \
      mixup64(&s->n.b, &s->n.a, fetch64_##ENDIANNES##_##ALIGNESS(v++),         \
              prime_3);                                                        \
    /* fall through */                                                         \
    case 16:                                                                   \
    case 15:                                                                   \
    case 14:                                                                   \
    case 13:                                                                   \
    case 12:                                                                   \
    case 11:                                                                   \
    case 10:                                                                   \
    case 9:                                                                    \
      mixup64(&s->n.a, &s->n.b, fetch64_##ENDIANNES##_##ALIGNESS(v++),         \
              prime_2);                                                        \
    /* fall through */                                                         \
    case 8:                                                                    \
    case 7:                                                                    \
    case 6:                                                                    \
    case 5:                                                                    \
    case 4:                                                                    \
    case 3:                                                                    \
    case 2:                                                                    \
    case 1:                                                                    \
      mixup64(&s->n.b, &s->n.a, tail64_##ENDIANNES##_##ALIGNESS(v, len),       \
              prime_1);                                                        \
    /* fall through */                                                         \
    case 0:                                                                    \
      return final64(s->n.a, s->n.b);                                          \
    }                                                                          \
  } while (0)

/* TODO: C++ template in the next version */
#define T1HA2_TAIL_ABCD(ENDIANNES, ALIGNESS, state, data, len)                 \
  do {                                                                         \
    t1ha_state256_t *const s = state;                                          \
    const uint64_t *v = (const uint64_t *)data;                                \
    switch (len) {                                                             \
    default:                                                                   \
      mixup64(&s->n.a, &s->n.d, fetch64_##ENDIANNES##_##ALIGNESS(v++),         \
              prime_4);                                                        \
    /* fall through */                                                         \
    case 24:                                                                   \
    case 23:                                                                   \
    case 22:                                                                   \
    case 21:                                                                   \
    case 20:                                                                   \
    case 19:                                                                   \
    case 18:                                                                   \
    case 17:                                                                   \
      mixup64(&s->n.b, &s->n.a, fetch64_##ENDIANNES##_##ALIGNESS(v++),         \
              prime_3);                                                        \
    /* fall through */                                                         \
    case 16:                                                                   \
    case 15:                                                                   \
    case 14:                                                                   \
    case 13:                                                                   \
    case 12:                                                                   \
    case 11:                                                                   \
    case 10:                                                                   \
    case 9:                                                                    \
      mixup64(&s->n.c, &s->n.b, fetch64_##ENDIANNES##_##ALIGNESS(v++),         \
              prime_2);                                                        \
    /* fall through */                                                         \
    case 8:                                                                    \
    case 7:                                                                    \
    case 6:                                                                    \
    case 5:                                                                    \
    case 4:                                                                    \
    case 3:                                                                    \
    case 2:                                                                    \
    case 1:                                                                    \
      mixup64(&s->n.d, &s->n.c, tail64_##ENDIANNES##_##ALIGNESS(v, len),       \
              prime_1);                                                        \
    /* fall through */                                                         \
    case 0:                                                                    \
      return final128(s->n.a, s->n.b, s->n.c, s->n.d, extra_result);           \
    }                                                                          \
  } while (0)

static __always_inline uint64_t final128(uint64_t a, uint64_t b, uint64_t c,
                                         uint64_t d, uint64_t *h) {
  mixup64(&a, &b, rot64(c, 41) ^ d, prime_0);
  mixup64(&b, &c, rot64(d, 23) ^ a, prime_6);
  mixup64(&c, &d, rot64(a, 19) ^ b, prime_5);
  mixup64(&d, &a, rot64(b, 31) ^ c, prime_4);
  *h = c + d;
  return a ^ b;
}

//------------------------------------------------------------------------------

uint64_t t1ha2_atonce(const void *data, size_t length, uint64_t seed) {
  t1ha_state256_t state;
  init_ab(&state, seed, length);

#if T1HA_SYS_UNALIGNED_ACCESS == T1HA_UNALIGNED_ACCESS__EFFICIENT
  if (unlikely(length > 32)) {
    init_cd(&state, seed, length);
    T1HA2_LOOP(le, unaligned, &state, data, length);
    squash(&state);
    length &= 31;
  }
  T1HA2_TAIL_AB(le, unaligned, &state, data, length);
#else
  if ((((uintptr_t)data) & (ALIGNMENT_64 - 1)) != 0) {
    if (unlikely(length > 32)) {
      init_cd(&state, seed, length);
      T1HA2_LOOP(le, unaligned, &state, data, length);
      squash(&state);
      length &= 31;
    }
    T1HA2_TAIL_AB(le, unaligned, &state, data, length);
  } else {
    if (unlikely(length > 32)) {
      init_cd(&state, seed, length);
      T1HA2_LOOP(le, aligned, &state, data, length);
      squash(&state);
      length &= 31;
    }
    T1HA2_TAIL_AB(le, aligned, &state, data, length);
  }
#endif
}

uint64_t t1ha2_atonce128(uint64_t *__restrict extra_result,
                         const void *__restrict data, size_t length,
                         uint64_t seed) {
  t1ha_state256_t state;
  init_ab(&state, seed, length);
  init_cd(&state, seed, length);

#if T1HA_SYS_UNALIGNED_ACCESS == T1HA_UNALIGNED_ACCESS__EFFICIENT
  if (unlikely(length > 32)) {
    T1HA2_LOOP(le, unaligned, &state, data, length);
    length &= 31;
  }
  T1HA2_TAIL_ABCD(le, unaligned, &state, data, length);
#else
  if ((((uintptr_t)data) & (ALIGNMENT_64 - 1)) != 0) {
    if (unlikely(length > 32)) {
      T1HA2_LOOP(le, unaligned, &state, data, length);
      length &= 31;
    }
    T1HA2_TAIL_ABCD(le, unaligned, &state, data, length);
  } else {
    if (unlikely(length > 32)) {
      T1HA2_LOOP(le, aligned, &state, data, length);
      length &= 31;
    }
    T1HA2_TAIL_ABCD(le, aligned, &state, data, length);
  }
#endif
}

//------------------------------------------------------------------------------

void t1ha2_init(t1ha_context_t *ctx, uint64_t seed_x, uint64_t seed_y) {
  init_ab(&ctx->state, seed_x, seed_y);
  init_cd(&ctx->state, seed_x, seed_y);
  ctx->partial = 0;
  ctx->total = 0;
}

void t1ha2_update(t1ha_context_t *__restrict ctx, const void *__restrict data,
                  size_t length) {
  ctx->total += length;

  if (ctx->partial) {
    const size_t left = 32 - ctx->partial;
    const size_t chunk = (length >= left) ? left : length;
    memcpy(ctx->buffer.bytes + ctx->partial, data, chunk);
    ctx->partial += chunk;
    if (ctx->partial < 32) {
      assert(left >= length);
      return;
    }
    ctx->partial = 0;
    data = (const uint8_t *)data + chunk;
    length -= chunk;
    T1HA2_UPDATE(le, aligned, &ctx->state, ctx->buffer.u64);
  }

  if (length >= 32) {
#if T1HA_SYS_UNALIGNED_ACCESS == T1HA_UNALIGNED_ACCESS__EFFICIENT
    T1HA2_LOOP(le, unaligned, &ctx->state, data, length);
#else
    if ((((uintptr_t)data) & (ALIGNMENT_64 - 1)) != 0) {
      T1HA2_LOOP(le, unaligned, &ctx->state, data, length);
    } else {
      T1HA2_LOOP(le, aligned, &ctx->state, data, length);
    }
#endif
    length &= 31;
  }

  if (length)
    memcpy(ctx->buffer.bytes, data, ctx->partial = length);
}

uint64_t t1ha2_final(t1ha_context_t *__restrict ctx,
                     uint64_t *__restrict extra_result) {
  uint64_t bits = (ctx->total << 3) ^ (UINT64_C(1) << 63);
#if __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
  bits = bswap64(bits);
#endif
  t1ha2_update(ctx, &bits, 8);

  if (likely(!extra_result)) {
    squash(&ctx->state);
    T1HA2_TAIL_AB(le, aligned, &ctx->state, ctx->buffer.u64, ctx->partial);
  }

  T1HA2_TAIL_ABCD(le, aligned, &ctx->state, ctx->buffer.u64, ctx->partial);
}
