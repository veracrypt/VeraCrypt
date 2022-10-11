/*
   BLAKE2 reference source code package - optimized C implementations

   Copyright 2012, Samuel Neves <sneves@dei.uc.pt>.  You may use this under the
   terms of the CC0, the OpenSSL Licence, or the Apache Public License 2.0, at
   your option.  The terms of these licenses can be found at:

   - CC0 1.0 Universal : http://creativecommons.org/publicdomain/zero/1.0
   - OpenSSL license   : https://www.openssl.org/source/license.html
   - Apache 2.0        : http://www.apache.org/licenses/LICENSE-2.0

   More information about the BLAKE2 hash function can be found at
   https://blake2.net.
*/

/* Adapted for VeraCrypt */


#ifndef BLAKE2S_ROUND_H
#define BLAKE2S_ROUND_H

#define LOADU(p)  _mm_loadu_si128( (const __m128i *)(p) )
#define STOREU(p,r) _mm_storeu_si128((__m128i *)(p), r)

#define TOF(reg) _mm_castsi128_ps((reg))
#define TOI(reg) _mm_castps_si128((reg))

#define LIKELY(x) __builtin_expect((x),1)


/* Microarchitecture-specific macros */
#ifndef HAVE_XOP
#ifdef HAVE_SSSE3
#define _mm_roti_epi32(r, c) ( \
                (8==-(c)) ? _mm_shuffle_epi8(r,r8) \
              : (16==-(c)) ? _mm_shuffle_epi8(r,r16) \
              : _mm_xor_si128(_mm_srli_epi32( (r), -(c) ),_mm_slli_epi32( (r), 32-(-(c)) )) )
#else
#define _mm_roti_epi32(r, c) _mm_xor_si128(_mm_srli_epi32( (r), -(c) ),_mm_slli_epi32( (r), 32-(-(c)) ))
#endif
#else
/* ... */
#endif


#define G1(row1,row2,row3,row4,buf) \
  row1 = _mm_add_epi32( _mm_add_epi32( row1, buf), row2 ); \
  row4 = _mm_xor_si128( row4, row1 ); \
  row4 = _mm_roti_epi32(row4, -16); \
  row3 = _mm_add_epi32( row3, row4 );   \
  row2 = _mm_xor_si128( row2, row3 ); \
  row2 = _mm_roti_epi32(row2, -12);

#define G2(row1,row2,row3,row4,buf) \
  row1 = _mm_add_epi32( _mm_add_epi32( row1, buf), row2 ); \
  row4 = _mm_xor_si128( row4, row1 ); \
  row4 = _mm_roti_epi32(row4, -8); \
  row3 = _mm_add_epi32( row3, row4 );   \
  row2 = _mm_xor_si128( row2, row3 ); \
  row2 = _mm_roti_epi32(row2, -7);

#define DIAGONALIZE(row1,row2,row3,row4) \
  row1 = _mm_shuffle_epi32( row1, _MM_SHUFFLE(2,1,0,3) ); \
  row4 = _mm_shuffle_epi32( row4, _MM_SHUFFLE(1,0,3,2) ); \
  row3 = _mm_shuffle_epi32( row3, _MM_SHUFFLE(0,3,2,1) );

#define UNDIAGONALIZE(row1,row2,row3,row4) \
  row1 = _mm_shuffle_epi32( row1, _MM_SHUFFLE(0,3,2,1) ); \
  row4 = _mm_shuffle_epi32( row4, _MM_SHUFFLE(1,0,3,2) ); \
  row3 = _mm_shuffle_epi32( row3, _MM_SHUFFLE(2,1,0,3) );

#if defined(HAVE_XOP)
#include "blake2s-load-xop.h"
#elif defined(HAVE_SSE41)
#include "blake2s-load-sse41.h"
#else
#include "blake2s-load-sse2.h"
#endif

#define ROUND(r)  \
  LOAD_MSG_ ##r ##_1(buf1); \
  G1(row1,row2,row3,row4,buf1); \
  LOAD_MSG_ ##r ##_2(buf2); \
  G2(row1,row2,row3,row4,buf2); \
  DIAGONALIZE(row1,row2,row3,row4); \
  LOAD_MSG_ ##r ##_3(buf3); \
  G1(row1,row2,row3,row4,buf3); \
  LOAD_MSG_ ##r ##_4(buf4); \
  G2(row1,row2,row3,row4,buf4); \
  UNDIAGONALIZE(row1,row2,row3,row4); \

// load32 is always called in SSE case which implies little endian 
#define load32(x)	*((uint32*) (x))

extern const uint32 blake2s_IV[8];

#if defined(HAVE_SSE41)
void blake2s_compress_sse41( blake2s_state *S, const uint8 block[BLAKE2S_BLOCKBYTES] )
#elif defined (HAVE_SSSE3)
void blake2s_compress_ssse3( blake2s_state *S, const uint8 block[BLAKE2S_BLOCKBYTES] )
#else
void blake2s_compress_sse2( blake2s_state *S, const uint8 block[BLAKE2S_BLOCKBYTES] )
#endif
{
  __m128i row1, row2, row3, row4;
  __m128i buf1, buf2, buf3, buf4;
#if defined(HAVE_SSE41)
  __m128i t0, t1;
#if !defined(HAVE_XOP)
  __m128i t2;
#endif
#endif
  __m128i ff0, ff1;
#if defined(HAVE_SSSE3) && !defined(HAVE_XOP)
  const __m128i r8 = _mm_set_epi8( 12, 15, 14, 13, 8, 11, 10, 9, 4, 7, 6, 5, 0, 3, 2, 1 );
  const __m128i r16 = _mm_set_epi8( 13, 12, 15, 14, 9, 8, 11, 10, 5, 4, 7, 6, 1, 0, 3, 2 );
#endif
#if defined(HAVE_SSE41)
  const __m128i m0 = LOADU( block +  00 );
  const __m128i m1 = LOADU( block +  16 );
  const __m128i m2 = LOADU( block +  32 );
  const __m128i m3 = LOADU( block +  48 );
#else
  const uint32  m0 = load32(block +  0 * sizeof(uint32));
  const uint32  m1 = load32(block +  1 * sizeof(uint32));
  const uint32  m2 = load32(block +  2 * sizeof(uint32));
  const uint32  m3 = load32(block +  3 * sizeof(uint32));
  const uint32  m4 = load32(block +  4 * sizeof(uint32));
  const uint32  m5 = load32(block +  5 * sizeof(uint32));
  const uint32  m6 = load32(block +  6 * sizeof(uint32));
  const uint32  m7 = load32(block +  7 * sizeof(uint32));
  const uint32  m8 = load32(block +  8 * sizeof(uint32));
  const uint32  m9 = load32(block +  9 * sizeof(uint32));
  const uint32 m10 = load32(block + 10 * sizeof(uint32));
  const uint32 m11 = load32(block + 11 * sizeof(uint32));
  const uint32 m12 = load32(block + 12 * sizeof(uint32));
  const uint32 m13 = load32(block + 13 * sizeof(uint32));
  const uint32 m14 = load32(block + 14 * sizeof(uint32));
  const uint32 m15 = load32(block + 15 * sizeof(uint32));
#endif
  row1 = ff0 = LOADU( &S->h[0] );
  row2 = ff1 = LOADU( &S->h[4] );
  row3 = _mm_loadu_si128( (__m128i const *)&blake2s_IV[0] );
  row4 = _mm_xor_si128( _mm_loadu_si128( (__m128i const *)&blake2s_IV[4] ), LOADU( &S->t[0] ) );
  ROUND( 0 );
  ROUND( 1 );
  ROUND( 2 );
  ROUND( 3 );
  ROUND( 4 );
  ROUND( 5 );
  ROUND( 6 );
  ROUND( 7 );
  ROUND( 8 );
  ROUND( 9 );
  STOREU( &S->h[0], _mm_xor_si128( ff0, _mm_xor_si128( row1, row3 ) ) );
  STOREU( &S->h[4], _mm_xor_si128( ff1, _mm_xor_si128( row2, row4 ) ) );
}

#endif
