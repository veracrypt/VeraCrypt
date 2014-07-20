/*
 ---------------------------------------------------------------------------
 Copyright (c) 2003, Dr Brian Gladman, Worcester, UK.   All rights reserved.

 LICENSE TERMS

 The free distribution and use of this software is allowed (with or without
 changes) provided that:

  1. source code distributions include the above copyright notice, this
     list of conditions and the following disclaimer;

  2. binary distributions include the above copyright notice, this list
     of conditions and the following disclaimer in their documentation;

  3. the name of the copyright holder is not used to endorse products
     built using this software without specific written permission.

 DISCLAIMER

 This software is provided 'as is' with no explicit or implied warranties
 in respect of its properties, including, but not limited to, correctness
 and/or fitness for purpose.
 ---------------------------------------------------------------------------
 Issue Date: 31/01/2004

 My thanks to John Viega and David McGrew for their support in developing 
 this code and to David for testing it on a big-endain system.
*/

/* 
 ---------------------------------------------------------------------------
 Portions Copyright (c) 2005 TrueCrypt Developers Association

 Changes:

   - Added multiplication in the finite field GF(2^128) optimized for
     cases involving a 64-bit operand.

   - Added multiplication in the finite field GF(2^64).

   - Added MSB-first mode.

   - Added basic test algorithms.

   - Removed GCM.
 ---------------------------------------------------------------------------
*/

#include <memory.h>
#include <stdlib.h>
#include "GfMul.h"
#include "Tcdefs.h"
#include "Common/Endian.h"

/* BUFFER_ALIGN32 or BUFFER_ALIGN64 must be defined at this point to    */
/* enable faster operation by taking advantage of memory aligned values */
/* NOTE: the BUFFER_ALIGN64 option has not been tested extensively      */

#define BUFFER_ALIGN32
#define UNROLL_LOOPS    /* define to unroll some loops      */
#define IN_LINES        /* define to use inline functions   */
                        /* in place of macros               */

#define mode(x)			GM_##x

#if defined(__cplusplus)
extern "C"
{
#endif

typedef unsigned __int32 mode(32t);
typedef uint64 mode(64t);

#define BRG_LITTLE_ENDIAN   1234 /* byte 0 is least significant (i386) */
#define BRG_BIG_ENDIAN      4321 /* byte 0 is most significant (mc68k) */

#if BYTE_ORDER == LITTLE_ENDIAN
#  define PLATFORM_BYTE_ORDER BRG_LITTLE_ENDIAN
#endif

#if BYTE_ORDER == BIG_ENDIAN
#  define PLATFORM_BYTE_ORDER BRG_BIG_ENDIAN
#endif

#ifdef _MSC_VER
#pragma intrinsic(memcpy)
#define in_line __inline
#else
#define in_line
#endif

#if 0 && defined(_MSC_VER)
#define rotl32 _lrotl
#define rotr32 _lrotr
#else
#define rotl32(x,n)   (((x) << n) | ((x) >> (32 - n)))
#define rotr32(x,n)   (((x) >> n) | ((x) << (32 - n)))
#endif

#if !defined(bswap_32)
#define bswap_32(x) ((rotr32((x), 24) & 0x00ff00ff) | (rotr32((x), 8) & 0xff00ff00))
#endif

#if (PLATFORM_BYTE_ORDER == BRG_LITTLE_ENDIAN)
#define SWAP_BYTES
#else
#undef  SWAP_BYTES
#endif

#if defined(SWAP_BYTES)

#if defined ( IN_LINES )

in_line void bsw_32(void * p, unsigned int n)
{   unsigned int i = n;
    while(i--)
        ((mode(32t)*)p)[i] = bswap_32(((mode(32t)*)p)[i]);
}

#else

#define bsw_32(p,n) \
    { int _i = (n); while(_i--) ((mode(32t)*)p)[_i] = bswap_32(((mode(32t)*)p)[_i]); }

#endif

#else
#define bsw_32(p,n)
#endif

/* These values are used to detect long word alignment in order */
/* to speed up some GCM buffer operations. This facility may    */
/* not work on some machines                                    */

#define lp08(x)      ((unsigned char*)(x))
#define lp32(x)      ((mode(32t)*)(x))
#define lp64(x)      ((mode(64t)*)(x))

#define A32_MASK     3
#define A64_MASK     7
#define aligned32(x) (!(((mode(32t))(x)) & A32_MASK))
#define aligned64(x) (!(((mode(32t))(x)) & A64_MASK))

#if defined( BUFFER_ALIGN32 )

#define ADR_MASK    A32_MASK
#define aligned     aligned32
#define lp          lp32
#define lp_inc      4

#if defined( IN_LINES )

in_line void move_block_aligned( void *p, const void *q)
{
    lp32(p)[0] = lp32(q)[0], lp32(p)[1] = lp32(q)[1],
    lp32(p)[2] = lp32(q)[2], lp32(p)[3] = lp32(q)[3];
}

in_line void move_block_aligned64( void *p, const void *q)
{
    lp32(p)[0] = lp32(q)[0], lp32(p)[1] = lp32(q)[1];
}

in_line void xor_block_aligned( void *p, const void *q)
{
    lp32(p)[0] ^= lp32(q)[0], lp32(p)[1] ^= lp32(q)[1],
    lp32(p)[2] ^= lp32(q)[2], lp32(p)[3] ^= lp32(q)[3];
}

in_line void xor_block_aligned64( void *p, const void *q)
{
    lp32(p)[0] ^= lp32(q)[0], lp32(p)[1] ^= lp32(q)[1];
}

#else

#define move_block_aligned(p,q) \
    lp32(p)[0] = lp32(q)[0], lp32(p)[1] = lp32(q)[1], \
    lp32(p)[2] = lp32(q)[2], lp32(p)[3] = lp32(q)[3]

#define xor_block_aligned(p,q) \
    lp32(p)[0] ^= lp32(q)[0], lp32(p)[1] ^= lp32(q)[1], \
    lp32(p)[2] ^= lp32(q)[2], lp32(p)[3] ^= lp32(q)[3]

#endif

#elif defined( BUFFER_ALIGN64 )

#define ADR_MASK    A64_MASK
#define aligned     aligned64
#define lp          lp64
#define lp_inc      8

#define move_block_aligned(p,q) \
    lp64(p)[0] = lp64(q)[0], lp64(p)[1] = lp64(q)[1]

#define xor_block_aligned(p,q) \
    lp64(p)[0] ^= lp64(q)[0], lp64(p)[1] ^= lp64(q)[1]

#else
#define aligned(x) 0
#endif

#define move_block(p,q) memcpy((p), (q), BLOCK_LEN)

#define xor_block(p,q) \
    lp08(p)[ 0] ^= lp08(q)[ 0], lp08(p)[ 1] ^= lp08(q)[ 1], \
    lp08(p)[ 2] ^= lp08(q)[ 2], lp08(p)[ 3] ^= lp08(q)[ 3], \
    lp08(p)[ 4] ^= lp08(q)[ 4], lp08(p)[ 5] ^= lp08(q)[ 5], \
    lp08(p)[ 6] ^= lp08(q)[ 6], lp08(p)[ 7] ^= lp08(q)[ 7], \
    lp08(p)[ 8] ^= lp08(q)[ 8], lp08(p)[ 9] ^= lp08(q)[ 9], \
    lp08(p)[10] ^= lp08(q)[10], lp08(p)[11] ^= lp08(q)[11], \
    lp08(p)[12] ^= lp08(q)[12], lp08(p)[13] ^= lp08(q)[13], \
    lp08(p)[14] ^= lp08(q)[14], lp08(p)[15] ^= lp08(q)[15]


#define gf_dat(q) {\
    q(0x00), q(0x01), q(0x02), q(0x03), q(0x04), q(0x05), q(0x06), q(0x07),\
    q(0x08), q(0x09), q(0x0a), q(0x0b), q(0x0c), q(0x0d), q(0x0e), q(0x0f),\
    q(0x10), q(0x11), q(0x12), q(0x13), q(0x14), q(0x15), q(0x16), q(0x17),\
    q(0x18), q(0x19), q(0x1a), q(0x1b), q(0x1c), q(0x1d), q(0x1e), q(0x1f),\
    q(0x20), q(0x21), q(0x22), q(0x23), q(0x24), q(0x25), q(0x26), q(0x27),\
    q(0x28), q(0x29), q(0x2a), q(0x2b), q(0x2c), q(0x2d), q(0x2e), q(0x2f),\
    q(0x30), q(0x31), q(0x32), q(0x33), q(0x34), q(0x35), q(0x36), q(0x37),\
    q(0x38), q(0x39), q(0x3a), q(0x3b), q(0x3c), q(0x3d), q(0x3e), q(0x3f),\
    q(0x40), q(0x41), q(0x42), q(0x43), q(0x44), q(0x45), q(0x46), q(0x47),\
    q(0x48), q(0x49), q(0x4a), q(0x4b), q(0x4c), q(0x4d), q(0x4e), q(0x4f),\
    q(0x50), q(0x51), q(0x52), q(0x53), q(0x54), q(0x55), q(0x56), q(0x57),\
    q(0x58), q(0x59), q(0x5a), q(0x5b), q(0x5c), q(0x5d), q(0x5e), q(0x5f),\
    q(0x60), q(0x61), q(0x62), q(0x63), q(0x64), q(0x65), q(0x66), q(0x67),\
    q(0x68), q(0x69), q(0x6a), q(0x6b), q(0x6c), q(0x6d), q(0x6e), q(0x6f),\
    q(0x70), q(0x71), q(0x72), q(0x73), q(0x74), q(0x75), q(0x76), q(0x77),\
    q(0x78), q(0x79), q(0x7a), q(0x7b), q(0x7c), q(0x7d), q(0x7e), q(0x7f),\
    q(0x80), q(0x81), q(0x82), q(0x83), q(0x84), q(0x85), q(0x86), q(0x87),\
    q(0x88), q(0x89), q(0x8a), q(0x8b), q(0x8c), q(0x8d), q(0x8e), q(0x8f),\
    q(0x90), q(0x91), q(0x92), q(0x93), q(0x94), q(0x95), q(0x96), q(0x97),\
    q(0x98), q(0x99), q(0x9a), q(0x9b), q(0x9c), q(0x9d), q(0x9e), q(0x9f),\
    q(0xa0), q(0xa1), q(0xa2), q(0xa3), q(0xa4), q(0xa5), q(0xa6), q(0xa7),\
    q(0xa8), q(0xa9), q(0xaa), q(0xab), q(0xac), q(0xad), q(0xae), q(0xaf),\
    q(0xb0), q(0xb1), q(0xb2), q(0xb3), q(0xb4), q(0xb5), q(0xb6), q(0xb7),\
    q(0xb8), q(0xb9), q(0xba), q(0xbb), q(0xbc), q(0xbd), q(0xbe), q(0xbf),\
    q(0xc0), q(0xc1), q(0xc2), q(0xc3), q(0xc4), q(0xc5), q(0xc6), q(0xc7),\
    q(0xc8), q(0xc9), q(0xca), q(0xcb), q(0xcc), q(0xcd), q(0xce), q(0xcf),\
    q(0xd0), q(0xd1), q(0xd2), q(0xd3), q(0xd4), q(0xd5), q(0xd6), q(0xd7),\
    q(0xd8), q(0xd9), q(0xda), q(0xdb), q(0xdc), q(0xdd), q(0xde), q(0xdf),\
    q(0xe0), q(0xe1), q(0xe2), q(0xe3), q(0xe4), q(0xe5), q(0xe6), q(0xe7),\
    q(0xe8), q(0xe9), q(0xea), q(0xeb), q(0xec), q(0xed), q(0xee), q(0xef),\
    q(0xf0), q(0xf1), q(0xf2), q(0xf3), q(0xf4), q(0xf5), q(0xf6), q(0xf7),\
    q(0xf8), q(0xf9), q(0xfa), q(0xfb), q(0xfc), q(0xfd), q(0xfe), q(0xff) }

/* given the value i in 0..255 as the byte overflow when a a field  */
/* element in GHASH is multipled by x^8, this function will return  */
/* the values that are generated in the lo 16-bit word of the field */
/* value by applying the modular polynomial. The values lo_byte and */
/* hi_byte are returned via the macro xp_fun(lo_byte, hi_byte) so   */
/* that the values can be assembled into memory as required by a    */
/* suitable definition of this macro operating on the table above   */

#define xp(i) xp_fun( \
    (i & 0x80 ? 0xe1 : 0) ^ (i & 0x40 ? 0x70 : 0) ^ \
    (i & 0x20 ? 0x38 : 0) ^ (i & 0x10 ? 0x1c : 0) ^ \
    (i & 0x08 ? 0x0e : 0) ^ (i & 0x04 ? 0x07 : 0) ^ \
    (i & 0x02 ? 0x03 : 0) ^ (i & 0x01 ? 0x01 : 0),  \
    (i & 0x80 ? 0x00 : 0) ^ (i & 0x40 ? 0x80 : 0) ^ \
    (i & 0x20 ? 0x40 : 0) ^ (i & 0x10 ? 0x20 : 0) ^ \
    (i & 0x08 ? 0x10 : 0) ^ (i & 0x04 ? 0x08 : 0) ^ \
    (i & 0x02 ? 0x84 : 0) ^ (i & 0x01 ? 0xc2 : 0) )

#define xp64(i) xp_fun( \
    (i & 0x80 ? 0xd8 : 0) ^ (i & 0x40 ? 0x6c : 0) ^ \
    (i & 0x20 ? 0x36 : 0) ^ (i & 0x10 ? 0x1b : 0) ^ \
    (i & 0x08 ? 0x0d : 0) ^ (i & 0x04 ? 0x06 : 0) ^ \
    (i & 0x02 ? 0x03 : 0) ^ (i & 0x01 ? 0x01 : 0),  \
    (i & 0x80 ? 0x00 : 0) ^ (i & 0x40 ? 0x00 : 0) ^ \
    (i & 0x20 ? 0x00 : 0) ^ (i & 0x10 ? 0x00 : 0) ^ \
    (i & 0x08 ? 0x80 : 0) ^ (i & 0x04 ? 0xc0 : 0) ^ \
    (i & 0x02 ? 0x60 : 0) ^ (i & 0x01 ? 0xb0 : 0) )

static mode(32t) gf_poly[2] = { 0, 0xe1000000 };
static mode(32t) gf_poly64[2] = { 0, 0xd8000000 };

/* Multiply of a GF128 field element by x.   The field element  */
/* is held in an array of bytes in which field bits 8n..8n + 7  */
/* are held in byte[n], with lower indexed bits placed in the   */
/* more numerically significant bit positions in bytes.         */

/* This function multiples a field element x, in the polynomial */
/* field representation. It uses 32-bit word operations to gain */
/* speed but compensates for machine endianess and hence works  */
/* correctly on both styles of machine                          */

in_line void mul_x(mode(32t) x[4])
{   mode(32t)   t;

    bsw_32(x, 4);

    /* at this point the filed element bits 0..127 are set out  */
    /* as follows in 32-bit words (where the most significant   */
    /* (ms) numeric bits are to the left)                       */
    /*                                                          */
    /*            x[0]      x[1]      x[2]      x[3]            */
    /*          ms    ls  ms    ls  ms    ls  ms     ls         */
    /* field:   0 ... 31  32 .. 63  64 .. 95  96 .. 127         */

    t = gf_poly[x[3] & 1];          /* bit 127 of the element   */
    x[3] = (x[3] >> 1) | (x[2] << 31);  /* shift bits up by one */
    x[2] = (x[2] >> 1) | (x[1] << 31);  /* position             */
    x[1] = (x[1] >> 1) | (x[0] << 31);  /* if bit 7 is 1 xor in */
    x[0] = (x[0] >> 1) ^ t;             /* the field polynomial */
    bsw_32(x, 4);
}

in_line void mul_x64(mode(32t) x[2])
{   mode(32t)   t;

    bsw_32(x, 2);

    /* at this point the filed element bits 0..127 are set out  */
    /* as follows in 32-bit words (where the most significant   */
    /* (ms) numeric bits are to the left)                       */
    /*                                                          */
    /*            x[0]      x[1]      x[2]      x[3]            */
    /*          ms    ls  ms    ls  ms    ls  ms     ls         */
    /* field:   0 ... 31  32 .. 63  64 .. 95  96 .. 127         */

    t = gf_poly64[x[1] & 1];          /* bit 127 of the element   */
										/* shift bits up by one */
										/* position             */
    x[1] = (x[1] >> 1) | (x[0] << 31);  /* if bit 7 is 1 xor in */
    x[0] = (x[0] >> 1) ^ t;             /* the field polynomial */
    bsw_32(x, 2);
}

/* Multiply of a GF128 field element by x^8 using 32-bit words  */
/* for speed - machine endianess matters here                   */

#if (PLATFORM_BYTE_ORDER == BRG_LITTLE_ENDIAN)

#define xp_fun(x,y)    ((mode(32t))(x)) | (((mode(32t))(y)) << 8)
static const unsigned __int16 gft_le[256] = gf_dat(xp);
static const unsigned __int16 gft_le64[256] = gf_dat(xp64);

in_line void mul_lex8(mode(32t) x[4])   /* mutiply with long words  */
{   mode(32t)   t = (x[3] >> 24);       /* in little endian format  */
    x[3] = (x[3] << 8) | (x[2] >> 24);
    x[2] = (x[2] << 8) | (x[1] >> 24);
    x[1] = (x[1] << 8) | (x[0] >> 24);
    x[0] = (x[0] << 8) ^ gft_le[t];
}

in_line void mul_lex8_64(mode(32t) x[2])   /* mutiply with long words  */
{   mode(32t)   t = (x[1] >> 24);       /* in little endian format  */
    x[1] = (x[1] << 8) | (x[0] >> 24);
    x[0] = (x[0] << 8) ^ gft_le64[t];
}

#endif

#if 1 || (PLATFORM_BYTE_ORDER == BRG_LITTLE_ENDIAN)

#undef  xp_fun
#define xp_fun(x,y)    ((mode(32t))(y)) | (((mode(32t))(x)) << 8)
static const unsigned __int16 gft_be[256] = gf_dat(xp);
static const unsigned __int16 gft_be64[256] = gf_dat(xp64);

in_line void mul_bex8(mode(32t) x[4])   /* mutiply with long words  */
{   mode(32t)   t = (x[3] & 0xff);      /* in big endian format     */
    x[3] = (x[3] >> 8) | (x[2] << 24);
    x[2] = (x[2] >> 8) | (x[1] << 24);
    x[1] = (x[1] >> 8) | (x[0] << 24);
    x[0] = (x[0] >> 8) ^ (((mode(32t))gft_be[t]) << 16);
}

in_line void mul_bex8_64(mode(32t) x[2])   /* mutiply with long words  */
{   mode(32t)   t = (x[1] & 0xff);      /* in big endian format     */
    x[1] = (x[1] >> 8) | (x[0] << 24);
    x[0] = (x[0] >> 8) ^ (((mode(32t))gft_be64[t]) << 16);
}

#endif

/* hence choose the correct version for the machine endianess       */

#if PLATFORM_BYTE_ORDER == BRG_BIG_ENDIAN
#define mul_x8  mul_bex8
#define mul_x8_64  mul_bex8_64
#else
#define mul_x8  mul_lex8
#define mul_x8_64  mul_lex8_64
#endif

/* different versions of the general gf_mul function are provided   */
/* here. Sadly none are very fast :-(                               */

void GfMul128 (void *a, const void* b)
{   mode(32t) r[CBLK_LEN >> 2], p[8][CBLK_LEN >> 2];
    int i;

    move_block_aligned(p[0], b);
    bsw_32(p[0], 4);
    for(i = 0; i < 7; ++i)
    {
        p[i + 1][3] = (p[i][3] >> 1) | (p[i][2] << 31);
        p[i + 1][2] = (p[i][2] >> 1) | (p[i][1] << 31);
        p[i + 1][1] = (p[i][1] >> 1) | (p[i][0] << 31);
        p[i + 1][0] = (p[i][0] >> 1) ^ gf_poly[p[i][3] & 1];
    }

    memset(r, 0, CBLK_LEN);
    for(i = 0; i < 16; ++i)
    {
        if(i) mul_bex8(r);  /* order is always big endian here */

        if(((unsigned char*)a)[15 - i] & 0x80)
            xor_block_aligned(r, p[0]);
        if(((unsigned char*)a)[15 - i] & 0x40)
            xor_block_aligned(r, p[1]);
        if(((unsigned char*)a)[15 - i] & 0x20)
            xor_block_aligned(r, p[2]);
        if(((unsigned char*)a)[15 - i] & 0x10)
            xor_block_aligned(r, p[3]);
        if(((unsigned char*)a)[15 - i] & 0x08)
            xor_block_aligned(r, p[4]);
        if(((unsigned char*)a)[15 - i] & 0x04)
            xor_block_aligned(r, p[5]);
        if(((unsigned char*)a)[15 - i] & 0x02)
            xor_block_aligned(r, p[6]);
        if(((unsigned char*)a)[15 - i] & 0x01)
            xor_block_aligned(r, p[7]);
    }
    bsw_32(r, 4);
    move_block_aligned(a, r);
}

#if defined( UNROLL_LOOPS )

#define xor_8k(i)   \
    xor_block_aligned(r, ctx->gf_t8k[i + i][a[i] & 15]); \
    xor_block_aligned(r, ctx->gf_t8k[i + i + 1][a[i] >> 4])


void GfMul128Tab (unsigned char a[CBLK_LEN], GfCtx8k *ctx)
{   unsigned __int32 r[CBLK_LEN >> 2];

    move_block_aligned(r, ctx->gf_t8k[0][a[0] & 15]);
    xor_block_aligned(r, ctx->gf_t8k[1][a[0] >> 4]);
                xor_8k( 1); xor_8k( 2); xor_8k( 3);
    xor_8k( 4); xor_8k( 5); xor_8k( 6); xor_8k( 7);
    xor_8k( 8); xor_8k( 9); xor_8k(10); xor_8k(11);
    xor_8k(12); xor_8k(13); xor_8k(14); xor_8k(15);
    move_block_aligned(a, r);
}

#else

void GfMul128Tab (unsigned char a[CBLK_LEN], GfCtx8k *ctx)
{   unsigned __int32 r[CBLK_LEN >> 2], *p;
    int i;

    p = ctx->gf_t8k[0][a[0] & 15];
    memcpy(r, p, CBLK_LEN);
    p = ctx->gf_t8k[1][a[0] >> 4];
    xor_block_aligned(r, p);
    for(i = 1; i < CBLK_LEN; ++i)
    {
        xor_block_aligned(r, ctx->gf_t8k[i + i][a[i] & 15]);
        xor_block_aligned(r, ctx->gf_t8k[i + i + 1][a[i] >> 4]);
    }
    memcpy(a, r, CBLK_LEN);
}

#endif

void compile_8k_table(unsigned __int8 *a, GfCtx8k *ctx)
{   int i, j, k;

    memset(ctx->gf_t8k, 0, 32 * 16 * 16);
    for(i = 0; i < 2 * CBLK_LEN; ++i)
    {
        if(i == 0)
        {
            memcpy(ctx->gf_t8k[1][8], a, CBLK_LEN);
            for(j = 4; j > 0; j >>= 1)
            {
                memcpy(ctx->gf_t8k[1][j], ctx->gf_t8k[1][j + j], CBLK_LEN);
                mul_x(ctx->gf_t8k[1][j]);
            }
            memcpy(ctx->gf_t8k[0][8], ctx->gf_t8k[1][1], CBLK_LEN);
            mul_x(ctx->gf_t8k[0][8]);
            for(j = 4; j > 0; j >>= 1)
            {
                memcpy(ctx->gf_t8k[0][j], ctx->gf_t8k[0][j + j], CBLK_LEN);
                mul_x(ctx->gf_t8k[0][j]);
            }
        }
        else if(i > 1)
            for(j = 8; j > 0; j >>= 1)
            {
                memcpy(ctx->gf_t8k[i][j], ctx->gf_t8k[i - 2][j], CBLK_LEN);
                mul_x8(ctx->gf_t8k[i][j]);
            }

        for(j = 2; j < 16; j += j)
        {
            mode(32t) *pj = ctx->gf_t8k[i][j];
            mode(32t) *pk = ctx->gf_t8k[i][1];
            mode(32t) *pl = ctx->gf_t8k[i][j + 1];

            for(k = 1; k < j; ++k)
            {
                *pl++ = pj[0] ^ *pk++;
                *pl++ = pj[1] ^ *pk++;
                *pl++ = pj[2] ^ *pk++;
                *pl++ = pj[3] ^ *pk++;
            }
        }
    }
}


void compile_4k_table64(unsigned __int8 *a, GfCtx4k64 *ctx)
{   int i, j, k;

    memset(ctx->gf_t4k, 0, sizeof(ctx->gf_t4k));
    for(i = 0; i < 2 * CBLK_LEN8; ++i)
    {
        if(i == 0)
        {
            memcpy(ctx->gf_t4k[1][8], a, CBLK_LEN8);
            for(j = 4; j > 0; j >>= 1)
            {
                memcpy(ctx->gf_t4k[1][j], ctx->gf_t4k[1][j + j], CBLK_LEN8);
                mul_x64(ctx->gf_t4k[1][j]);
            }
            memcpy(ctx->gf_t4k[0][8], ctx->gf_t4k[1][1], CBLK_LEN8);
            mul_x64(ctx->gf_t4k[0][8]);
            for(j = 4; j > 0; j >>= 1)
            {
                memcpy(ctx->gf_t4k[0][j], ctx->gf_t4k[0][j + j], CBLK_LEN8);
                mul_x64(ctx->gf_t4k[0][j]);
            }
        }
        else if(i > 1)
            for(j = 8; j > 0; j >>= 1)
            {
                memcpy(ctx->gf_t4k[i][j], ctx->gf_t4k[i - 2][j], CBLK_LEN8);
                mul_x8_64(ctx->gf_t4k[i][j]);
            }

        for(j = 2; j < 16; j += j)
        {
            mode(32t) *pj = ctx->gf_t4k[i][j];
            mode(32t) *pk = ctx->gf_t4k[i][1];
            mode(32t) *pl = ctx->gf_t4k[i][j + 1];

            for(k = 1; k < j; ++k)
            {
                *pl++ = pj[0] ^ *pk++;
                *pl++ = pj[1] ^ *pk++;
                *pl++ = pj[2] ^ *pk++;
                *pl++ = pj[3] ^ *pk++;
            }
        }
    }
}

static int IsBitSet128 (unsigned int bit, unsigned __int8 *a)
{
	return a[(127 - bit) / 8] & (0x80 >> ((127 - bit) % 8));
}

static int IsBitSet64 (unsigned int bit, unsigned __int8 *a)
{
	return a[(63 - bit) / 8] & (0x80 >> ((63 - bit) % 8));
}

static void SetBit128 (unsigned int bit, unsigned __int8 *a)
{
	a[(127 - bit) / 8] |= 0x80 >> ((127 - bit) % 8);
}

static void SetBit64 (unsigned int bit, unsigned __int8 *a)
{
	a[(63 - bit) / 8] |= 0x80 >> ((63 - bit) % 8);
}

void MirrorBits128 (unsigned __int8 *a)
{
	unsigned __int8 t[128 / 8];
	int i;
	memset (t,0,16);
	for (i = 0; i < 128; i++)
	{
		if (IsBitSet128(i, a))
			SetBit128 (127 - i, t);
	}
	memcpy (a, t, sizeof (t));
	burn (t,sizeof (t));
}

void MirrorBits64 (unsigned __int8 *a)
{
	unsigned __int8 t[64 / 8];
	int i;
	memset (t,0,8);
	for (i = 0; i < 64; i++)
	{
		if (IsBitSet64(i, a))
			SetBit64 (63 - i, t);
	}
	memcpy (a, t, sizeof (t));
	burn (t,sizeof (t));
}

/* Allocate and initialize speed optimization table
   for multiplication by 64-bit operand in MSB-first mode */
int Gf128Tab64Init (unsigned __int8 *a, GfCtx *ctx)
{
	GfCtx8k *ctx8k;
	unsigned __int8 am[16];
	int i, j;

	ctx8k = (GfCtx8k *) TCalloc (sizeof (GfCtx8k));
	if (!ctx8k)
		return FALSE;

	memcpy (am, a, 16);
	MirrorBits128 (am);
    compile_8k_table (am, ctx8k);

	/* Convert 8k LSB-first table to 4k MSB-first */
	for (i = 16; i < 32; i++) 
	{
		for (j = 0; j < 16; j++) 
		{
			int jm = 0;
			jm |= (j & 0x1) << 3;
			jm |= (j & 0x2) << 1;
			jm |= (j & 0x4) >> 1;
			jm |= (j & 0x8) >> 3;

			memcpy (&ctx->gf_t128[i-16][jm], (unsigned char *)&ctx8k->gf_t8k[31-i][j], 16);
			MirrorBits128 ((unsigned char *)&ctx->gf_t128[i-16][jm]);
		}
	}

	burn (ctx8k ,sizeof (*ctx8k));
	burn (am, sizeof (am));
	TCfree (ctx8k);
	return TRUE;
}


#define xor_8kt64(i)   \
    xor_block_aligned(r, ctx->gf_t128[i + i][a[i] & 15]); \
    xor_block_aligned(r, ctx->gf_t128[i + i + 1][a[i] >> 4])

/* Multiply a 128-bit number by a 64-bit number in the finite field GF(2^128) */
void Gf128MulBy64Tab (unsigned __int8 a[8], unsigned __int8 p[16], GfCtx *ctx)
{  
	unsigned __int32 r[CBLK_LEN >> 2];

	move_block_aligned(r, ctx->gf_t128[7*2][a[7] & 15]);
    xor_block_aligned(r,  ctx->gf_t128[7*2+1][a[7] >> 4]);

	if (*(unsigned __int16 *)a)
	{
		xor_8kt64(0);
		xor_8kt64(1);
	}
	if (a[2])
	{
		xor_8kt64(2);
	}
	xor_8kt64(3);
    xor_8kt64(4);
	xor_8kt64(5);
	xor_8kt64(6);

    move_block_aligned(p, r);
}



/* Basic algorithms for testing of optimized algorithms */

static void xor128 (uint64 *a, uint64 *b)
{
	*a++ ^= *b++;
	*a ^= *b;
}

static void shl128 (unsigned __int8 *a)
{
	int i, x = 0, xx;
	for (i = 15; i >= 0; i--)
	{
		xx = (a[i] & 0x80) >> 7;
		a[i] = (char) ((a[i] << 1) | x);
		x = xx;
	}
}

static void GfMul128Basic (unsigned __int8 *a, unsigned __int8 *b, unsigned __int8 *p)
{
	int i;
	unsigned __int8 la[16];
	memcpy (la, a, 16);
	memset (p, 0, 16);

	for (i = 0; i < 128; i++)
	{
		if (IsBitSet128 (i, b))
			xor128 ((uint64 *)p, (uint64 *)la);

		if (la[0] & 0x80)
		{
			shl128 (la);
			la[15] ^= 0x87;
		}
		else
		{
			shl128 (la);
		}
	}
}

static void xor64 (uint64 *a, uint64 *b)
{
	*a ^= *b;
}

static void shl64 (unsigned __int8 *a)
{
	int i, x = 0, xx;
	for (i = 7; i >= 0; i--)
	{
		xx = (a[i] & 0x80) >> 7;
		a[i] = (char) ((a[i] << 1) | x);
		x = xx;
	}
}


BOOL GfMulSelfTest ()
{
	BOOL result = TRUE;
	unsigned __int8 a[16];
	unsigned __int8 b[16];
	unsigned __int8 p1[16];
	unsigned __int8 p2[16];
	GfCtx *gfCtx = (GfCtx *) TCalloc (sizeof (GfCtx));
	int i, j;

	if (!gfCtx)
		return FALSE;


	/* GF(2^128) */
	for (i = 0; i < 0x100; i++)
	{
		for (j = 0; j < 16; j++)
		{
			a[j] = (unsigned __int8) i;
			b[j] = j < 8 ? 0 : a[j] ^ 0xff;
		}

		GfMul128Basic (a, b, p1);
	
		Gf128Tab64Init (a, gfCtx);
		Gf128MulBy64Tab (b + 8, p2, gfCtx);

		if (memcmp (p1, p2, 16) != 0)
			result = FALSE;
	}

	TCfree (gfCtx);
	return result;
}

#if defined(__cplusplus)
}
#endif
