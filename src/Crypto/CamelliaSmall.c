/*
 *  Camellia implementation
 *
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */
/*
 *  The Camellia block cipher was designed by NTT and Mitsubishi Electric
 *  Corporation.
 *
 *  http://info.isl.ntt.co.jp/crypt/eng/camellia/dl/01espec.pdf
 */

/* Adapted for VeraCrypt */

#ifdef TC_WINDOWS_BOOT
#pragma optimize ("t", on)
#endif

#include "camelliaSmall.h"
#include <memory.h>


//#define MBEDTLS_CAMELLIA_SMALL_MEMORY

/*
 * 32-bit integer manipulation macros (big endian)
 */
#ifndef GET_UINT32_BE
#define GET_UINT32_BE(n,b,i)                            \
{                                                       \
    (n) = ( (unsigned __int32) (b)[(i)    ] << 24 );             \
    (n)|= ( (unsigned __int32) (b)[(i) + 1] << 16 );             \
    (n)|= ( (unsigned __int32) (b)[(i) + 2] <<  8 );             \
    (n)|= ( (unsigned __int32) (b)[(i) + 3]       );            \
}
#endif

#ifndef PUT_UINT32_BE
#define PUT_UINT32_BE(n,b,i)                            \
{                                                       \
    (b)[(i)    ] = (unsigned char) ( (n) >> 24 );       \
    (b)[(i) + 1] = (unsigned char) ( (n) >> 16 );       \
    (b)[(i) + 2] = (unsigned char) ( (n) >>  8 );       \
    (b)[(i) + 3] = (unsigned char) ( (n)       );       \
}
#endif

static const unsigned char SIGMA_CHARS[6][8] =
{
    { 0xa0, 0x9e, 0x66, 0x7f, 0x3b, 0xcc, 0x90, 0x8b },
    { 0xb6, 0x7a, 0xe8, 0x58, 0x4c, 0xaa, 0x73, 0xb2 },
    { 0xc6, 0xef, 0x37, 0x2f, 0xe9, 0x4f, 0x82, 0xbe },
    { 0x54, 0xff, 0x53, 0xa5, 0xf1, 0xd3, 0x6f, 0x1c },
    { 0x10, 0xe5, 0x27, 0xfa, 0xde, 0x68, 0x2d, 0x1d },
    { 0xb0, 0x56, 0x88, 0xc2, 0xb3, 0xe6, 0xc1, 0xfd }
};

#if defined(MBEDTLS_CAMELLIA_SMALL_MEMORY)

static const unsigned char FSb[256] =
{
    112,130, 44,236,179, 39,192,229,228,133, 87, 53,234, 12,174, 65,
     35,239,107,147, 69, 25,165, 33,237, 14, 79, 78, 29,101,146,189,
    134,184,175,143,124,235, 31,206, 62, 48,220, 95, 94,197, 11, 26,
    166,225, 57,202,213, 71, 93, 61,217,  1, 90,214, 81, 86,108, 77,
    139, 13,154,102,251,204,176, 45,116, 18, 43, 32,240,177,132,153,
    223, 76,203,194, 52,126,118,  5,109,183,169, 49,209, 23,  4,215,
     20, 88, 58, 97,222, 27, 17, 28, 50, 15,156, 22, 83, 24,242, 34,
    254, 68,207,178,195,181,122,145, 36,  8,232,168, 96,252,105, 80,
    170,208,160,125,161,137, 98,151, 84, 91, 30,149,224,255,100,210,
     16,196,  0, 72,163,247,117,219,138,  3,230,218,  9, 63,221,148,
    135, 92,131,  2,205, 74,144, 51,115,103,246,243,157,127,191,226,
     82,155,216, 38,200, 55,198, 59,129,150,111, 75, 19,190, 99, 46,
    233,121,167,140,159,110,188,142, 41,245,249,182, 47,253,180, 89,
    120,152,  6,106,231, 70,113,186,212, 37,171, 66,136,162,141,250,
    114,  7,185, 85,248,238,172, 10, 54, 73, 42,104, 60, 56,241,164,
     64, 40,211,123,187,201, 67,193, 21,227,173,244,119,199,128,158
};

#define SBOX1(n) FSb[(n)]
#define SBOX2(n) (unsigned char)((FSb[(n)] >> 7 ^ FSb[(n)] << 1) & 0xff)
#define SBOX3(n) (unsigned char)((FSb[(n)] >> 1 ^ FSb[(n)] << 7) & 0xff)
#define SBOX4(n) FSb[((n) << 1 ^ (n) >> 7) &0xff]

#else /* MBEDTLS_CAMELLIA_SMALL_MEMORY */

static const unsigned char FSb[256] =
{
 112, 130,  44, 236, 179,  39, 192, 229, 228, 133,  87,  53, 234,  12, 174,  65,
  35, 239, 107, 147,  69,  25, 165,  33, 237,  14,  79,  78,  29, 101, 146, 189,
 134, 184, 175, 143, 124, 235,  31, 206,  62,  48, 220,  95,  94, 197,  11,  26,
 166, 225,  57, 202, 213,  71,  93,  61, 217,   1,  90, 214,  81,  86, 108,  77,
 139,  13, 154, 102, 251, 204, 176,  45, 116,  18,  43,  32, 240, 177, 132, 153,
 223,  76, 203, 194,  52, 126, 118,   5, 109, 183, 169,  49, 209,  23,   4, 215,
  20,  88,  58,  97, 222,  27,  17,  28,  50,  15, 156,  22,  83,  24, 242,  34,
 254,  68, 207, 178, 195, 181, 122, 145,  36,   8, 232, 168,  96, 252, 105,  80,
 170, 208, 160, 125, 161, 137,  98, 151,  84,  91,  30, 149, 224, 255, 100, 210,
  16, 196,   0,  72, 163, 247, 117, 219, 138,   3, 230, 218,   9,  63, 221, 148,
 135,  92, 131,   2, 205,  74, 144,  51, 115, 103, 246, 243, 157, 127, 191, 226,
  82, 155, 216,  38, 200,  55, 198,  59, 129, 150, 111,  75,  19, 190,  99,  46,
 233, 121, 167, 140, 159, 110, 188, 142,  41, 245, 249, 182,  47, 253, 180,  89,
 120, 152,   6, 106, 231,  70, 113, 186, 212,  37, 171,  66, 136, 162, 141, 250,
 114,   7, 185,  85, 248, 238, 172,  10,  54,  73,  42, 104,  60,  56, 241, 164,
 64,  40, 211, 123, 187, 201,  67, 193,  21, 227, 173, 244, 119, 199, 128, 158
};

static const unsigned char FSb2[256] =
{
 224,   5,  88, 217, 103,  78, 129, 203, 201,  11, 174, 106, 213,  24,  93, 130,
  70, 223, 214,  39, 138,  50,  75,  66, 219,  28, 158, 156,  58, 202,  37, 123,
  13, 113,  95,  31, 248, 215,  62, 157, 124,  96, 185, 190, 188, 139,  22,  52,
  77, 195, 114, 149, 171, 142, 186, 122, 179,   2, 180, 173, 162, 172, 216, 154,
  23,  26,  53, 204, 247, 153,  97,  90, 232,  36,  86,  64, 225,  99,   9,  51,
 191, 152, 151, 133, 104, 252, 236,  10, 218, 111,  83,  98, 163,  46,   8, 175,
  40, 176, 116, 194, 189,  54,  34,  56, 100,  30,  57,  44, 166,  48, 229,  68,
 253, 136, 159, 101, 135, 107, 244,  35,  72,  16, 209,  81, 192, 249, 210, 160,
  85, 161,  65, 250,  67,  19, 196,  47, 168, 182,  60,  43, 193, 255, 200, 165,
  32, 137,   0, 144,  71, 239, 234, 183,  21,   6, 205, 181,  18, 126, 187,  41,
  15, 184,   7,   4, 155, 148,  33, 102, 230, 206, 237, 231,  59, 254, 127, 197,
 164,  55, 177,  76, 145, 110, 141, 118,   3,  45, 222, 150,  38, 125, 198,  92,
 211, 242,  79,  25,  63, 220, 121,  29,  82, 235, 243, 109,  94, 251, 105, 178,
 240,  49,  12, 212, 207, 140, 226, 117, 169,  74,  87, 132,  17,  69,  27, 245,
 228,  14, 115, 170, 241, 221,  89,  20, 108, 146,  84, 208, 120, 112, 227,  73,
 128,  80, 167, 246, 119, 147, 134, 131,  42, 199,  91, 233, 238, 143,   1,  61
};

static const unsigned char FSb3[256] =
{
  56,  65,  22, 118, 217, 147,  96, 242, 114, 194, 171, 154, 117,   6,  87, 160,
 145, 247, 181, 201, 162, 140, 210, 144, 246,   7, 167,  39, 142, 178,  73, 222,
  67,  92, 215, 199,  62, 245, 143, 103,  31,  24, 110, 175,  47, 226, 133,  13,
  83, 240, 156, 101, 234, 163, 174, 158, 236, 128,  45, 107, 168,  43,  54, 166,
 197, 134,  77,  51, 253, 102,  88, 150,  58,   9, 149,  16, 120, 216,  66, 204,
 239,  38, 229,  97,  26,  63,  59, 130, 182, 219, 212, 152, 232, 139,   2, 235,
  10,  44,  29, 176, 111, 141, 136,  14,  25, 135,  78,  11, 169,  12, 121,  17,
 127,  34, 231,  89, 225, 218,  61, 200,  18,   4, 116,  84,  48, 126, 180,  40,
  85, 104,  80, 190, 208, 196,  49, 203,  42, 173,  15, 202, 112, 255,  50, 105,
   8,  98,   0,  36, 209, 251, 186, 237,  69, 129, 115, 109, 132, 159, 238,  74,
 195,  46, 193,   1, 230,  37,  72, 153, 185, 179, 123, 249, 206, 191, 223, 113,
  41, 205, 108,  19, 100, 155,  99, 157, 192,  75, 183, 165, 137,  95, 177,  23,
 244, 188, 211,  70, 207,  55,  94,  71, 148, 250, 252,  91, 151, 254,  90, 172,
  60,  76,   3,  53, 243,  35, 184,  93, 106, 146, 213,  33,  68,  81, 198, 125,
  57, 131, 220, 170, 124, 119,  86,   5,  27, 164,  21,  52,  30,  28, 248,  82,
  32,  20, 233, 189, 221, 228, 161, 224, 138, 241, 214, 122, 187, 227,  64,  79
};

static const unsigned char FSb4[256] =
{
 112,  44, 179, 192, 228,  87, 234, 174,  35, 107,  69, 165, 237,  79,  29, 146,
 134, 175, 124,  31,  62, 220,  94,  11, 166,  57, 213,  93, 217,  90,  81, 108,
 139, 154, 251, 176, 116,  43, 240, 132, 223, 203,  52, 118, 109, 169, 209,   4,
  20,  58, 222,  17,  50, 156,  83, 242, 254, 207, 195, 122,  36, 232,  96, 105,
 170, 160, 161,  98,  84,  30, 224, 100,  16,   0, 163, 117, 138, 230,   9, 221,
 135, 131, 205, 144, 115, 246, 157, 191,  82, 216, 200, 198, 129, 111,  19,  99,
 233, 167, 159, 188,  41, 249,  47, 180, 120,   6, 231, 113, 212, 171, 136, 141,
 114, 185, 248, 172,  54,  42,  60, 241,  64, 211, 187,  67,  21, 173, 119, 128,
 130, 236,  39, 229, 133,  53,  12,  65, 239, 147,  25,  33,  14,  78, 101, 189,
 184, 143, 235, 206,  48,  95, 197,  26, 225, 202,  71,  61,   1, 214,  86,  77,
  13, 102, 204,  45,  18,  32, 177, 153,  76, 194, 126,   5, 183,  49,  23, 215,
  88,  97,  27,  28,  15,  22,  24,  34,  68, 178, 181, 145,   8, 168, 252,  80,
 208, 125, 137, 151,  91, 149, 255, 210, 196,  72, 247, 219,   3, 218,  63, 148,
  92,   2,  74,  51, 103, 243, 127, 226, 155,  38,  55,  59, 150,  75, 190,  46,
 121, 140, 110, 142, 245, 182, 253,  89, 152, 106,  70, 186,  37,  66, 162, 250,
  7,  85, 238,  10,  73, 104,  56, 164,  40, 123, 201, 193, 227, 244, 199, 158
};

#define SBOX1(n) FSb[(n)]
#define SBOX2(n) FSb2[(n)]
#define SBOX3(n) FSb3[(n)]
#define SBOX4(n) FSb4[(n)]

#endif /* MBEDTLS_CAMELLIA_SMALL_MEMORY */

static const unsigned char shifts[4][4] =
{
	{ 1, 0, 1, 1 }, /* KL */
	{ 1, 1, 0, 1 }, /* KR */
	{ 1, 1, 1, 0 }, /* KA */
	{ 1, 1, 0, 1 }  /* KB */
};

static const signed char indexes[4][20] =
{
	{  0,  1,  2,  3, 61, 62, 63, 60, -1, -1,
	  -1, -1, 27, 24, 25, 26, 35, 32, 33, 34 }, /* KL -> RK */
	{ -1, -1, -1, -1,  8,  9, 10, 11, 16, 17,
	  18, 19, -1, -1, -1, -1, 39, 36, 37, 38 }, /* KR -> RK */
	{ -1, -1, -1, -1, 12, 13, 14, 15, 58, 59,
	  56, 57, 31, 28, 29, 30, -1, -1, -1, -1 }, /* KA -> RK */
	{  4,  5,  6,  7, 65, 66, 67, 64, 20, 21,
	  22, 23, -1, -1, -1, -1, 43, 40, 41, 42 }  /* KB -> RK */
};

static const signed char transposes[20] =
{
	25, 26, 27, 24,
	29, 30, 31, 28,
	18, 19, 16, 17,
	-1, -1, -1, -1,
	-1, -1, -1, -1
};

/* Shift macro for 128 bit strings with rotation smaller than 32 bits (!) */
#define ROTL(DEST, SRC, SHIFT)                                      \
{                                                                   \
    (DEST)[0] = (SRC)[0] << (SHIFT) ^ (SRC)[1] >> (32 - (SHIFT));   \
    (DEST)[1] = (SRC)[1] << (SHIFT) ^ (SRC)[2] >> (32 - (SHIFT));   \
    (DEST)[2] = (SRC)[2] << (SHIFT) ^ (SRC)[3] >> (32 - (SHIFT));   \
    (DEST)[3] = (SRC)[3] << (SHIFT) ^ (SRC)[0] >> (32 - (SHIFT));   \
}

#define FL(XL, XR, KL, KR)                                          \
{                                                                   \
    (XR) = ((((XL) & (KL)) << 1) | (((XL) & (KL)) >> 31)) ^ (XR);   \
    (XL) = ((XR) | (KR)) ^ (XL);                                    \
}

#define FLInv(YL, YR, KL, KR)                                       \
{                                                                   \
    (YL) = ((YR) | (KR)) ^ (YL);                                    \
    (YR) = ((((YL) & (KL)) << 1) | (((YL) & (KL)) >> 31)) ^ (YR);   \
}

#define SHIFT_AND_PLACE(OFFSET)                      \
{                                                           \
    TK[0] = KC[(OFFSET) * 4 + 0];                           \
    TK[1] = KC[(OFFSET) * 4 + 1];                           \
    TK[2] = KC[(OFFSET) * 4 + 2];                           \
    TK[3] = KC[(OFFSET) * 4 + 3];                           \
                                                            \
    for( i = 1; i <= 4; i++ )                               \
        if( shifts[(OFFSET)][i -1] )               \
            ROTL(TK + i * 4, TK, ( 15 * i ) % 32);          \
                                                            \
    for( i = 0; i < 20; i++ )                               \
        if( indexes[(OFFSET)][i] != -1 ) {         \
            RK[indexes[(OFFSET)][i]] = TK[ i ];    \
        }                                                   \
}

static void camellia_feistel( const unsigned __int32 x[2], const unsigned __int32 k[2],
                              unsigned __int32 z[2])
{
    unsigned __int32 I0, I1;
    I0 = x[0] ^ k[0];
    I1 = x[1] ^ k[1];

    I0 = ((unsigned __int32) SBOX1((I0 >> 24) & 0xFF) << 24) |
         ((unsigned __int32) SBOX2((I0 >> 16) & 0xFF) << 16) |
         ((unsigned __int32) SBOX3((I0 >>  8) & 0xFF) <<  8) |
         ((unsigned __int32) SBOX4((I0      ) & 0xFF)      );
    I1 = ((unsigned __int32) SBOX2((I1 >> 24) & 0xFF) << 24) |
         ((unsigned __int32) SBOX3((I1 >> 16) & 0xFF) << 16) |
         ((unsigned __int32) SBOX4((I1 >>  8) & 0xFF) <<  8) |
         ((unsigned __int32) SBOX1((I1      ) & 0xFF)      );

    I0 ^= (I1 << 8) | (I1 >> 24);
    I1 ^= (I0 << 16) | (I0 >> 16);
    I0 ^= (I1 >> 8) | (I1 << 24);
    I1 ^= (I0 >> 8) | (I0 << 24);

    z[0] ^= I1;
    z[1] ^= I0;
}

/*
 * Camellia key schedule (encryption)
 */
void mbedtls_camellia_setkey_enc( const unsigned char *key, unsigned __int32 *RK)
{
    int i;
    unsigned char t[64];
    unsigned __int32 SIGMA[6][2];
    unsigned __int32 KC[16];
    unsigned __int32 TK[20];

    memset( t, 0, 64 );
    memset( RK, 0, CAMELLIA_KS/2 );

    for( i = 0; i < 32; ++i )
        t[i] = key[i];

    /*
     * Prepare SIGMA values
     */
    for( i = 0; i < 6; i++ ) {
        GET_UINT32_BE( SIGMA[i][0], SIGMA_CHARS[i], 0 );
        GET_UINT32_BE( SIGMA[i][1], SIGMA_CHARS[i], 4 );
    }

    /*
     * Key storage in KC
     * Order: KL, KR, KA, KB
     */
    memset( KC, 0, sizeof(KC) );

    /* Store KL, KR */
    for( i = 0; i < 8; i++ )
        GET_UINT32_BE( KC[i], t, i * 4 );

    /* Generate KA */
    for( i = 0; i < 4; ++i )
        KC[8 + i] = KC[i] ^ KC[4 + i];

    camellia_feistel( KC + 8, SIGMA[0], KC + 10 );
    camellia_feistel( KC + 10, SIGMA[1], KC + 8 );

    for( i = 0; i < 4; ++i )
        KC[8 + i] ^= KC[i];

    camellia_feistel( KC + 8, SIGMA[2], KC + 10 );
    camellia_feistel( KC + 10, SIGMA[3], KC + 8 );

	/* Generate KB */
	for( i = 0; i < 4; ++i )
		KC[12 + i] = KC[4 + i] ^ KC[8 + i];

	camellia_feistel( KC + 12, SIGMA[4], KC + 14 );
	camellia_feistel( KC + 14, SIGMA[5], KC + 12 );

    /*
     * Generating subkeys
     */

    /* Manipulating KL */
    SHIFT_AND_PLACE( 0 );

    /* Manipulating KR */
    SHIFT_AND_PLACE( 1 );

    /* Manipulating KA */
    SHIFT_AND_PLACE( 2 );

    /* Manipulating KB */
    SHIFT_AND_PLACE( 3 );

    /* Do transpositions */
    for( i = 0; i < 20; i++ ) {
        if( transposes[i] != -1 ) {
            RK[32 + 12 + i] = RK[transposes[i]];
        }
    }
}

/*
 * Camellia key schedule (decryption)
 */
void camellia_set_key(const unsigned __int8 key[], unsigned __int8 *ks)
{
    int i;
    unsigned __int32 *RK = (unsigned __int32 *) (ks + (CAMELLIA_KS /2));
    unsigned __int32 *SK;

    mbedtls_camellia_setkey_enc( key, (unsigned __int32 *) ks );

    SK = ((unsigned __int32 *) ks) + 24 * 2 + 8 * 2;

    *RK++ = *SK++;
    *RK++ = *SK++;
    *RK++ = *SK++;
    *RK++ = *SK++;

    for( i = 22 + 8, SK -= 6; i > 0; i--, SK -= 4 )
    {
        *RK++ = *SK++;
        *RK++ = *SK++;
    }

    SK -= 2;

    *RK++ = *SK++;
    *RK++ = *SK++;
    *RK++ = *SK++;
    *RK++ = *SK++;
}

/*
 * Camellia-ECB block encryption/decryption
 */
void mbedtls_camellia_crypt_ecb(const unsigned __int8 *input,
                    unsigned __int8 *output,  unsigned __int8 * ks)
{
    int NR = 4;
	unsigned __int32 *RK = (unsigned __int32 *) ks;
    unsigned __int32 X[4];

    GET_UINT32_BE( X[0], input,  0 );
    GET_UINT32_BE( X[1], input,  4 );
    GET_UINT32_BE( X[2], input,  8 );
    GET_UINT32_BE( X[3], input, 12 );

    X[0] ^= *RK++;
    X[1] ^= *RK++;
    X[2] ^= *RK++;
    X[3] ^= *RK++;

    while( NR ) {
        --NR;
        camellia_feistel( X, RK, X + 2 );
        RK += 2;
        camellia_feistel( X + 2, RK, X );
        RK += 2;
        camellia_feistel( X, RK, X + 2 );
        RK += 2;
        camellia_feistel( X + 2, RK, X );
        RK += 2;
        camellia_feistel( X, RK, X + 2 );
        RK += 2;
        camellia_feistel( X + 2, RK, X );
        RK += 2;

        if( NR ) {
            FL(X[0], X[1], RK[0], RK[1]);
            RK += 2;
            FLInv(X[2], X[3], RK[0], RK[1]);
            RK += 2;
        }
    }

    X[2] ^= *RK++;
    X[3] ^= *RK++;
    X[0] ^= *RK++;
    X[1] ^= *RK++;

    PUT_UINT32_BE( X[2], output,  0 );
    PUT_UINT32_BE( X[3], output,  4 );
    PUT_UINT32_BE( X[0], output,  8 );
    PUT_UINT32_BE( X[1], output, 12 );
}

void camellia_encrypt(const unsigned __int8 *inBlock, unsigned __int8 *outBlock, unsigned __int8 *ks)
{
	mbedtls_camellia_crypt_ecb (inBlock, outBlock, ks);
}

void camellia_decrypt(const unsigned __int8 *inBlock,  unsigned __int8 *outBlock, unsigned __int8 *ks)
{
	mbedtls_camellia_crypt_ecb (inBlock, outBlock, ks + (CAMELLIA_KS / 2));
}

