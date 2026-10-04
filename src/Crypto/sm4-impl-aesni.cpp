/*******************************************************************************
* Copyright 2014 Intel Corporation
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*     http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*******************************************************************************/

// Modified by kerukuro for use in cppcrypto.
// Modified by Mounir IDRASSI for use in VeraCrypt.

#include "sm4.h"
#include "Common/Endian.h"
#include "misc.h"
#include "cpu.h"

#if CRYPTOPP_BOOL_SSE41_INTRINSICS_AVAILABLE && CRYPTOPP_BOOL_AESNI_INTRINSICS_AVAILABLE

//#include <immintrin.h>
//#include <emmintrin.h>

#define Ipp32u uint32
#define Ipp32s int32
#define Ipp8u uint8
#define ENDIANNESS32(x) ByteReverseWord32(x)


    CRYPTOPP_ALIGN_DATA(16) Ipp32u SMS4_FK[4] = {
       0xA3B1BAC6,0x56AA3350,0x677D9197,0xB27022DC
    };

    /* CK[] constants */
    CRYPTOPP_ALIGN_DATA(16) Ipp32u SMS4_CK[32] =
    {
       0x00070E15,0x1C232A31,0x383F464D,0x545B6269,
       0x70777E85,0x8C939AA1,0xA8AFB6BD,0xC4CBD2D9,
       0xE0E7EEF5,0xFC030A11,0x181F262D,0x343B4249,
       0x50575E65,0x6C737A81,0x888F969D,0xA4ABB2B9,
       0xC0C7CED5,0xDCE3EAF1,0xF8FF060D,0x141B2229,
       0x30373E45,0x4C535A61,0x686F767D,0x848B9299,
       0xA0A7AEB5,0xBCC3CAD1,0xD8DFE6ED,0xF4FB0209,
       0x10171E25,0x2C333A41,0x484F565D,0x646B7279
    };

    CRYPTOPP_ALIGN_DATA(64) const Ipp8u SMS4_Sbox[16 * 16] = {
       0xD6,0x90,0xE9,0xFE,0xCC,0xE1,0x3D,0xB7,0x16,0xB6,0x14,0xC2,0x28,0xFB,0x2C,0x05,
       0x2B,0x67,0x9A,0x76,0x2A,0xBE,0x04,0xC3,0xAA,0x44,0x13,0x26,0x49,0x86,0x06,0x99,
       0x9C,0x42,0x50,0xF4,0x91,0xEF,0x98,0x7A,0x33,0x54,0x0B,0x43,0xED,0xCF,0xAC,0x62,
       0xE4,0xB3,0x1C,0xA9,0xC9,0x08,0xE8,0x95,0x80,0xDF,0x94,0xFA,0x75,0x8F,0x3F,0xA6,
       0x47,0x07,0xA7,0xFC,0xF3,0x73,0x17,0xBA,0x83,0x59,0x3C,0x19,0xE6,0x85,0x4F,0xA8,
       0x68,0x6B,0x81,0xB2,0x71,0x64,0xDA,0x8B,0xF8,0xEB,0x0F,0x4B,0x70,0x56,0x9D,0x35,
       0x1E,0x24,0x0E,0x5E,0x63,0x58,0xD1,0xA2,0x25,0x22,0x7C,0x3B,0x01,0x21,0x78,0x87,
       0xD4,0x00,0x46,0x57,0x9F,0xD3,0x27,0x52,0x4C,0x36,0x02,0xE7,0xA0,0xC4,0xC8,0x9E,
       0xEA,0xBF,0x8A,0xD2,0x40,0xC7,0x38,0xB5,0xA3,0xF7,0xF2,0xCE,0xF9,0x61,0x15,0xA1,
       0xE0,0xAE,0x5D,0xA4,0x9B,0x34,0x1A,0x55,0xAD,0x93,0x32,0x30,0xF5,0x8C,0xB1,0xE3,
       0x1D,0xF6,0xE2,0x2E,0x82,0x66,0xCA,0x60,0xC0,0x29,0x23,0xAB,0x0D,0x53,0x4E,0x6F,
       0xD5,0xDB,0x37,0x45,0xDE,0xFD,0x8E,0x2F,0x03,0xFF,0x6A,0x72,0x6D,0x6C,0x5B,0x51,
       0x8D,0x1B,0xAF,0x92,0xBB,0xDD,0xBC,0x7F,0x11,0xD9,0x5C,0x41,0x1F,0x10,0x5A,0xD8,
       0x0A,0xC1,0x31,0x88,0xA5,0xCD,0x7B,0xBD,0x2D,0x74,0xD0,0x12,0xB8,0xE5,0xB4,0xB0,
       0x89,0x69,0x97,0x4A,0x0C,0x96,0x77,0x7E,0x65,0xB9,0xF1,0x09,0xC5,0x6E,0xC6,0x84,
       0x18,0xF0,0x7D,0xEC,0x3A,0xDC,0x4D,0x20,0x79,0xEE,0x5F,0x3E,0xD7,0xCB,0x39,0x48
    };

    CRYPTOPP_ALIGN_DATA(16) static Ipp8u inpMaskLO[] = { 0x65,0x41,0xfd,0xd9,0x0a,0x2e,0x92,0xb6,0x0f,0x2b,0x97,0xb3,0x60,0x44,0xf8,0xdc };
    CRYPTOPP_ALIGN_DATA(16) static Ipp8u inpMaskHI[] = { 0x00,0xc9,0x67,0xae,0x80,0x49,0xe7,0x2e,0x4a,0x83,0x2d,0xe4,0xca,0x03,0xad,0x64 };
    CRYPTOPP_ALIGN_DATA(16) static Ipp8u outMaskLO[] = { 0xd3,0x59,0x38,0xb2,0xcc,0x46,0x27,0xad,0x36,0xbc,0xdd,0x57,0x29,0xa3,0xc2,0x48 };
    CRYPTOPP_ALIGN_DATA(16) static Ipp8u outMaskHI[] = { 0x00,0x50,0x14,0x44,0x89,0xd9,0x9d,0xcd,0xde,0x8e,0xca,0x9a,0x57,0x07,0x43,0x13 };
    CRYPTOPP_ALIGN_DATA(16) static Ipp8u encKey[] = { 0x63,0x63,0x63,0x63,0x63,0x63,0x63,0x63,0x63,0x63,0x63,0x63,0x63,0x63,0x63,0x63 };
    CRYPTOPP_ALIGN_DATA(16) static Ipp8u maskSrows[] = { 0x00,0x0d,0x0a,0x07,0x04,0x01,0x0e,0x0b,0x08,0x05,0x02,0x0f,0x0c,0x09,0x06,0x03 };
    CRYPTOPP_ALIGN_DATA(16) static Ipp8u lowBits4[] = { 0x0f,0x0f,0x0f,0x0f,0x0f,0x0f,0x0f,0x0f,0x0f,0x0f,0x0f,0x0f,0x0f,0x0f,0x0f,0x0f };
    CRYPTOPP_ALIGN_DATA(16) static Ipp8u swapBytes[] = { 3,2,1,0, 7,6,5,4, 11,10,9,8, 15,14,13,12 };

#define M128(mem)    (*((__m128i*)((Ipp8u*)(mem))))
#define MBS_SMS4  (16)

    /*
    //
    // AES and SMS4 ciphers both based on composite field GF(2^8).
    // This affine transformation transforms 16 bytes
    // from SMS4 representation to AES representation or vise versa
    // depending on passed masks.
    //
    */

    static inline __m128i affine(__m128i x, __m128i maskLO, __m128i maskHI)
    {
        __m128i T1 = _mm_and_si128(_mm_srli_epi64(x, 4), M128(lowBits4));
        __m128i T0 = _mm_and_si128(x, M128(lowBits4));
        T0 = _mm_shuffle_epi8(maskLO, T0);
        T1 = _mm_shuffle_epi8(maskHI, T1);
        return _mm_xor_si128(T0, T1);
    }

    /*
    //
    // GF(256) is isomorfic.
    // Encoding/decoding data of SM4 and AES are elements of GF(256).
    // The difference in representation only.
    // (It happend due to using different generating polynomials in SM4 and AES representations).
    // Doing data conversion from SM4 to AES domain
    // lets use AES specific intrinsics to perform less expensive SMS4 S-box computation.
    //
    // Original SMS4 S-box algorithm is converted to the following:
    //
    // - transform  data  from  SMS4  representation  to AES representation
    // - compute S-box  value using  _mm_aesenclast_si128  with special key
    // - re-shuffle data  after _mm_aesenclast_si128 that shuffle it inside
    // - transform data back from AES representation to SMS4 representation
    //
    */

    static inline __m128i sBox(__m128i block)
    {
        block = affine(block, M128(inpMaskLO), M128(inpMaskHI));
        block = _mm_aesenclast_si128(block, M128(encKey));
        block = _mm_shuffle_epi8(block, M128(maskSrows));
        block = affine(block, M128(outMaskLO), M128(outMaskHI));

        return block;
    }

    CRYPTOPP_ALIGN_DATA(16) static Ipp8u ROL8[] = { 3,0,1,2,  7,4,5,6,  11,8,9,10,  15,12,13,14 };
    CRYPTOPP_ALIGN_DATA(16) static Ipp8u ROL16[] = { 2,3,0,1,  6,7,4,5,  10,11,8,9,  14,15,12,13 };
    CRYPTOPP_ALIGN_DATA(16) static Ipp8u ROL24[] = { 1,2,3,0,  5,6,7,4,  9,10,11,8,  13,14,15,12 };

    static inline  __m128i L(__m128i x)
    {
        __m128i rol2 = _mm_xor_si128(_mm_slli_epi32(x, 2), _mm_srli_epi32(x, 30));
        __m128i rol24 = _mm_shuffle_epi8(x, M128(ROL24));
        __m128i rol10 = _mm_shuffle_epi8(rol2, M128(ROL8));
        __m128i rol18 = _mm_shuffle_epi8(rol2, M128(ROL16));
        __m128i R = _mm_xor_si128(rol24, _mm_xor_si128(rol18, _mm_xor_si128(rol2, rol10)));
        return R;
    }

#define TRANSPOSE_INP(K0,K1,K2,K3, T) \
   T  = _mm_unpacklo_epi32(K0, K1); \
   K1 = _mm_unpackhi_epi32(K0, K1); \
   K0 = _mm_unpacklo_epi32(K2, K3); \
   K3 = _mm_unpackhi_epi32(K2, K3); \
   \
   K2 = _mm_unpacklo_epi64(K1, K3); \
   K3 = _mm_unpackhi_epi64(K1, K3); \
   K1 = _mm_unpackhi_epi64(T,  K0); \
   K0 = _mm_unpacklo_epi64(T,  K0)

#define TRANSPOSE_OUT(K0,K1,K2,K3, T) \
   T  = _mm_unpacklo_epi32(K1, K0); \
   K0 = _mm_unpackhi_epi32(K1, K0); \
   K1 = _mm_unpacklo_epi32(K3, K2); \
   K3 = _mm_unpackhi_epi32(K3, K2); \
   \
   K2 = _mm_unpackhi_epi64(K1,  T); \
   T  = _mm_unpacklo_epi64(K1,  T); \
   K1 = _mm_unpacklo_epi64(K3, K0); \
   K0 = _mm_unpackhi_epi64(K3, K0); \
   K3 = T

static inline __m128i Ltag(__m128i x)
{
   __m128i T = _mm_slli_epi32(x, 13);
   T = _mm_xor_si128(T, _mm_srli_epi32 (x,19));
   T = _mm_xor_si128(T, _mm_slli_epi32 (x,23));
   T = _mm_xor_si128(T, _mm_srli_epi32 (x, 9));
   return T;
}

static inline void cpSMS4_SetRoundKeys_aesni(Ipp32u* pRoundKey, const Ipp8u* pSecretKey)
{
    CRYPTOPP_ALIGN_DATA(16) __m128i TMP[5];
    /*
       TMP[0] = T
       TMP[1] = K0
       TMP[2] = K1
       TMP[3] = K2
       TMP[4] = K3
    */
    TMP[1] = _mm_cvtsi32_si128((Ipp32s)(ENDIANNESS32(((Ipp32u*)pSecretKey)[0]) ^ SMS4_FK[0]));
    TMP[2] = _mm_cvtsi32_si128((Ipp32s)(ENDIANNESS32(((Ipp32u*)pSecretKey)[1]) ^ SMS4_FK[1]));
    TMP[3] = _mm_cvtsi32_si128((Ipp32s)(ENDIANNESS32(((Ipp32u*)pSecretKey)[2]) ^ SMS4_FK[2]));
    TMP[4] = _mm_cvtsi32_si128((Ipp32s)(ENDIANNESS32(((Ipp32u*)pSecretKey)[3]) ^ SMS4_FK[3]));

    const Ipp32u* pCK = SMS4_CK;

    int itr;
    for (itr = 0; itr < 8; itr++) {
        /* initial xors */
        TMP[0] = _mm_cvtsi32_si128((Ipp32s)pCK[0]);
        TMP[0] = _mm_xor_si128(TMP[0], TMP[2]);
        TMP[0] = _mm_xor_si128(TMP[0], TMP[3]);
        TMP[0] = _mm_xor_si128(TMP[0], TMP[4]);
        /* Sbox */
        TMP[0] = sBox(TMP[0]);
        /* Sbox done, now Ltag */
        TMP[1] = _mm_xor_si128(_mm_xor_si128(TMP[1], TMP[0]), Ltag(TMP[0]));
        pRoundKey[0] = (Ipp32u)_mm_cvtsi128_si32(TMP[1]);

        /* initial xors */
        TMP[0] = _mm_cvtsi32_si128((Ipp32s)pCK[1]);
        TMP[0] = _mm_xor_si128(TMP[0], TMP[3]);
        TMP[0] = _mm_xor_si128(TMP[0], TMP[4]);
        TMP[0] = _mm_xor_si128(TMP[0], TMP[1]);
        /* Sbox */
        TMP[0] = sBox(TMP[0]);
        /* Sbox done, now Ltag */
        TMP[2] = _mm_xor_si128(_mm_xor_si128(TMP[2], TMP[0]), Ltag(TMP[0]));
        pRoundKey[1] = (Ipp32u)_mm_cvtsi128_si32(TMP[2]);

        /* initial xors */
        TMP[0] = _mm_cvtsi32_si128((Ipp32s)pCK[2]);
        TMP[0] = _mm_xor_si128(TMP[0], TMP[4]);
        TMP[0] = _mm_xor_si128(TMP[0], TMP[1]);
        TMP[0] = _mm_xor_si128(TMP[0], TMP[2]);
        /* Sbox */
        TMP[0] = sBox(TMP[0]);
        /* Sbox done, now Ltag */
        TMP[3] = _mm_xor_si128(_mm_xor_si128(TMP[3], TMP[0]), Ltag(TMP[0]));
        pRoundKey[2] = (Ipp32u)_mm_cvtsi128_si32(TMP[3]);

        /* initial xors */
        TMP[0] = _mm_cvtsi32_si128((Ipp32s)pCK[3]);
        TMP[0] = _mm_xor_si128(TMP[0], TMP[1]);
        TMP[0] = _mm_xor_si128(TMP[0], TMP[2]);
        TMP[0] = _mm_xor_si128(TMP[0], TMP[3]);
        /* Sbox */
        TMP[0] = sBox(TMP[0]);
        /* Sbox done, now Ltag */
        TMP[4] = _mm_xor_si128(_mm_xor_si128(TMP[4], TMP[0]), Ltag(TMP[0]));
        pRoundKey[3] = (Ipp32u)_mm_cvtsi128_si32(TMP[4]);

        pCK += 4;
        pRoundKey += 4;
    }

    /* clear secret data */
    for (size_t i = 0; i < sizeof(TMP) / sizeof(TMP[0]); i++) {
        TMP[i] = _mm_xor_si128(TMP[i], TMP[i]);
    }
}

static inline void cpSMS4_ECB_aesni_x1(Ipp8u* pOut, const Ipp8u* pInp, const Ipp32u* pRKey)
{
    CRYPTOPP_ALIGN_DATA(16) __m128i TMP[6];
    /*
       TMP[0] = T
       TMP[1] = K0
       TMP[2] = K1
       TMP[3] = K2
       TMP[4] = K3
       TMP[5] = key4
    */

    TMP[1] = _mm_shuffle_epi8(_mm_cvtsi32_si128(((Ipp32s*)pInp)[0]), M128(swapBytes));
    TMP[2] = _mm_shuffle_epi8(_mm_cvtsi32_si128(((Ipp32s*)pInp)[1]), M128(swapBytes));
    TMP[3] = _mm_shuffle_epi8(_mm_cvtsi32_si128(((Ipp32s*)pInp)[2]), M128(swapBytes));
    TMP[4] = _mm_shuffle_epi8(_mm_cvtsi32_si128(((Ipp32s*)pInp)[3]), M128(swapBytes));

    int itr;
    for (itr = 0; itr < 8; itr++, pRKey += 4) {
        TMP[5] = _mm_loadu_si128((__m128i*)pRKey);
        /* initial xors */
        TMP[0] = _mm_shuffle_epi32(TMP[5], 0x00); /* broadcast(key4 TMP[0]) */
        TMP[0] = _mm_xor_si128(TMP[0], TMP[2]);
        TMP[0] = _mm_xor_si128(TMP[0], TMP[3]);
        TMP[0] = _mm_xor_si128(TMP[0], TMP[4]);
        /* Sbox */
        TMP[0] = sBox(TMP[0]);
        /* Sbox done, now L */
        TMP[1] = _mm_xor_si128(_mm_xor_si128(TMP[1], TMP[0]), L(TMP[0]));

        /* initial xors */
        TMP[0] = _mm_shuffle_epi32(TMP[5], 0x55); /* broadcast(key4 TMP[1]) */
        TMP[0] = _mm_xor_si128(TMP[0], TMP[3]);
        TMP[0] = _mm_xor_si128(TMP[0], TMP[4]);
        TMP[0] = _mm_xor_si128(TMP[0], TMP[1]);
        /* Sbox */
        TMP[0] = sBox(TMP[0]);
        /* Sbox done, now L */
        TMP[2] = _mm_xor_si128(_mm_xor_si128(TMP[2], TMP[0]), L(TMP[0]));

        /* initial xors */
        TMP[0] = _mm_shuffle_epi32(TMP[5], 0xAA); /* broadcast(key4 TMP[2]) */
        TMP[0] = _mm_xor_si128(TMP[0], TMP[4]);
        TMP[0] = _mm_xor_si128(TMP[0], TMP[1]);
        TMP[0] = _mm_xor_si128(TMP[0], TMP[2]);
        /* Sbox */
        TMP[0] = sBox(TMP[0]);
        /* Sbox done, now L */
        TMP[3] = _mm_xor_si128(_mm_xor_si128(TMP[3], TMP[0]), L(TMP[0]));

        /* initial xors */
        TMP[0] = _mm_shuffle_epi32(TMP[5], 0xFF); /* broadcast(key4 TMP[3]) */
        TMP[0] = _mm_xor_si128(TMP[0], TMP[1]);
        TMP[0] = _mm_xor_si128(TMP[0], TMP[2]);
        TMP[0] = _mm_xor_si128(TMP[0], TMP[3]);
        /* Sbox */
        TMP[0] = sBox(TMP[0]);
        /* Sbox done, now L */
        TMP[4] = _mm_xor_si128(_mm_xor_si128(TMP[4], TMP[0]), L(TMP[0]));
    }

    ((Ipp32u*)(pOut))[0] = (Ipp32u)_mm_cvtsi128_si32(_mm_shuffle_epi8(TMP[4], M128(swapBytes)));
    ((Ipp32u*)(pOut))[1] = (Ipp32u)_mm_cvtsi128_si32(_mm_shuffle_epi8(TMP[3], M128(swapBytes)));
    ((Ipp32u*)(pOut))[2] = (Ipp32u)_mm_cvtsi128_si32(_mm_shuffle_epi8(TMP[2], M128(swapBytes)));
    ((Ipp32u*)(pOut))[3] = (Ipp32u)_mm_cvtsi128_si32(_mm_shuffle_epi8(TMP[1], M128(swapBytes)));

    /* clear secret data */
    for (size_t i = 0; i < sizeof(TMP) / sizeof(TMP[0]); i++) {
        TMP[i] = _mm_xor_si128(TMP[i], TMP[i]);
    }
}

/*
// (1-3)*MBS_SMS4 processing
*/

static inline int cpSMS4_ECB_aesni_tail(Ipp8u* pOut, const Ipp8u* pInp, int len, const Ipp32u* pRKey)
{
    CRYPTOPP_ALIGN_DATA(16) __m128i TMP[6];
    /*
       TMP[0] = T
       TMP[1] = K0
       TMP[2] = K1
       TMP[3] = K2
       TMP[4] = K3
       TMP[5] = key4
    */

    TMP[2] = _mm_setzero_si128();
    TMP[3] = _mm_setzero_si128();
    TMP[4] = _mm_setzero_si128();

    switch (len) {
    case (3 * MBS_SMS4):
        TMP[3] = _mm_shuffle_epi8(_mm_loadu_si128((__m128i*)(pInp + 2 * MBS_SMS4)), M128(swapBytes));
    case (2 * MBS_SMS4):
        TMP[2] = _mm_shuffle_epi8(_mm_loadu_si128((__m128i*)(pInp + 1 * MBS_SMS4)), M128(swapBytes));
    case (1 * MBS_SMS4):
        TMP[1] = _mm_shuffle_epi8(_mm_loadu_si128((__m128i*)(pInp + 0 * MBS_SMS4)), M128(swapBytes));
        break;
    default: return 0;
    }
    TRANSPOSE_INP(TMP[1], TMP[2], TMP[3], TMP[4], TMP[0]);

    {
        int itr;
        for (itr = 0; itr < 8; itr++, pRKey += 4) {
            TMP[5] = _mm_loadu_si128((__m128i*)pRKey);

            /* initial xors */
            TMP[0] = _mm_shuffle_epi32(TMP[5], 0x00); /* broadcast(key4 TMP[0]) */
            TMP[0] = _mm_xor_si128(TMP[0], TMP[2]);
            TMP[0] = _mm_xor_si128(TMP[0], TMP[3]);
            TMP[0] = _mm_xor_si128(TMP[0], TMP[4]);
            /* Sbox */
            TMP[0] = sBox(TMP[0]);
            /* Sbox done, now L */
            TMP[1] = _mm_xor_si128(_mm_xor_si128(TMP[1], TMP[0]), L(TMP[0]));

            /* initial xors */
            TMP[0] = _mm_shuffle_epi32(TMP[5], 0x55); /* broadcast(key4 TMP[1]) */
            TMP[0] = _mm_xor_si128(TMP[0], TMP[3]);
            TMP[0] = _mm_xor_si128(TMP[0], TMP[4]);
            TMP[0] = _mm_xor_si128(TMP[0], TMP[1]);
            /* Sbox */
            TMP[0] = sBox(TMP[0]);
            /* Sbox done, now L */
            TMP[2] = _mm_xor_si128(_mm_xor_si128(TMP[2], TMP[0]), L(TMP[0]));

            /* initial xors */
            TMP[0] = _mm_shuffle_epi32(TMP[5], 0xAA);  /* broadcast(key4 TMP[2]) */
            TMP[0] = _mm_xor_si128(TMP[0], TMP[4]);
            TMP[0] = _mm_xor_si128(TMP[0], TMP[1]);
            TMP[0] = _mm_xor_si128(TMP[0], TMP[2]);
            /* Sbox */
            TMP[0] = sBox(TMP[0]);
            /* Sbox done, now L */
            TMP[3] = _mm_xor_si128(_mm_xor_si128(TMP[3], TMP[0]), L(TMP[0]));

            /* initial xors */
            TMP[0] = _mm_shuffle_epi32(TMP[5], 0xFF);  /* broadcast(key4 TMP[3]) */
            TMP[0] = _mm_xor_si128(TMP[0], TMP[1]);
            TMP[0] = _mm_xor_si128(TMP[0], TMP[2]);
            TMP[0] = _mm_xor_si128(TMP[0], TMP[3]);
            /* Sbox */
            TMP[0] = sBox(TMP[0]);
            /* Sbox done, now L */
            TMP[4] = _mm_xor_si128(_mm_xor_si128(TMP[4], TMP[0]), L(TMP[0]));
        }
    }

    TRANSPOSE_OUT(TMP[1], TMP[2], TMP[3], TMP[4], TMP[0]);
    TMP[4] = _mm_shuffle_epi8(TMP[4], M128(swapBytes));
    TMP[3] = _mm_shuffle_epi8(TMP[3], M128(swapBytes));
    TMP[2] = _mm_shuffle_epi8(TMP[2], M128(swapBytes));
    TMP[1] = _mm_shuffle_epi8(TMP[1], M128(swapBytes));

    switch (len) {
    case (3 * MBS_SMS4):
        _mm_storeu_si128((__m128i*)(pOut + 2 * MBS_SMS4), TMP[2]);
    case (2 * MBS_SMS4):
        _mm_storeu_si128((__m128i*)(pOut + 1 * MBS_SMS4), TMP[3]);
    case (1 * MBS_SMS4):
        _mm_storeu_si128((__m128i*)(pOut + 0 * MBS_SMS4), TMP[4]);
        break;
    }

    /* clear secret data */
    for (size_t i = 0; i < sizeof(TMP) / sizeof(TMP[0]); i++) {
        TMP[i] = _mm_xor_si128(TMP[i], TMP[i]);
    }

    return len;
}

/*
// 4*MBS_SMS4 processing
*/
static inline int cpSMS4_ECB_aesni_x4(Ipp8u* pOut, const Ipp8u* pInp, int len, const Ipp32u* pRKey)
{
    CRYPTOPP_ALIGN_DATA(16) __m128i TMP[5];
    /*
       TMP[0] = T
       TMP[1] = K0
       TMP[2] = K1
       TMP[3] = K2
       TMP[4] = K3
    */
    int processedLen = len & -(4 * MBS_SMS4);
    int n;
    for (n = 0; n < processedLen; n += (4 * MBS_SMS4), pInp += (4 * MBS_SMS4), pOut += (4 * MBS_SMS4)) {
        int itr;
        TMP[1] = _mm_loadu_si128((__m128i*)(pInp));
        TMP[2] = _mm_loadu_si128((__m128i*)(pInp + MBS_SMS4));
        TMP[3] = _mm_loadu_si128((__m128i*)(pInp + MBS_SMS4 * 2));
        TMP[4] = _mm_loadu_si128((__m128i*)(pInp + MBS_SMS4 * 3));
        TMP[1] = _mm_shuffle_epi8(TMP[1], M128(swapBytes));
        TMP[2] = _mm_shuffle_epi8(TMP[2], M128(swapBytes));
        TMP[3] = _mm_shuffle_epi8(TMP[3], M128(swapBytes));
        TMP[4] = _mm_shuffle_epi8(TMP[4], M128(swapBytes));
        TRANSPOSE_INP(TMP[1], TMP[2], TMP[3], TMP[4], TMP[0]);

        for (itr = 0; itr < 8; itr++, pRKey += 4) {
            /* initial xors */
            TMP[0] = _mm_shuffle_epi32(_mm_cvtsi32_si128((Ipp32s)pRKey[0]), 0);
            TMP[0] = _mm_xor_si128(TMP[0], TMP[2]);
            TMP[0] = _mm_xor_si128(TMP[0], TMP[3]);
            TMP[0] = _mm_xor_si128(TMP[0], TMP[4]);
            /* Sbox */
            TMP[0] = sBox(TMP[0]);
            /* Sbox done, now L */
            TMP[1] = _mm_xor_si128(_mm_xor_si128(TMP[1], TMP[0]), L(TMP[0]));

            /* initial xors */
            TMP[0] = _mm_shuffle_epi32(_mm_cvtsi32_si128((Ipp32s)pRKey[1]), 0);
            TMP[0] = _mm_xor_si128(TMP[0], TMP[3]);
            TMP[0] = _mm_xor_si128(TMP[0], TMP[4]);
            TMP[0] = _mm_xor_si128(TMP[0], TMP[1]);
            /* Sbox */
            TMP[0] = sBox(TMP[0]);
            /* Sbox done, now L */
            TMP[2] = _mm_xor_si128(_mm_xor_si128(TMP[2], TMP[0]), L(TMP[0]));

            /* initial xors */
            TMP[0] = _mm_shuffle_epi32(_mm_cvtsi32_si128((Ipp32s)pRKey[2]), 0);
            TMP[0] = _mm_xor_si128(TMP[0], TMP[4]);
            TMP[0] = _mm_xor_si128(TMP[0], TMP[1]);
            TMP[0] = _mm_xor_si128(TMP[0], TMP[2]);
            /* Sbox */
            TMP[0] = sBox(TMP[0]);
            /* Sbox done, now L */
            TMP[3] = _mm_xor_si128(_mm_xor_si128(TMP[3], TMP[0]), L(TMP[0]));

            /* initial xors */
            TMP[0] = _mm_shuffle_epi32(_mm_cvtsi32_si128((Ipp32s)pRKey[3]), 0);
            TMP[0] = _mm_xor_si128(TMP[0], TMP[1]);
            TMP[0] = _mm_xor_si128(TMP[0], TMP[2]);
            TMP[0] = _mm_xor_si128(TMP[0], TMP[3]);
            /* Sbox */
            TMP[0] = sBox(TMP[0]);
            /* Sbox done, now L */
            TMP[4] = _mm_xor_si128(_mm_xor_si128(TMP[4], TMP[0]), L(TMP[0]));
        }

        pRKey -= 32;

        TRANSPOSE_OUT(TMP[1], TMP[2], TMP[3], TMP[4], TMP[0]);
        TMP[4] = _mm_shuffle_epi8(TMP[4], M128(swapBytes));
        TMP[3] = _mm_shuffle_epi8(TMP[3], M128(swapBytes));
        TMP[2] = _mm_shuffle_epi8(TMP[2], M128(swapBytes));
        TMP[1] = _mm_shuffle_epi8(TMP[1], M128(swapBytes));
        _mm_storeu_si128((__m128i*)(pOut), TMP[4]);
        _mm_storeu_si128((__m128i*)(pOut + MBS_SMS4), TMP[3]);
        _mm_storeu_si128((__m128i*)(pOut + MBS_SMS4 * 2), TMP[2]);
        _mm_storeu_si128((__m128i*)(pOut + MBS_SMS4 * 3), TMP[1]);
    }

    len -= processedLen;
    if (len)
        processedLen += cpSMS4_ECB_aesni_tail(pOut, pInp, len, pRKey);

    /* clear secret data */
    for (size_t i = 0; i < sizeof(TMP) / sizeof(TMP[0]); i++) {
        TMP[i] = _mm_setzero_si128(); //_mm_xor_si128(TMP[i],TMP[i]);
    }

    return processedLen;
}

/*
// 8*MBS_SMS4 processing
*/
static inline int cpSMS4_ECB_aesni_x8(Ipp8u* pOut, const Ipp8u* pInp, int len, const Ipp32u* pRKey)
{
    CRYPTOPP_ALIGN_DATA(16) __m128i TMP[10];
    /*
       TMP[0] = T
       TMP[1] = U
       TMP[2] = K0
       TMP[3] = K1
       TMP[4] = K2
       TMP[5] = K3
       TMP[6] = P0
       TMP[7] = P1
       TMP[8] = P2
       TMP[9] = P3
    */

    int processedLen = len & -(8 * MBS_SMS4);
    int n;
    for (n = 0; n < processedLen; n += (8 * MBS_SMS4), pInp += (8 * MBS_SMS4), pOut += (8 * MBS_SMS4)) {
        int itr;
        TMP[2] = _mm_loadu_si128((__m128i*)(pInp));
        TMP[3] = _mm_loadu_si128((__m128i*)(pInp + MBS_SMS4));
        TMP[4] = _mm_loadu_si128((__m128i*)(pInp + MBS_SMS4 * 2));
        TMP[5] = _mm_loadu_si128((__m128i*)(pInp + MBS_SMS4 * 3));

        TMP[6] = _mm_loadu_si128((__m128i*)(pInp + MBS_SMS4 * 4));
        TMP[7] = _mm_loadu_si128((__m128i*)(pInp + MBS_SMS4 * 5));
        TMP[8] = _mm_loadu_si128((__m128i*)(pInp + MBS_SMS4 * 6));
        TMP[9] = _mm_loadu_si128((__m128i*)(pInp + MBS_SMS4 * 7));

        TMP[2] = _mm_shuffle_epi8(TMP[2], M128(swapBytes));
        TMP[3] = _mm_shuffle_epi8(TMP[3], M128(swapBytes));
        TMP[4] = _mm_shuffle_epi8(TMP[4], M128(swapBytes));
        TMP[5] = _mm_shuffle_epi8(TMP[5], M128(swapBytes));
        TRANSPOSE_INP(TMP[2], TMP[3], TMP[4], TMP[5], TMP[0]);

        TMP[6] = _mm_shuffle_epi8(TMP[6], M128(swapBytes));
        TMP[7] = _mm_shuffle_epi8(TMP[7], M128(swapBytes));
        TMP[8] = _mm_shuffle_epi8(TMP[8], M128(swapBytes));
        TMP[9] = _mm_shuffle_epi8(TMP[9], M128(swapBytes));
        TRANSPOSE_INP(TMP[6], TMP[7], TMP[8], TMP[9], TMP[0]);

        for (itr = 0; itr < 8; itr++, pRKey += 4) {
            /* initial xors */
            TMP[1] = TMP[0] = _mm_shuffle_epi32(_mm_cvtsi32_si128((Ipp32s)pRKey[0]), 0);
            TMP[0] = _mm_xor_si128(TMP[0], TMP[3]);
            TMP[0] = _mm_xor_si128(TMP[0], TMP[4]);
            TMP[0] = _mm_xor_si128(TMP[0], TMP[5]);
            TMP[1] = _mm_xor_si128(TMP[1], TMP[7]);
            TMP[1] = _mm_xor_si128(TMP[1], TMP[8]);
            TMP[1] = _mm_xor_si128(TMP[1], TMP[9]);
            /* Sbox */
            TMP[0] = sBox(TMP[0]);
            TMP[1] = sBox(TMP[1]);
            /* Sbox done, now L */
            TMP[2] = _mm_xor_si128(_mm_xor_si128(TMP[2], TMP[0]), L(TMP[0]));
            TMP[6] = _mm_xor_si128(_mm_xor_si128(TMP[6], TMP[1]), L(TMP[1]));

            /* initial xors */
            TMP[1] = TMP[0] = _mm_shuffle_epi32(_mm_cvtsi32_si128((Ipp32s)pRKey[1]), 0);
            TMP[0] = _mm_xor_si128(TMP[0], TMP[4]);
            TMP[0] = _mm_xor_si128(TMP[0], TMP[5]);
            TMP[0] = _mm_xor_si128(TMP[0], TMP[2]);
            TMP[1] = _mm_xor_si128(TMP[1], TMP[8]);
            TMP[1] = _mm_xor_si128(TMP[1], TMP[9]);
            TMP[1] = _mm_xor_si128(TMP[1], TMP[6]);
            /* Sbox */
            TMP[0] = sBox(TMP[0]);
            TMP[1] = sBox(TMP[1]);
            /* Sbox done, now L */
            TMP[3] = _mm_xor_si128(_mm_xor_si128(TMP[3], TMP[0]), L(TMP[0]));
            TMP[7] = _mm_xor_si128(_mm_xor_si128(TMP[7], TMP[1]), L(TMP[1]));

            /* initial xors */
            TMP[1] = TMP[0] = _mm_shuffle_epi32(_mm_cvtsi32_si128((Ipp32s)pRKey[2]), 0);
            TMP[0] = _mm_xor_si128(TMP[0], TMP[5]);
            TMP[0] = _mm_xor_si128(TMP[0], TMP[2]);
            TMP[0] = _mm_xor_si128(TMP[0], TMP[3]);
            TMP[1] = _mm_xor_si128(TMP[1], TMP[9]);
            TMP[1] = _mm_xor_si128(TMP[1], TMP[6]);
            TMP[1] = _mm_xor_si128(TMP[1], TMP[7]);
            /* Sbox */
            TMP[0] = sBox(TMP[0]);
            TMP[1] = sBox(TMP[1]);
            /* Sbox done, now L */
            TMP[4] = _mm_xor_si128(_mm_xor_si128(TMP[4], TMP[0]), L(TMP[0]));
            TMP[8] = _mm_xor_si128(_mm_xor_si128(TMP[8], TMP[1]), L(TMP[1]));

            /* initial xors */
            TMP[1] = TMP[0] = _mm_shuffle_epi32(_mm_cvtsi32_si128((Ipp32s)pRKey[3]), 0);
            TMP[0] = _mm_xor_si128(TMP[0], TMP[2]);
            TMP[0] = _mm_xor_si128(TMP[0], TMP[3]);
            TMP[0] = _mm_xor_si128(TMP[0], TMP[4]);
            TMP[1] = _mm_xor_si128(TMP[1], TMP[6]);
            TMP[1] = _mm_xor_si128(TMP[1], TMP[7]);
            TMP[1] = _mm_xor_si128(TMP[1], TMP[8]);
            /* Sbox */
            TMP[0] = sBox(TMP[0]);
            TMP[1] = sBox(TMP[1]);
            /* Sbox done, now L */
            TMP[5] = _mm_xor_si128(_mm_xor_si128(TMP[5], TMP[0]), L(TMP[0]));
            TMP[9] = _mm_xor_si128(_mm_xor_si128(TMP[9], TMP[1]), L(TMP[1]));
        }

        pRKey -= 32;

        TRANSPOSE_OUT(TMP[2], TMP[3], TMP[4], TMP[5], TMP[0]);
        TMP[5] = _mm_shuffle_epi8(TMP[5], M128(swapBytes));
        TMP[4] = _mm_shuffle_epi8(TMP[4], M128(swapBytes));
        TMP[3] = _mm_shuffle_epi8(TMP[3], M128(swapBytes));
        TMP[2] = _mm_shuffle_epi8(TMP[2], M128(swapBytes));
        _mm_storeu_si128((__m128i*)(pOut), TMP[5]);
        _mm_storeu_si128((__m128i*)(pOut + MBS_SMS4), TMP[4]);
        _mm_storeu_si128((__m128i*)(pOut + MBS_SMS4 * 2), TMP[3]);
        _mm_storeu_si128((__m128i*)(pOut + MBS_SMS4 * 3), TMP[2]);

        TRANSPOSE_OUT(TMP[6], TMP[7], TMP[8], TMP[9], TMP[0]);
        TMP[9] = _mm_shuffle_epi8(TMP[9], M128(swapBytes));
        TMP[8] = _mm_shuffle_epi8(TMP[8], M128(swapBytes));
        TMP[7] = _mm_shuffle_epi8(TMP[7], M128(swapBytes));
        TMP[6] = _mm_shuffle_epi8(TMP[6], M128(swapBytes));
        _mm_storeu_si128((__m128i*)(pOut + MBS_SMS4 * 4), TMP[9]);
        _mm_storeu_si128((__m128i*)(pOut + MBS_SMS4 * 5), TMP[8]);
        _mm_storeu_si128((__m128i*)(pOut + MBS_SMS4 * 6), TMP[7]);
        _mm_storeu_si128((__m128i*)(pOut + MBS_SMS4 * 7), TMP[6]);
    }


    len -= processedLen;
    if (len)
        processedLen += cpSMS4_ECB_aesni_x4(pOut, pInp, len, pRKey);

    /* clear secret data */
    for (size_t i = 0; i < sizeof(TMP) / sizeof(TMP[0]); i++) {
        TMP[i] = _mm_setzero_si128(); //_mm_xor_si128(TMP[i],TMP[i]);
    }

    return processedLen;
}

extern "C" void sm4_set_key_aesni(const uint8* key, sm4_kds* kds)
{
    uint32* rk = kds->m_rDeckeys;
    cpSMS4_SetRoundKeys_aesni(kds->m_rEnckeys, key);
    cpSMS4_SetRoundKeys_aesni(kds->m_rDeckeys, key);
    for (int i = 0; i < 16; i++) {
        uint32 temp = rk[i];
        rk[i] = rk[31 - i];
        rk[31 - i] = temp;
    }
}

extern "C" void sm4_encrypt_block_aesni(uint8* out, const uint8* in, sm4_kds* kds)
{
    cpSMS4_ECB_aesni_x1(out, in, kds->m_rEnckeys);
}

extern "C" void sm4_decrypt_block_aesni(uint8* out, const uint8* in, sm4_kds* kds)
{
    cpSMS4_ECB_aesni_x1(out, in, kds->m_rDeckeys);
}

extern "C" void sm4_encrypt_blocks_aesni(uint8* out, const uint8* in, size_t blocks, sm4_kds* kds)
{
    cpSMS4_ECB_aesni_x8(out, in, (int) blocks * 16, kds->m_rEnckeys);
}

extern "C" void sm4_decrypt_blocks_aesni(uint8* out, const uint8* in, size_t blocks, sm4_kds* kds)
{
    cpSMS4_ECB_aesni_x8(out, in, (int) blocks * 16, kds->m_rDeckeys);
}

#endif
