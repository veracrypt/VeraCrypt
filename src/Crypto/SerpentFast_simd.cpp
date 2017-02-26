/*
* Serpent (SIMD)
* (C) 2009,2013 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "SerpentFast.h"
#include "SerpentFast_sbox.h"
#if !defined(_UEFI)
#include <memory.h>
#include <stdlib.h>
#endif
#include "cpu.h"
#include "misc.h"

#if CRYPTOPP_BOOL_SSE2_INTRINSICS_AVAILABLE

/**
* This class is not a general purpose SIMD type, and only offers
* instructions needed for evaluation of specific crypto primitives.
* For example it does not currently have equality operators of any
* kind.
*/
class SIMD_4x32
{
public:

    SIMD_4x32() // zero initialized
        {
        ::memset(&m_reg, 0, sizeof(m_reg));
        }

    explicit SIMD_4x32(const unsigned __int32 B[4])
        {
        m_reg = _mm_loadu_si128(reinterpret_cast<const __m128i*>(B));
        }

    SIMD_4x32(unsigned __int32 B0, unsigned __int32 B1, unsigned __int32 B2, unsigned __int32 B3)
        {
        m_reg = _mm_set_epi32(B0, B1, B2, B3);
        }

    explicit SIMD_4x32(unsigned __int32 B)
        {
        m_reg = _mm_set1_epi32(B);
        }

    static SIMD_4x32 load_le(const void* in)
        {
        return SIMD_4x32(_mm_loadu_si128(reinterpret_cast<const __m128i*>(in)));
        }

    static SIMD_4x32 load_be(const void* in)
        {
        return load_le(in).bswap();
        }

    void store_le(unsigned __int8 out[]) const
        {
        _mm_storeu_si128(reinterpret_cast<__m128i*>(out), m_reg);
        }

    void store_be(unsigned __int8 out[]) const
        {
        bswap().store_le(out);
        }

    void rotate_left(size_t rot)
        {
        m_reg = _mm_or_si128(_mm_slli_epi32(m_reg, static_cast<int>(rot)),
                            _mm_srli_epi32(m_reg, static_cast<int>(32-rot)));

        }

    void rotate_right(size_t rot)
        {
        rotate_left(32 - rot);
        }

    void operator+=(const SIMD_4x32& other)
        {
        m_reg = _mm_add_epi32(m_reg, other.m_reg);
        }

    SIMD_4x32 operator+(const SIMD_4x32& other) const
        {
        return SIMD_4x32(_mm_add_epi32(m_reg, other.m_reg));
        }

    void operator-=(const SIMD_4x32& other)
        {
        m_reg = _mm_sub_epi32(m_reg, other.m_reg);
        }

    SIMD_4x32 operator-(const SIMD_4x32& other) const
        {
        return SIMD_4x32(_mm_sub_epi32(m_reg, other.m_reg));
        }

    void operator^=(const SIMD_4x32& other)
        {
        m_reg = _mm_xor_si128(m_reg, other.m_reg);
        }

    SIMD_4x32 operator^(const SIMD_4x32& other) const
        {
        return SIMD_4x32(_mm_xor_si128(m_reg, other.m_reg));
        }

    void operator|=(const SIMD_4x32& other)
        {
        m_reg = _mm_or_si128(m_reg, other.m_reg);
        }

    SIMD_4x32 operator&(const SIMD_4x32& other)
        {
        return SIMD_4x32(_mm_and_si128(m_reg, other.m_reg));
        }

    void operator&=(const SIMD_4x32& other)
        {
        m_reg = _mm_and_si128(m_reg, other.m_reg);
        }

    SIMD_4x32 operator<<(size_t shift) const
        {
        return SIMD_4x32(_mm_slli_epi32(m_reg, static_cast<int>(shift)));
        }

    SIMD_4x32 operator>>(size_t shift) const
        {
        return SIMD_4x32(_mm_srli_epi32(m_reg, static_cast<int>(shift)));
        }

    SIMD_4x32 operator~() const
        {
        return SIMD_4x32(_mm_xor_si128(m_reg, _mm_set1_epi32(0xFFFFFFFF)));
        }

    // (~reg) & other
    SIMD_4x32 andc(const SIMD_4x32& other)
        {
        return SIMD_4x32(_mm_andnot_si128(m_reg, other.m_reg));
        }

    SIMD_4x32 bswap() const
        {
        __m128i T = m_reg;

        T = _mm_shufflehi_epi16(T, _MM_SHUFFLE(2, 3, 0, 1));
        T = _mm_shufflelo_epi16(T, _MM_SHUFFLE(2, 3, 0, 1));

        return SIMD_4x32(_mm_or_si128(_mm_srli_epi16(T, 8),
                                    _mm_slli_epi16(T, 8)));
        }

    static void transpose(SIMD_4x32& B0, SIMD_4x32& B1,
                        SIMD_4x32& B2, SIMD_4x32& B3)
        {
        __m128i T0 = _mm_unpacklo_epi32(B0.m_reg, B1.m_reg);
        __m128i T1 = _mm_unpacklo_epi32(B2.m_reg, B3.m_reg);
        __m128i T2 = _mm_unpackhi_epi32(B0.m_reg, B1.m_reg);
        __m128i T3 = _mm_unpackhi_epi32(B2.m_reg, B3.m_reg);
        B0.m_reg = _mm_unpacklo_epi64(T0, T1);
        B1.m_reg = _mm_unpackhi_epi64(T0, T1);
        B2.m_reg = _mm_unpacklo_epi64(T2, T3);
        B3.m_reg = _mm_unpackhi_epi64(T2, T3);
        }

private:

    explicit SIMD_4x32(__m128i in) { m_reg = in; }

    __m128i m_reg;

};

typedef SIMD_4x32 SIMD_32;

#define key_xor(round, B0, B1, B2, B3)                             \
   do {                                                            \
      B0 ^= SIMD_32(round_key[4*round  ]);                       \
      B1 ^= SIMD_32(round_key[4*round+1]);                       \
      B2 ^= SIMD_32(round_key[4*round+2]);                       \
      B3 ^= SIMD_32(round_key[4*round+3]);                       \
   } while(0);

/*
* Serpent's linear transformations
*/
#define transform(B0, B1, B2, B3)                                  \
   do {                                                            \
      B0.rotate_left(13);                                          \
      B2.rotate_left(3);                                           \
      B1 ^= B0 ^ B2;                                               \
      B3 ^= B2 ^ (B0 << 3);                                        \
      B1.rotate_left(1);                                           \
      B3.rotate_left(7);                                           \
      B0 ^= B1 ^ B3;                                               \
      B2 ^= B3 ^ (B1 << 7);                                        \
      B0.rotate_left(5);                                           \
      B2.rotate_left(22);                                          \
   } while(0);

#define i_transform(B0, B1, B2, B3)                                \
   do {                                                            \
      B2.rotate_right(22);                                         \
      B0.rotate_right(5);                                          \
      B2 ^= B3 ^ (B1 << 7);                                        \
      B0 ^= B1 ^ B3;                                               \
      B3.rotate_right(7);                                          \
      B1.rotate_right(1);                                          \
      B3 ^= B2 ^ (B0 << 3);                                        \
      B1 ^= B0 ^ B2;                                               \
      B2.rotate_right(3);                                          \
      B0.rotate_right(13);                                         \
   } while(0);



/*
* SIMD Serpent Encryption of 4 blocks in parallel
*/
extern "C" void serpent_simd_encrypt_blocks_4(const unsigned __int8 in[], unsigned __int8 out[], unsigned __int32* round_key)
{
   SIMD_32 B0 = SIMD_32::load_le(in);
   SIMD_32 B1 = SIMD_32::load_le(in + 16);
   SIMD_32 B2 = SIMD_32::load_le(in + 32);
   SIMD_32 B3 = SIMD_32::load_le(in + 48);

   SIMD_32::transpose(B0, B1, B2, B3);

   key_xor( 0,B0,B1,B2,B3); SBoxE1(SIMD_32,B0,B1,B2,B3); transform(B0,B1,B2,B3);
   key_xor( 1,B0,B1,B2,B3); SBoxE2(SIMD_32,B0,B1,B2,B3); transform(B0,B1,B2,B3);
   key_xor( 2,B0,B1,B2,B3); SBoxE3(SIMD_32,B0,B1,B2,B3); transform(B0,B1,B2,B3);
   key_xor( 3,B0,B1,B2,B3); SBoxE4(SIMD_32,B0,B1,B2,B3); transform(B0,B1,B2,B3);
   key_xor( 4,B0,B1,B2,B3); SBoxE5(SIMD_32,B0,B1,B2,B3); transform(B0,B1,B2,B3);
   key_xor( 5,B0,B1,B2,B3); SBoxE6(SIMD_32,B0,B1,B2,B3); transform(B0,B1,B2,B3);
   key_xor( 6,B0,B1,B2,B3); SBoxE7(SIMD_32,B0,B1,B2,B3); transform(B0,B1,B2,B3);
   key_xor( 7,B0,B1,B2,B3); SBoxE8(SIMD_32,B0,B1,B2,B3); transform(B0,B1,B2,B3);

   key_xor( 8,B0,B1,B2,B3); SBoxE1(SIMD_32,B0,B1,B2,B3); transform(B0,B1,B2,B3);
   key_xor( 9,B0,B1,B2,B3); SBoxE2(SIMD_32,B0,B1,B2,B3); transform(B0,B1,B2,B3);
   key_xor(10,B0,B1,B2,B3); SBoxE3(SIMD_32,B0,B1,B2,B3); transform(B0,B1,B2,B3);
   key_xor(11,B0,B1,B2,B3); SBoxE4(SIMD_32,B0,B1,B2,B3); transform(B0,B1,B2,B3);
   key_xor(12,B0,B1,B2,B3); SBoxE5(SIMD_32,B0,B1,B2,B3); transform(B0,B1,B2,B3);
   key_xor(13,B0,B1,B2,B3); SBoxE6(SIMD_32,B0,B1,B2,B3); transform(B0,B1,B2,B3);
   key_xor(14,B0,B1,B2,B3); SBoxE7(SIMD_32,B0,B1,B2,B3); transform(B0,B1,B2,B3);
   key_xor(15,B0,B1,B2,B3); SBoxE8(SIMD_32,B0,B1,B2,B3); transform(B0,B1,B2,B3);

   key_xor(16,B0,B1,B2,B3); SBoxE1(SIMD_32,B0,B1,B2,B3); transform(B0,B1,B2,B3);
   key_xor(17,B0,B1,B2,B3); SBoxE2(SIMD_32,B0,B1,B2,B3); transform(B0,B1,B2,B3);
   key_xor(18,B0,B1,B2,B3); SBoxE3(SIMD_32,B0,B1,B2,B3); transform(B0,B1,B2,B3);
   key_xor(19,B0,B1,B2,B3); SBoxE4(SIMD_32,B0,B1,B2,B3); transform(B0,B1,B2,B3);
   key_xor(20,B0,B1,B2,B3); SBoxE5(SIMD_32,B0,B1,B2,B3); transform(B0,B1,B2,B3);
   key_xor(21,B0,B1,B2,B3); SBoxE6(SIMD_32,B0,B1,B2,B3); transform(B0,B1,B2,B3);
   key_xor(22,B0,B1,B2,B3); SBoxE7(SIMD_32,B0,B1,B2,B3); transform(B0,B1,B2,B3);
   key_xor(23,B0,B1,B2,B3); SBoxE8(SIMD_32,B0,B1,B2,B3); transform(B0,B1,B2,B3);

   key_xor(24,B0,B1,B2,B3); SBoxE1(SIMD_32,B0,B1,B2,B3); transform(B0,B1,B2,B3);
   key_xor(25,B0,B1,B2,B3); SBoxE2(SIMD_32,B0,B1,B2,B3); transform(B0,B1,B2,B3);
   key_xor(26,B0,B1,B2,B3); SBoxE3(SIMD_32,B0,B1,B2,B3); transform(B0,B1,B2,B3);
   key_xor(27,B0,B1,B2,B3); SBoxE4(SIMD_32,B0,B1,B2,B3); transform(B0,B1,B2,B3);
   key_xor(28,B0,B1,B2,B3); SBoxE5(SIMD_32,B0,B1,B2,B3); transform(B0,B1,B2,B3);
   key_xor(29,B0,B1,B2,B3); SBoxE6(SIMD_32,B0,B1,B2,B3); transform(B0,B1,B2,B3);
   key_xor(30,B0,B1,B2,B3); SBoxE7(SIMD_32,B0,B1,B2,B3); transform(B0,B1,B2,B3);
   key_xor(31,B0,B1,B2,B3); SBoxE8(SIMD_32,B0,B1,B2,B3); key_xor(32,B0,B1,B2,B3);

   SIMD_32::transpose(B0, B1, B2, B3);

   B0.store_le(out);
   B1.store_le(out + 16);
   B2.store_le(out + 32);
   B3.store_le(out + 48);
}

/*
* SIMD Serpent Decryption of 4 blocks in parallel
*/
extern "C" void serpent_simd_decrypt_blocks_4(const unsigned __int8 in[], unsigned __int8 out[], unsigned __int32* round_key)
{
   SIMD_32 B0 = SIMD_32::load_le(in);
   SIMD_32 B1 = SIMD_32::load_le(in + 16);
   SIMD_32 B2 = SIMD_32::load_le(in + 32);
   SIMD_32 B3 = SIMD_32::load_le(in + 48);

   SIMD_32::transpose(B0, B1, B2, B3);

   key_xor(32,B0,B1,B2,B3);  SBoxD8(SIMD_32,B0,B1,B2,B3); key_xor(31,B0,B1,B2,B3);
   i_transform(B0,B1,B2,B3); SBoxD7(SIMD_32,B0,B1,B2,B3); key_xor(30,B0,B1,B2,B3);
   i_transform(B0,B1,B2,B3); SBoxD6(SIMD_32,B0,B1,B2,B3); key_xor(29,B0,B1,B2,B3);
   i_transform(B0,B1,B2,B3); SBoxD5(SIMD_32,B0,B1,B2,B3); key_xor(28,B0,B1,B2,B3);
   i_transform(B0,B1,B2,B3); SBoxD4(SIMD_32,B0,B1,B2,B3); key_xor(27,B0,B1,B2,B3);
   i_transform(B0,B1,B2,B3); SBoxD3(SIMD_32,B0,B1,B2,B3); key_xor(26,B0,B1,B2,B3);
   i_transform(B0,B1,B2,B3); SBoxD2(SIMD_32,B0,B1,B2,B3); key_xor(25,B0,B1,B2,B3);
   i_transform(B0,B1,B2,B3); SBoxD1(SIMD_32,B0,B1,B2,B3); key_xor(24,B0,B1,B2,B3);

   i_transform(B0,B1,B2,B3); SBoxD8(SIMD_32,B0,B1,B2,B3); key_xor(23,B0,B1,B2,B3);
   i_transform(B0,B1,B2,B3); SBoxD7(SIMD_32,B0,B1,B2,B3); key_xor(22,B0,B1,B2,B3);
   i_transform(B0,B1,B2,B3); SBoxD6(SIMD_32,B0,B1,B2,B3); key_xor(21,B0,B1,B2,B3);
   i_transform(B0,B1,B2,B3); SBoxD5(SIMD_32,B0,B1,B2,B3); key_xor(20,B0,B1,B2,B3);
   i_transform(B0,B1,B2,B3); SBoxD4(SIMD_32,B0,B1,B2,B3); key_xor(19,B0,B1,B2,B3);
   i_transform(B0,B1,B2,B3); SBoxD3(SIMD_32,B0,B1,B2,B3); key_xor(18,B0,B1,B2,B3);
   i_transform(B0,B1,B2,B3); SBoxD2(SIMD_32,B0,B1,B2,B3); key_xor(17,B0,B1,B2,B3);
   i_transform(B0,B1,B2,B3); SBoxD1(SIMD_32,B0,B1,B2,B3); key_xor(16,B0,B1,B2,B3);

   i_transform(B0,B1,B2,B3); SBoxD8(SIMD_32,B0,B1,B2,B3); key_xor(15,B0,B1,B2,B3);
   i_transform(B0,B1,B2,B3); SBoxD7(SIMD_32,B0,B1,B2,B3); key_xor(14,B0,B1,B2,B3);
   i_transform(B0,B1,B2,B3); SBoxD6(SIMD_32,B0,B1,B2,B3); key_xor(13,B0,B1,B2,B3);
   i_transform(B0,B1,B2,B3); SBoxD5(SIMD_32,B0,B1,B2,B3); key_xor(12,B0,B1,B2,B3);
   i_transform(B0,B1,B2,B3); SBoxD4(SIMD_32,B0,B1,B2,B3); key_xor(11,B0,B1,B2,B3);
   i_transform(B0,B1,B2,B3); SBoxD3(SIMD_32,B0,B1,B2,B3); key_xor(10,B0,B1,B2,B3);
   i_transform(B0,B1,B2,B3); SBoxD2(SIMD_32,B0,B1,B2,B3); key_xor( 9,B0,B1,B2,B3);
   i_transform(B0,B1,B2,B3); SBoxD1(SIMD_32,B0,B1,B2,B3); key_xor( 8,B0,B1,B2,B3);

   i_transform(B0,B1,B2,B3); SBoxD8(SIMD_32,B0,B1,B2,B3); key_xor( 7,B0,B1,B2,B3);
   i_transform(B0,B1,B2,B3); SBoxD7(SIMD_32,B0,B1,B2,B3); key_xor( 6,B0,B1,B2,B3);
   i_transform(B0,B1,B2,B3); SBoxD6(SIMD_32,B0,B1,B2,B3); key_xor( 5,B0,B1,B2,B3);
   i_transform(B0,B1,B2,B3); SBoxD5(SIMD_32,B0,B1,B2,B3); key_xor( 4,B0,B1,B2,B3);
   i_transform(B0,B1,B2,B3); SBoxD4(SIMD_32,B0,B1,B2,B3); key_xor( 3,B0,B1,B2,B3);
   i_transform(B0,B1,B2,B3); SBoxD3(SIMD_32,B0,B1,B2,B3); key_xor( 2,B0,B1,B2,B3);
   i_transform(B0,B1,B2,B3); SBoxD2(SIMD_32,B0,B1,B2,B3); key_xor( 1,B0,B1,B2,B3);
   i_transform(B0,B1,B2,B3); SBoxD1(SIMD_32,B0,B1,B2,B3); key_xor( 0,B0,B1,B2,B3);

   SIMD_32::transpose(B0, B1, B2, B3);

   B0.store_le(out);
   B1.store_le(out + 16);
   B2.store_le(out + 32);
   B3.store_le(out + 48);
}

#undef key_xor
#undef transform
#undef i_transform

#endif
