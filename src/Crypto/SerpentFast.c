/*
* Serpent
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "SerpentFast.h"
#include "SerpentFast_sbox.h"
#include "Common/Endian.h"
#if !defined(_UEFI)
#include <memory.h>
#include <stdlib.h>
#endif
#include "cpu.h"
#include "misc.h"

#if BYTE_ORDER == BIG_ENDIAN

#define BOTAN_ENDIAN_N2B(x) (x)
#define BOTAN_ENDIAN_B2N(x) (x)

#define BOTAN_ENDIAN_N2L(x) bswap_32(x)
#define BOTAN_ENDIAN_L2N(x) bswap_32(x)

#elif  BYTE_ORDER == LITTLE_ENDIAN

#define BOTAN_ENDIAN_N2L(x) (x)
#define BOTAN_ENDIAN_L2N(x) (x)

#define BOTAN_ENDIAN_N2B(x) bswap_32(x)
#define BOTAN_ENDIAN_B2N(x) bswap_32(x)

#endif

#if CRYPTOPP_BOOL_SSE2_INTRINSICS_AVAILABLE
extern void serpent_simd_encrypt_blocks_4(const unsigned __int8 in[], unsigned __int8 out[], unsigned __int32* round_key);
extern void serpent_simd_decrypt_blocks_4(const unsigned __int8 in[], unsigned __int8 out[], unsigned __int32* round_key);
#endif

/*
* Serpent's Linear Transform
*/
#define transform(B0,B1,B2,B3) \
	do { \
		B0  = rotl32(B0, 13);   B2  = rotl32(B2, 3); \
		B1 ^= B0 ^ B2;               B3 ^= B2 ^ (B0 << 3); \
		B1  = rotl32(B1, 1);    B3  = rotl32(B3, 7); \
		B0 ^= B1 ^ B3;               B2 ^= B3 ^ (B1 << 7); \
		B0  = rotl32(B0, 5);    B2  = rotl32(B2, 22); \
	} while (0);

/*
* Serpent's Inverse Linear Transform
*/
#define i_transform(B0,B1,B2,B3) \
   do { \
	   B2  = rotr32(B2, 22);  B0  = rotr32(B0, 5); \
	   B2 ^= B3 ^ (B1 << 7);        B0 ^= B1 ^ B3; \
	   B3  = rotr32(B3, 7);   B1  = rotr32(B1, 1); \
	   B3 ^= B2 ^ (B0 << 3);        B1 ^= B0 ^ B2; \
	   B2  = rotr32(B2, 3);   B0  = rotr32(B0, 13); \
   } while (0);


/*
* XOR a key block with a data block
*/
#define key_xor(round, B0, B1, B2, B3) \
   B0 ^= round_key[4*round  ]; \
   B1 ^= round_key[4*round+1]; \
   B2 ^= round_key[4*round+2]; \
   B3 ^= round_key[4*round+3];

/*
* Serpent Encryption
*/
void serpent_encrypt_blocks(const unsigned __int8* in, unsigned __int8* out, size_t blocks, unsigned __int8 *ks)
{
   unsigned __int32 B0, B1, B2, B3;
   unsigned __int32* round_key = ((unsigned __int32*) ks) + 8;
   size_t i;
#if CRYPTOPP_BOOL_SSE2_INTRINSICS_AVAILABLE && (!defined (DEBUG) || !defined (TC_WINDOWS_DRIVER))
   if(HasSSE2() && (blocks >= 4))
   {
      while(blocks >= 4)
      {
         serpent_simd_encrypt_blocks_4(in, out, round_key);
         in += 4 * 16;
         out += 4 * 16;
         blocks -= 4;
      }
   }
#endif

   for(i = 0; i != blocks; ++i)
   {	  
	  memcpy (&B0, in +  0, 4);
	  memcpy (&B1, in +  4, 4);
	  memcpy (&B2, in +  8, 4);
	  memcpy (&B3, in + 12, 4);
	  B0 = BOTAN_ENDIAN_N2L (B0);
	  B1 = BOTAN_ENDIAN_N2L (B1);
	  B2 = BOTAN_ENDIAN_N2L (B2);
	  B3 = BOTAN_ENDIAN_N2L (B3);

      key_xor( 0,B0,B1,B2,B3); SBoxE1(unsigned __int32,B0,B1,B2,B3); transform(B0,B1,B2,B3);
      key_xor( 1,B0,B1,B2,B3); SBoxE2(unsigned __int32,B0,B1,B2,B3); transform(B0,B1,B2,B3);
      key_xor( 2,B0,B1,B2,B3); SBoxE3(unsigned __int32,B0,B1,B2,B3); transform(B0,B1,B2,B3);
      key_xor( 3,B0,B1,B2,B3); SBoxE4(unsigned __int32,B0,B1,B2,B3); transform(B0,B1,B2,B3);
      key_xor( 4,B0,B1,B2,B3); SBoxE5(unsigned __int32,B0,B1,B2,B3); transform(B0,B1,B2,B3);
      key_xor( 5,B0,B1,B2,B3); SBoxE6(unsigned __int32,B0,B1,B2,B3); transform(B0,B1,B2,B3);
      key_xor( 6,B0,B1,B2,B3); SBoxE7(unsigned __int32,B0,B1,B2,B3); transform(B0,B1,B2,B3);
      key_xor( 7,B0,B1,B2,B3); SBoxE8(unsigned __int32,B0,B1,B2,B3); transform(B0,B1,B2,B3);
      key_xor( 8,B0,B1,B2,B3); SBoxE1(unsigned __int32,B0,B1,B2,B3); transform(B0,B1,B2,B3);
      key_xor( 9,B0,B1,B2,B3); SBoxE2(unsigned __int32,B0,B1,B2,B3); transform(B0,B1,B2,B3);
      key_xor(10,B0,B1,B2,B3); SBoxE3(unsigned __int32,B0,B1,B2,B3); transform(B0,B1,B2,B3);
      key_xor(11,B0,B1,B2,B3); SBoxE4(unsigned __int32,B0,B1,B2,B3); transform(B0,B1,B2,B3);
      key_xor(12,B0,B1,B2,B3); SBoxE5(unsigned __int32,B0,B1,B2,B3); transform(B0,B1,B2,B3);
      key_xor(13,B0,B1,B2,B3); SBoxE6(unsigned __int32,B0,B1,B2,B3); transform(B0,B1,B2,B3);
      key_xor(14,B0,B1,B2,B3); SBoxE7(unsigned __int32,B0,B1,B2,B3); transform(B0,B1,B2,B3);
      key_xor(15,B0,B1,B2,B3); SBoxE8(unsigned __int32,B0,B1,B2,B3); transform(B0,B1,B2,B3);
      key_xor(16,B0,B1,B2,B3); SBoxE1(unsigned __int32,B0,B1,B2,B3); transform(B0,B1,B2,B3);
      key_xor(17,B0,B1,B2,B3); SBoxE2(unsigned __int32,B0,B1,B2,B3); transform(B0,B1,B2,B3);
      key_xor(18,B0,B1,B2,B3); SBoxE3(unsigned __int32,B0,B1,B2,B3); transform(B0,B1,B2,B3);
      key_xor(19,B0,B1,B2,B3); SBoxE4(unsigned __int32,B0,B1,B2,B3); transform(B0,B1,B2,B3);
      key_xor(20,B0,B1,B2,B3); SBoxE5(unsigned __int32,B0,B1,B2,B3); transform(B0,B1,B2,B3);
      key_xor(21,B0,B1,B2,B3); SBoxE6(unsigned __int32,B0,B1,B2,B3); transform(B0,B1,B2,B3);
      key_xor(22,B0,B1,B2,B3); SBoxE7(unsigned __int32,B0,B1,B2,B3); transform(B0,B1,B2,B3);
      key_xor(23,B0,B1,B2,B3); SBoxE8(unsigned __int32,B0,B1,B2,B3); transform(B0,B1,B2,B3);
      key_xor(24,B0,B1,B2,B3); SBoxE1(unsigned __int32,B0,B1,B2,B3); transform(B0,B1,B2,B3);
      key_xor(25,B0,B1,B2,B3); SBoxE2(unsigned __int32,B0,B1,B2,B3); transform(B0,B1,B2,B3);
      key_xor(26,B0,B1,B2,B3); SBoxE3(unsigned __int32,B0,B1,B2,B3); transform(B0,B1,B2,B3);
      key_xor(27,B0,B1,B2,B3); SBoxE4(unsigned __int32,B0,B1,B2,B3); transform(B0,B1,B2,B3);
      key_xor(28,B0,B1,B2,B3); SBoxE5(unsigned __int32,B0,B1,B2,B3); transform(B0,B1,B2,B3);
      key_xor(29,B0,B1,B2,B3); SBoxE6(unsigned __int32,B0,B1,B2,B3); transform(B0,B1,B2,B3);
      key_xor(30,B0,B1,B2,B3); SBoxE7(unsigned __int32,B0,B1,B2,B3); transform(B0,B1,B2,B3);
      key_xor(31,B0,B1,B2,B3); SBoxE8(unsigned __int32,B0,B1,B2,B3); key_xor(32,B0,B1,B2,B3);

      B0 = BOTAN_ENDIAN_L2N(B0);
	  B1 = BOTAN_ENDIAN_L2N(B1);
	  B2 = BOTAN_ENDIAN_L2N(B2);
	  B3 = BOTAN_ENDIAN_L2N(B3);
      memcpy(out +  0, &B0, 4);
	  memcpy(out +  4, &B1, 4);
	  memcpy(out +  8, &B2, 4);
	  memcpy(out + 12, &B3, 4);

      in += 16;
      out += 16;
   }
}

/*
* Serpent Decryption
*/
void serpent_decrypt_blocks(const unsigned __int8* in, unsigned __int8* out, size_t blocks, unsigned __int8 *ks)
{
   unsigned __int32 B0, B1, B2, B3;
   unsigned __int32* round_key = ((unsigned __int32*) ks) + 8;
   size_t i;
#if CRYPTOPP_BOOL_SSE2_INTRINSICS_AVAILABLE && (!defined (DEBUG) || !defined (TC_WINDOWS_DRIVER))
   if(HasSSE2() && (blocks >= 4))
   {
      while(blocks >= 4)
      {
         serpent_simd_decrypt_blocks_4(in, out, round_key);
         in += 4 * 16;
         out += 4 * 16;
         blocks -= 4;
      }
   }
#endif

   for(i = 0; i != blocks; ++i)
   {      	  
	  memcpy (&B0, in +  0, 4);
	  memcpy (&B1, in +  4, 4);
	  memcpy (&B2, in +  8, 4);
	  memcpy (&B3, in + 12, 4);
	  B0 = BOTAN_ENDIAN_N2L (B0);
	  B1 = BOTAN_ENDIAN_N2L (B1);
	  B2 = BOTAN_ENDIAN_N2L (B2);
	  B3 = BOTAN_ENDIAN_N2L (B3);

      key_xor(32,B0,B1,B2,B3);  SBoxD8(unsigned __int32,B0,B1,B2,B3); key_xor(31,B0,B1,B2,B3);
      i_transform(B0,B1,B2,B3); SBoxD7(unsigned __int32,B0,B1,B2,B3); key_xor(30,B0,B1,B2,B3);
      i_transform(B0,B1,B2,B3); SBoxD6(unsigned __int32,B0,B1,B2,B3); key_xor(29,B0,B1,B2,B3);
      i_transform(B0,B1,B2,B3); SBoxD5(unsigned __int32,B0,B1,B2,B3); key_xor(28,B0,B1,B2,B3);
      i_transform(B0,B1,B2,B3); SBoxD4(unsigned __int32,B0,B1,B2,B3); key_xor(27,B0,B1,B2,B3);
      i_transform(B0,B1,B2,B3); SBoxD3(unsigned __int32,B0,B1,B2,B3); key_xor(26,B0,B1,B2,B3);
      i_transform(B0,B1,B2,B3); SBoxD2(unsigned __int32,B0,B1,B2,B3); key_xor(25,B0,B1,B2,B3);
      i_transform(B0,B1,B2,B3); SBoxD1(unsigned __int32,B0,B1,B2,B3); key_xor(24,B0,B1,B2,B3);
      i_transform(B0,B1,B2,B3); SBoxD8(unsigned __int32,B0,B1,B2,B3); key_xor(23,B0,B1,B2,B3);
      i_transform(B0,B1,B2,B3); SBoxD7(unsigned __int32,B0,B1,B2,B3); key_xor(22,B0,B1,B2,B3);
      i_transform(B0,B1,B2,B3); SBoxD6(unsigned __int32,B0,B1,B2,B3); key_xor(21,B0,B1,B2,B3);
      i_transform(B0,B1,B2,B3); SBoxD5(unsigned __int32,B0,B1,B2,B3); key_xor(20,B0,B1,B2,B3);
      i_transform(B0,B1,B2,B3); SBoxD4(unsigned __int32,B0,B1,B2,B3); key_xor(19,B0,B1,B2,B3);
      i_transform(B0,B1,B2,B3); SBoxD3(unsigned __int32,B0,B1,B2,B3); key_xor(18,B0,B1,B2,B3);
      i_transform(B0,B1,B2,B3); SBoxD2(unsigned __int32,B0,B1,B2,B3); key_xor(17,B0,B1,B2,B3);
      i_transform(B0,B1,B2,B3); SBoxD1(unsigned __int32,B0,B1,B2,B3); key_xor(16,B0,B1,B2,B3);
      i_transform(B0,B1,B2,B3); SBoxD8(unsigned __int32,B0,B1,B2,B3); key_xor(15,B0,B1,B2,B3);
      i_transform(B0,B1,B2,B3); SBoxD7(unsigned __int32,B0,B1,B2,B3); key_xor(14,B0,B1,B2,B3);
      i_transform(B0,B1,B2,B3); SBoxD6(unsigned __int32,B0,B1,B2,B3); key_xor(13,B0,B1,B2,B3);
      i_transform(B0,B1,B2,B3); SBoxD5(unsigned __int32,B0,B1,B2,B3); key_xor(12,B0,B1,B2,B3);
      i_transform(B0,B1,B2,B3); SBoxD4(unsigned __int32,B0,B1,B2,B3); key_xor(11,B0,B1,B2,B3);
      i_transform(B0,B1,B2,B3); SBoxD3(unsigned __int32,B0,B1,B2,B3); key_xor(10,B0,B1,B2,B3);
      i_transform(B0,B1,B2,B3); SBoxD2(unsigned __int32,B0,B1,B2,B3); key_xor( 9,B0,B1,B2,B3);
      i_transform(B0,B1,B2,B3); SBoxD1(unsigned __int32,B0,B1,B2,B3); key_xor( 8,B0,B1,B2,B3);
      i_transform(B0,B1,B2,B3); SBoxD8(unsigned __int32,B0,B1,B2,B3); key_xor( 7,B0,B1,B2,B3);
      i_transform(B0,B1,B2,B3); SBoxD7(unsigned __int32,B0,B1,B2,B3); key_xor( 6,B0,B1,B2,B3);
      i_transform(B0,B1,B2,B3); SBoxD6(unsigned __int32,B0,B1,B2,B3); key_xor( 5,B0,B1,B2,B3);
      i_transform(B0,B1,B2,B3); SBoxD5(unsigned __int32,B0,B1,B2,B3); key_xor( 4,B0,B1,B2,B3);
      i_transform(B0,B1,B2,B3); SBoxD4(unsigned __int32,B0,B1,B2,B3); key_xor( 3,B0,B1,B2,B3);
      i_transform(B0,B1,B2,B3); SBoxD3(unsigned __int32,B0,B1,B2,B3); key_xor( 2,B0,B1,B2,B3);
      i_transform(B0,B1,B2,B3); SBoxD2(unsigned __int32,B0,B1,B2,B3); key_xor( 1,B0,B1,B2,B3);
      i_transform(B0,B1,B2,B3); SBoxD1(unsigned __int32,B0,B1,B2,B3); key_xor( 0,B0,B1,B2,B3);

      B0 = BOTAN_ENDIAN_L2N(B0);
	  B1 = BOTAN_ENDIAN_L2N(B1);
	  B2 = BOTAN_ENDIAN_L2N(B2);
	  B3 = BOTAN_ENDIAN_L2N(B3);
      memcpy(out +  0, &B0, 4);
	  memcpy(out +  4, &B1, 4);
	  memcpy(out +  8, &B2, 4);
	  memcpy(out + 12, &B3, 4);

      in += 16;
      out += 16;
   }
}

#undef key_xor
#undef transform
#undef i_transform

/*
* Serpent Key Schedule
*/
void serpent_set_key(const unsigned __int8 userKey[], unsigned __int8 *ks)
{
   const unsigned __int32 PHI = 0x9E3779B9;
   unsigned __int32* W = (unsigned __int32*) ks;
   int i;
   for(i = 0; i != 8; ++i)
   {
      memcpy (W + i, userKey + (i*4), 4);
	  W[i] = BOTAN_ENDIAN_N2L(W[i]);
   }

   for(i = 8; i != 140; ++i)
   {
      unsigned __int32 wi = W[i-8] ^ W[i-5] ^ W[i-3] ^ W[i-1] ^ PHI ^ (unsigned __int32)(i-8);
      W[i] = rotl32(wi, 11);
   }

   SBoxE4(unsigned __int32,W[  8],W[  9],W[ 10],W[ 11]); SBoxE3(unsigned __int32,W[ 12],W[ 13],W[ 14],W[ 15]);
   SBoxE2(unsigned __int32,W[ 16],W[ 17],W[ 18],W[ 19]); SBoxE1(unsigned __int32,W[ 20],W[ 21],W[ 22],W[ 23]);
   SBoxE8(unsigned __int32,W[ 24],W[ 25],W[ 26],W[ 27]); SBoxE7(unsigned __int32,W[ 28],W[ 29],W[ 30],W[ 31]);
   SBoxE6(unsigned __int32,W[ 32],W[ 33],W[ 34],W[ 35]); SBoxE5(unsigned __int32,W[ 36],W[ 37],W[ 38],W[ 39]);
   SBoxE4(unsigned __int32,W[ 40],W[ 41],W[ 42],W[ 43]); SBoxE3(unsigned __int32,W[ 44],W[ 45],W[ 46],W[ 47]);
   SBoxE2(unsigned __int32,W[ 48],W[ 49],W[ 50],W[ 51]); SBoxE1(unsigned __int32,W[ 52],W[ 53],W[ 54],W[ 55]);
   SBoxE8(unsigned __int32,W[ 56],W[ 57],W[ 58],W[ 59]); SBoxE7(unsigned __int32,W[ 60],W[ 61],W[ 62],W[ 63]);
   SBoxE6(unsigned __int32,W[ 64],W[ 65],W[ 66],W[ 67]); SBoxE5(unsigned __int32,W[ 68],W[ 69],W[ 70],W[ 71]);
   SBoxE4(unsigned __int32,W[ 72],W[ 73],W[ 74],W[ 75]); SBoxE3(unsigned __int32,W[ 76],W[ 77],W[ 78],W[ 79]);
   SBoxE2(unsigned __int32,W[ 80],W[ 81],W[ 82],W[ 83]); SBoxE1(unsigned __int32,W[ 84],W[ 85],W[ 86],W[ 87]);
   SBoxE8(unsigned __int32,W[ 88],W[ 89],W[ 90],W[ 91]); SBoxE7(unsigned __int32,W[ 92],W[ 93],W[ 94],W[ 95]);
   SBoxE6(unsigned __int32,W[ 96],W[ 97],W[ 98],W[ 99]); SBoxE5(unsigned __int32,W[100],W[101],W[102],W[103]);
   SBoxE4(unsigned __int32,W[104],W[105],W[106],W[107]); SBoxE3(unsigned __int32,W[108],W[109],W[110],W[111]);
   SBoxE2(unsigned __int32,W[112],W[113],W[114],W[115]); SBoxE1(unsigned __int32,W[116],W[117],W[118],W[119]);
   SBoxE8(unsigned __int32,W[120],W[121],W[122],W[123]); SBoxE7(unsigned __int32,W[124],W[125],W[126],W[127]);
   SBoxE6(unsigned __int32,W[128],W[129],W[130],W[131]); SBoxE5(unsigned __int32,W[132],W[133],W[134],W[135]);
   SBoxE4(unsigned __int32,W[136],W[137],W[138],W[139]);
}
