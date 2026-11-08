/*
* AES using ARMv8
* Contributed by Jeffrey Walton
*
* Further changes
* (C) 2017,2018 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

/* Modified and adapted for VeraCrypt */

#include "Common/Tcdefs.h"
#include "Aes_hw_cpu.h"
#if !defined(_UEFI)
#include <memory.h>
#include <stdlib.h>
#endif
#include "cpu.h"
#include "misc.h"

#if CRYPTOPP_ARM_AES_AVAILABLE

#include <arm_neon.h>

// Single block encryption operations
VC_INLINE void aes_enc_block(uint8x16_t* B, uint8x16_t K)
{
    *B = vaesmcq_u8(vaeseq_u8(*B, K));
}

VC_INLINE void aes_enc_block_last(uint8x16_t* B, uint8x16_t K, uint8x16_t K2)
{
    *B = veorq_u8(vaeseq_u8(*B, K), K2);
}

// 4-block parallel encryption operations
VC_INLINE void aes_enc_4_blocks(uint8x16_t* B0, uint8x16_t* B1, 
                                  uint8x16_t* B2, uint8x16_t* B3, uint8x16_t K)
{
    *B0 = vaesmcq_u8(vaeseq_u8(*B0, K));
    *B1 = vaesmcq_u8(vaeseq_u8(*B1, K));
    *B2 = vaesmcq_u8(vaeseq_u8(*B2, K));
    *B3 = vaesmcq_u8(vaeseq_u8(*B3, K));
}

VC_INLINE void aes_enc_4_blocks_last(uint8x16_t* B0, uint8x16_t* B1, 
                                       uint8x16_t* B2, uint8x16_t* B3,
                                       uint8x16_t K, uint8x16_t K2)
{
    *B0 = veorq_u8(vaeseq_u8(*B0, K), K2);
    *B1 = veorq_u8(vaeseq_u8(*B1, K), K2);
    *B2 = veorq_u8(vaeseq_u8(*B2, K), K2);
    *B3 = veorq_u8(vaeseq_u8(*B3, K), K2);
}

// Single block decryption operations
VC_INLINE void aes_dec_block(uint8x16_t* B, uint8x16_t K)
{
    *B = vaesimcq_u8(vaesdq_u8(*B, K));
}

VC_INLINE void aes_dec_block_last(uint8x16_t* B, uint8x16_t K, uint8x16_t K2)
{
    *B = veorq_u8(vaesdq_u8(*B, K), K2);
}

// 4-block parallel decryption operations
VC_INLINE void aes_dec_4_blocks(uint8x16_t* B0, uint8x16_t* B1,
                                  uint8x16_t* B2, uint8x16_t* B3, uint8x16_t K)
{
    *B0 = vaesimcq_u8(vaesdq_u8(*B0, K));
    *B1 = vaesimcq_u8(vaesdq_u8(*B1, K));
    *B2 = vaesimcq_u8(vaesdq_u8(*B2, K));
    *B3 = vaesimcq_u8(vaesdq_u8(*B3, K));
}

VC_INLINE void aes_dec_4_blocks_last(uint8x16_t* B0, uint8x16_t* B1,
                                       uint8x16_t* B2, uint8x16_t* B3,
                                       uint8x16_t K, uint8x16_t K2)
{
    *B0 = veorq_u8(vaesdq_u8(*B0, K), K2);
    *B1 = veorq_u8(vaesdq_u8(*B1, K), K2);
    *B2 = veorq_u8(vaesdq_u8(*B2, K), K2);
    *B3 = veorq_u8(vaesdq_u8(*B3, K), K2);
}

VC_INLINE void aes256_hw_encrypt_blocks(uint8 buffer[], size_t blocks, const uint8* ks)
{
    const uint8x16_t K0 = vld1q_u8(ks + 0 * 16);
    const uint8x16_t K1 = vld1q_u8(ks + 1 * 16);
    const uint8x16_t K2 = vld1q_u8(ks + 2 * 16);
    const uint8x16_t K3 = vld1q_u8(ks + 3 * 16);
    const uint8x16_t K4 = vld1q_u8(ks + 4 * 16);
    const uint8x16_t K5 = vld1q_u8(ks + 5 * 16);
    const uint8x16_t K6 = vld1q_u8(ks + 6 * 16);
    const uint8x16_t K7 = vld1q_u8(ks + 7 * 16);
    const uint8x16_t K8 = vld1q_u8(ks + 8 * 16);
    const uint8x16_t K9 = vld1q_u8(ks + 9 * 16);
    const uint8x16_t K10 = vld1q_u8(ks + 10 * 16);
    const uint8x16_t K11 = vld1q_u8(ks + 11 * 16);
    const uint8x16_t K12 = vld1q_u8(ks + 12 * 16);
    const uint8x16_t K13 = vld1q_u8(ks + 13 * 16);
    const uint8x16_t K14 = vld1q_u8(ks + 14 * 16);

    while(blocks >= 4) {
        uint8x16_t B0 = vld1q_u8(buffer);
        uint8x16_t B1 = vld1q_u8(buffer + 16);
        uint8x16_t B2 = vld1q_u8(buffer + 32);
        uint8x16_t B3 = vld1q_u8(buffer + 48);

        aes_enc_4_blocks(&B0, &B1, &B2, &B3, K0);
        aes_enc_4_blocks(&B0, &B1, &B2, &B3, K1);
        aes_enc_4_blocks(&B0, &B1, &B2, &B3, K2);
        aes_enc_4_blocks(&B0, &B1, &B2, &B3, K3);
        aes_enc_4_blocks(&B0, &B1, &B2, &B3, K4);
        aes_enc_4_blocks(&B0, &B1, &B2, &B3, K5);
        aes_enc_4_blocks(&B0, &B1, &B2, &B3, K6);
        aes_enc_4_blocks(&B0, &B1, &B2, &B3, K7);
        aes_enc_4_blocks(&B0, &B1, &B2, &B3, K8);
        aes_enc_4_blocks(&B0, &B1, &B2, &B3, K9);
        aes_enc_4_blocks(&B0, &B1, &B2, &B3, K10);
        aes_enc_4_blocks(&B0, &B1, &B2, &B3, K11);
        aes_enc_4_blocks(&B0, &B1, &B2, &B3, K12);
        aes_enc_4_blocks_last(&B0, &B1, &B2, &B3, K13, K14);

        vst1q_u8(buffer, B0);
        vst1q_u8(buffer + 16, B1); 
        vst1q_u8(buffer + 32, B2);
        vst1q_u8(buffer + 48, B3);

        buffer += 16 * 4;
        blocks -= 4;
    }

    for(size_t i = 0; i != blocks; ++i) {
        uint8x16_t B = vld1q_u8(buffer + 16 * i);
        aes_enc_block(&B, K0);
        aes_enc_block(&B, K1);
        aes_enc_block(&B, K2);
        aes_enc_block(&B, K3);
        aes_enc_block(&B, K4);
        aes_enc_block(&B, K5);
        aes_enc_block(&B, K6);
        aes_enc_block(&B, K7);
        aes_enc_block(&B, K8);
        aes_enc_block(&B, K9);
        aes_enc_block(&B, K10);
        aes_enc_block(&B, K11);
        aes_enc_block(&B, K12);
        aes_enc_block_last(&B, K13, K14);
        vst1q_u8(buffer + 16 * i, B);
    }
}

VC_INLINE void aes256_hw_encrypt_block(uint8 buffer[], const uint8* ks)
{
    const uint8x16_t K0 = vld1q_u8(ks + 0 * 16);
    const uint8x16_t K1 = vld1q_u8(ks + 1 * 16);
    const uint8x16_t K2 = vld1q_u8(ks + 2 * 16);
    const uint8x16_t K3 = vld1q_u8(ks + 3 * 16);
    const uint8x16_t K4 = vld1q_u8(ks + 4 * 16);
    const uint8x16_t K5 = vld1q_u8(ks + 5 * 16);
    const uint8x16_t K6 = vld1q_u8(ks + 6 * 16);
    const uint8x16_t K7 = vld1q_u8(ks + 7 * 16);
    const uint8x16_t K8 = vld1q_u8(ks + 8 * 16);
    const uint8x16_t K9 = vld1q_u8(ks + 9 * 16);
    const uint8x16_t K10 = vld1q_u8(ks + 10 * 16);
    const uint8x16_t K11 = vld1q_u8(ks + 11 * 16);
    const uint8x16_t K12 = vld1q_u8(ks + 12 * 16);
    const uint8x16_t K13 = vld1q_u8(ks + 13 * 16);
    const uint8x16_t K14 = vld1q_u8(ks + 14 * 16);

    uint8x16_t B = vld1q_u8(buffer);
    aes_enc_block(&B, K0);
    aes_enc_block(&B, K1);
    aes_enc_block(&B, K2);
    aes_enc_block(&B, K3);
    aes_enc_block(&B, K4);
    aes_enc_block(&B, K5);
    aes_enc_block(&B, K6);
    aes_enc_block(&B, K7);
    aes_enc_block(&B, K8);
    aes_enc_block(&B, K9);
    aes_enc_block(&B, K10);
    aes_enc_block(&B, K11);
    aes_enc_block(&B, K12);
    aes_enc_block_last(&B, K13, K14);
    vst1q_u8(buffer, B);
}

VC_INLINE void aes256_hw_decrypt_blocks(uint8 buffer[], size_t blocks, const uint8* ks)
{
    const uint8x16_t K0 = vld1q_u8(ks + 0 * 16);
    const uint8x16_t K1 = vld1q_u8(ks + 1 * 16);
    const uint8x16_t K2 = vld1q_u8(ks + 2 * 16);
    const uint8x16_t K3 = vld1q_u8(ks + 3 * 16);
    const uint8x16_t K4 = vld1q_u8(ks + 4 * 16);
    const uint8x16_t K5 = vld1q_u8(ks + 5 * 16);
    const uint8x16_t K6 = vld1q_u8(ks + 6 * 16);
    const uint8x16_t K7 = vld1q_u8(ks + 7 * 16);
    const uint8x16_t K8 = vld1q_u8(ks + 8 * 16);
    const uint8x16_t K9 = vld1q_u8(ks + 9 * 16);
    const uint8x16_t K10 = vld1q_u8(ks + 10 * 16);
    const uint8x16_t K11 = vld1q_u8(ks + 11 * 16);
    const uint8x16_t K12 = vld1q_u8(ks + 12 * 16);
    const uint8x16_t K13 = vld1q_u8(ks + 13 * 16);
    const uint8x16_t K14 = vld1q_u8(ks + 14 * 16);

    while(blocks >= 4) {
        uint8x16_t B0 = vld1q_u8(buffer);
        uint8x16_t B1 = vld1q_u8(buffer + 16);
        uint8x16_t B2 = vld1q_u8(buffer + 32);
        uint8x16_t B3 = vld1q_u8(buffer + 48);

        aes_dec_4_blocks(&B0, &B1, &B2, &B3, K0);
        aes_dec_4_blocks(&B0, &B1, &B2, &B3, K1);
        aes_dec_4_blocks(&B0, &B1, &B2, &B3, K2);
        aes_dec_4_blocks(&B0, &B1, &B2, &B3, K3);
        aes_dec_4_blocks(&B0, &B1, &B2, &B3, K4);
        aes_dec_4_blocks(&B0, &B1, &B2, &B3, K5);
        aes_dec_4_blocks(&B0, &B1, &B2, &B3, K6);
        aes_dec_4_blocks(&B0, &B1, &B2, &B3, K7);
        aes_dec_4_blocks(&B0, &B1, &B2, &B3, K8);
        aes_dec_4_blocks(&B0, &B1, &B2, &B3, K9);
        aes_dec_4_blocks(&B0, &B1, &B2, &B3, K10);
        aes_dec_4_blocks(&B0, &B1, &B2, &B3, K11);
        aes_dec_4_blocks(&B0, &B1, &B2, &B3, K12);
        aes_dec_4_blocks_last(&B0, &B1, &B2, &B3, K13, K14);

        vst1q_u8(buffer, B0);
        vst1q_u8(buffer + 16, B1);
        vst1q_u8(buffer + 32, B2);
        vst1q_u8(buffer + 48, B3);

        buffer += 16 * 4;
        blocks -= 4;
    }

    for(size_t i = 0; i != blocks; ++i) {
        uint8x16_t B = vld1q_u8(buffer + 16 * i);
        aes_dec_block(&B, K0);
        aes_dec_block(&B, K1);
        aes_dec_block(&B, K2);
        aes_dec_block(&B, K3);
        aes_dec_block(&B, K4);
        aes_dec_block(&B, K5);
        aes_dec_block(&B, K6);
        aes_dec_block(&B, K7);
        aes_dec_block(&B, K8);
        aes_dec_block(&B, K9);
        aes_dec_block(&B, K10);
        aes_dec_block(&B, K11);
        aes_dec_block(&B, K12);
        aes_dec_block_last(&B, K13, K14);
        vst1q_u8(buffer + 16 * i, B);
    }
}

VC_INLINE void aes256_hw_decrypt_block(uint8 buffer[], const uint8* ks)
{
    const uint8x16_t K0 = vld1q_u8(ks + 0 * 16);
    const uint8x16_t K1 = vld1q_u8(ks + 1 * 16);
    const uint8x16_t K2 = vld1q_u8(ks + 2 * 16);
    const uint8x16_t K3 = vld1q_u8(ks + 3 * 16);
    const uint8x16_t K4 = vld1q_u8(ks + 4 * 16);
    const uint8x16_t K5 = vld1q_u8(ks + 5 * 16);
    const uint8x16_t K6 = vld1q_u8(ks + 6 * 16);
    const uint8x16_t K7 = vld1q_u8(ks + 7 * 16);
    const uint8x16_t K8 = vld1q_u8(ks + 8 * 16);
    const uint8x16_t K9 = vld1q_u8(ks + 9 * 16);
    const uint8x16_t K10 = vld1q_u8(ks + 10 * 16);
    const uint8x16_t K11 = vld1q_u8(ks + 11 * 16);
    const uint8x16_t K12 = vld1q_u8(ks + 12 * 16);
    const uint8x16_t K13 = vld1q_u8(ks + 13 * 16);
    const uint8x16_t K14 = vld1q_u8(ks + 14 * 16);

    uint8x16_t B = vld1q_u8(buffer);
    aes_dec_block(&B, K0);
    aes_dec_block(&B, K1);
    aes_dec_block(&B, K2);
    aes_dec_block(&B, K3);
    aes_dec_block(&B, K4);
    aes_dec_block(&B, K5);
    aes_dec_block(&B, K6);
    aes_dec_block(&B, K7);
    aes_dec_block(&B, K8);
    aes_dec_block(&B, K9);
    aes_dec_block(&B, K10);
    aes_dec_block(&B, K11);
    aes_dec_block(&B, K12);
    aes_dec_block_last(&B, K13, K14);
    vst1q_u8(buffer, B);
}

void aes_hw_cpu_decrypt (const uint8 *ks, uint8 *data)
{
    aes256_hw_decrypt_block(data, ks);
}

void aes_hw_cpu_decrypt_32_blocks (const uint8 *ks, uint8 *data)
{
    aes256_hw_decrypt_blocks(data, 32, ks);
}

void aes_hw_cpu_encrypt (const uint8 *ks, uint8 *data)
{
    aes256_hw_encrypt_block(data, ks);
}

void aes_hw_cpu_encrypt_32_blocks (const uint8 *ks, uint8 *data)
{
    aes256_hw_encrypt_blocks(data, 32, ks);
}

#endif
