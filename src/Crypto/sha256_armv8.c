/*
* SHA-256 using CPU instructions in ARMv8
*
* Contributed by Jeffrey Walton. Based on public domain code by
* Johannes Schneiders, Skip Hovsmith and Barry O'Rourke.
*
* Further changes (C) 2020 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

/* Modified and adapted for VeraCrypt */

#include "Common/Tcdefs.h"
#if !defined(_UEFI)
#include <memory.h>
#include <stdlib.h>
#endif
#include "cpu.h"
#include "misc.h"

#if CRYPTOPP_ARM_SHA2_AVAILABLE

#include <arm_neon.h>

CRYPTOPP_ALIGN_DATA(64) static const uint32 K[] = {
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
};

void sha256_compress_digest_armv8(void* input_data, uint32 digest[8], uint64 num_blks) {


    // Load initial values
    uint32x4_t STATE0 = vld1q_u32(&digest[0]);
    uint32x4_t STATE1 = vld1q_u32(&digest[4]);

    // Intermediate void* cast due to https://llvm.org/bugs/show_bug.cgi?id=20670
    const uint32* input32 = (const uint32*)(const void*)input_data;

    while (num_blks > 0) {
        // Save current state
        const uint32x4_t ABCD_SAVE = STATE0;
        const uint32x4_t EFGH_SAVE = STATE1;

        uint32x4_t MSG0 = vld1q_u32(input32 + 0);
        uint32x4_t MSG1 = vld1q_u32(input32 + 4);
        uint32x4_t MSG2 = vld1q_u32(input32 + 8);
        uint32x4_t MSG3 = vld1q_u32(input32 + 12);

        MSG0 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(MSG0)));
        MSG1 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(MSG1)));
        MSG2 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(MSG2)));
        MSG3 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(MSG3)));

        uint32x4_t MSG_K, TSTATE;

        // Rounds 0-3
        MSG_K = vaddq_u32(MSG0, vld1q_u32(&K[4 * 0]));
        TSTATE = vsha256hq_u32(STATE0, STATE1, MSG_K);
        STATE1 = vsha256h2q_u32(STATE1, STATE0, MSG_K);
        STATE0 = TSTATE;
        MSG0 = vsha256su1q_u32(vsha256su0q_u32(MSG0, MSG1), MSG2, MSG3);

        // Rounds 4-7
        MSG_K = vaddq_u32(MSG1, vld1q_u32(&K[4 * 1]));
        TSTATE = vsha256hq_u32(STATE0, STATE1, MSG_K);
        STATE1 = vsha256h2q_u32(STATE1, STATE0, MSG_K);
        STATE0 = TSTATE;
        MSG1 = vsha256su1q_u32(vsha256su0q_u32(MSG1, MSG2), MSG3, MSG0);

        // Rounds 8-11
        MSG_K = vaddq_u32(MSG2, vld1q_u32(&K[4 * 2]));
        TSTATE = vsha256hq_u32(STATE0, STATE1, MSG_K);
        STATE1 = vsha256h2q_u32(STATE1, STATE0, MSG_K);
        STATE0 = TSTATE;
        MSG2 = vsha256su1q_u32(vsha256su0q_u32(MSG2, MSG3), MSG0, MSG1);

        // Rounds 12-15
        MSG_K = vaddq_u32(MSG3, vld1q_u32(&K[4 * 3]));
        TSTATE = vsha256hq_u32(STATE0, STATE1, MSG_K);
        STATE1 = vsha256h2q_u32(STATE1, STATE0, MSG_K);
        STATE0 = TSTATE;
        MSG3 = vsha256su1q_u32(vsha256su0q_u32(MSG3, MSG0), MSG1, MSG2);

        // Rounds 16-19
        MSG_K = vaddq_u32(MSG0, vld1q_u32(&K[4 * 4]));
        TSTATE = vsha256hq_u32(STATE0, STATE1, MSG_K);
        STATE1 = vsha256h2q_u32(STATE1, STATE0, MSG_K);
        STATE0 = TSTATE;
        MSG0 = vsha256su1q_u32(vsha256su0q_u32(MSG0, MSG1), MSG2, MSG3);

        // Rounds 20-23
        MSG_K = vaddq_u32(MSG1, vld1q_u32(&K[4 * 5]));
        TSTATE = vsha256hq_u32(STATE0, STATE1, MSG_K);
        STATE1 = vsha256h2q_u32(STATE1, STATE0, MSG_K);
        STATE0 = TSTATE;
        MSG1 = vsha256su1q_u32(vsha256su0q_u32(MSG1, MSG2), MSG3, MSG0);

        // Rounds 24-27
        MSG_K = vaddq_u32(MSG2, vld1q_u32(&K[4 * 6]));
        TSTATE = vsha256hq_u32(STATE0, STATE1, MSG_K);
        STATE1 = vsha256h2q_u32(STATE1, STATE0, MSG_K);
        STATE0 = TSTATE;
        MSG2 = vsha256su1q_u32(vsha256su0q_u32(MSG2, MSG3), MSG0, MSG1);

        // Rounds 28-31
        MSG_K = vaddq_u32(MSG3, vld1q_u32(&K[4 * 7]));
        TSTATE = vsha256hq_u32(STATE0, STATE1, MSG_K);
        STATE1 = vsha256h2q_u32(STATE1, STATE0, MSG_K);
        STATE0 = TSTATE;
        MSG3 = vsha256su1q_u32(vsha256su0q_u32(MSG3, MSG0), MSG1, MSG2);

        // Rounds 32-35
        MSG_K = vaddq_u32(MSG0, vld1q_u32(&K[4 * 8]));
        TSTATE = vsha256hq_u32(STATE0, STATE1, MSG_K);
        STATE1 = vsha256h2q_u32(STATE1, STATE0, MSG_K);
        STATE0 = TSTATE;
        MSG0 = vsha256su1q_u32(vsha256su0q_u32(MSG0, MSG1), MSG2, MSG3);

        // Rounds 36-39
        MSG_K = vaddq_u32(MSG1, vld1q_u32(&K[4 * 9]));
        TSTATE = vsha256hq_u32(STATE0, STATE1, MSG_K);
        STATE1 = vsha256h2q_u32(STATE1, STATE0, MSG_K);
        STATE0 = TSTATE;
        MSG1 = vsha256su1q_u32(vsha256su0q_u32(MSG1, MSG2), MSG3, MSG0);

        // Rounds 40-43
        MSG_K = vaddq_u32(MSG2, vld1q_u32(&K[4 * 10]));
        TSTATE = vsha256hq_u32(STATE0, STATE1, MSG_K);
        STATE1 = vsha256h2q_u32(STATE1, STATE0, MSG_K);
        STATE0 = TSTATE;
        MSG2 = vsha256su1q_u32(vsha256su0q_u32(MSG2, MSG3), MSG0, MSG1);

        // Rounds 44-47
        MSG_K = vaddq_u32(MSG3, vld1q_u32(&K[4 * 11]));
        TSTATE = vsha256hq_u32(STATE0, STATE1, MSG_K);
        STATE1 = vsha256h2q_u32(STATE1, STATE0, MSG_K);
        STATE0 = TSTATE;
        MSG3 = vsha256su1q_u32(vsha256su0q_u32(MSG3, MSG0), MSG1, MSG2);

        // Rounds 48-51
        MSG_K = vaddq_u32(MSG0, vld1q_u32(&K[4 * 12]));
        TSTATE = vsha256hq_u32(STATE0, STATE1, MSG_K);
        STATE1 = vsha256h2q_u32(STATE1, STATE0, MSG_K);
        STATE0 = TSTATE;

        // Rounds 52-55
        MSG_K = vaddq_u32(MSG1, vld1q_u32(&K[4 * 13]));
        TSTATE = vsha256hq_u32(STATE0, STATE1, MSG_K);
        STATE1 = vsha256h2q_u32(STATE1, STATE0, MSG_K);
        STATE0 = TSTATE;

        // Rounds 56-59
        MSG_K = vaddq_u32(MSG2, vld1q_u32(&K[4 * 14]));
        TSTATE = vsha256hq_u32(STATE0, STATE1, MSG_K);
        STATE1 = vsha256h2q_u32(STATE1, STATE0, MSG_K);
        STATE0 = TSTATE;

        // Rounds 60-63
        MSG_K = vaddq_u32(MSG3, vld1q_u32(&K[4 * 15]));
        TSTATE = vsha256hq_u32(STATE0, STATE1, MSG_K);
        STATE1 = vsha256h2q_u32(STATE1, STATE0, MSG_K);
        STATE0 = TSTATE;

        // Add back to state
        STATE0 = vaddq_u32(STATE0, ABCD_SAVE);
        STATE1 = vaddq_u32(STATE1, EFGH_SAVE);

        input32 += 64 / 4;
        num_blks--;
    }

    // Save state
    vst1q_u32(&digest[0], STATE0);
    vst1q_u32(&digest[4], STATE1);
}
#endif
