/*
* Support for SHA-256 x86 instrinsic
* Based on public domain code by Sean Gulley
*    (https://github.com/mitls/hacl-star/tree/master/experimental/hash)
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

/* November 10th 2024: Modified for VeraCrypt */

#include "Sha2.h"
#include "Common/Endian.h"
#include "cpu.h"
#include "misc.h"

#if defined(_UEFI) || defined(CRYPTOPP_DISABLE_ASM)
#define NO_OPTIMIZED_VERSIONS
#endif

#ifndef NO_OPTIMIZED_VERSIONS

#if CRYPTOPP_SHANI_AVAILABLE

#ifndef _MSC_VER
#include <signal.h>
#include <setjmp.h>

typedef void (*SigHandler)(int);

static jmp_buf s_jmpNoSHA;
static void SigIllHandlerSHA(int p)
{
	longjmp(s_jmpNoSHA, 1);
}
#endif

int TrySHA256()
{
    volatile int result = 0;
#ifdef _MSC_VER
    __try
#else
    SigHandler oldHandler = signal(SIGILL, SigIllHandlerSHA);
    if (oldHandler == SIG_ERR)
        return 0;
    if (setjmp(s_jmpNoSHA))
        result = 0;
    else
#endif
    {
        // Known input message block
        __m128i msg0 = _mm_setr_epi32(0x12345678, 0x9ABCDEF0, 0x87654321, 0x0FEDCBA9);
        __m128i msg1 = _mm_setr_epi32(0x11111111, 0x22222222, 0x33333333, 0x44444444);
        
        // SHA256 message schedule update
        __m128i tmp = _mm_sha256msg1_epu32(msg0, msg1);
        
        // Verify result - these values were pre-computed for the given input
#ifdef _MSC_VER
        if (tmp.m128i_u32[0] == 0xD8131B44 &&
            tmp.m128i_u32[1] == 0x9DE6E22B &&
            tmp.m128i_u32[2] == 0xA86D643A &&
            tmp.m128i_u32[3] == 0x74320FED)
#else
        if (((uint32_t*)(&tmp))[0] == 0xD8131B44 &&
            ((uint32_t*)(&tmp))[1] == 0x9DE6E22B &&
            ((uint32_t*)(&tmp))[2] == 0xA86D643A &&
            ((uint32_t*)(&tmp))[3] == 0x74320FED)
#endif
            result = 1;
    }
#ifdef _MSC_VER
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        // ignore error if SHA instructions not supported
    }
#else
    signal(SIGILL, oldHandler);
#endif

    return result;
}

//
void sha256_intel(void *mp, uint_32t state[8], uint_64t num_blks) 
{
    // Constants table - align for better performance
    CRYPTOPP_ALIGN_DATA(64) 
    static const uint_32t K[64] = {
        0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
        0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
        0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
        0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
        0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
        0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
        0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
        0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
    };

    const __m128i* K_mm = (const __m128i*)K;
    const __m128i* input_mm = (const __m128i*)mp;
    
    // Create byte shuffle mask for big-endian to little-endian conversion
    const __m128i MASK = _mm_set_epi64x(0x0c0d0e0f08090a0b, 0x0405060700010203);

    // Load initial values
    __m128i STATE0 = _mm_loadu_si128((__m128i*)&state[0]);
    __m128i STATE1 = _mm_loadu_si128((__m128i*)&state[4]);

    // Adjust byte ordering
    STATE0 = _mm_shuffle_epi32(STATE0, 0xB1);  // CDAB
    STATE1 = _mm_shuffle_epi32(STATE1, 0x1B);  // EFGH

    __m128i TMP = _mm_alignr_epi8(STATE0, STATE1, 8);  // ABEF
    STATE1 = _mm_blend_epi16(STATE1, STATE0, 0xF0);    // CDGH
    STATE0 = TMP;

    while(num_blks > 0) {
        // Save current state
        const __m128i ABEF_SAVE = STATE0;
        const __m128i CDGH_SAVE = STATE1;

        __m128i MSG;

        __m128i TMSG0 = _mm_shuffle_epi8(_mm_loadu_si128(input_mm), MASK);
        __m128i TMSG1 = _mm_shuffle_epi8(_mm_loadu_si128(input_mm + 1), MASK);
        __m128i TMSG2 = _mm_shuffle_epi8(_mm_loadu_si128(input_mm + 2), MASK);
        __m128i TMSG3 = _mm_shuffle_epi8(_mm_loadu_si128(input_mm + 3), MASK);

        // Rounds 0-3
        MSG = _mm_add_epi32(TMSG0, _mm_load_si128(K_mm));
        STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
        STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, _mm_shuffle_epi32(MSG, 0x0E));

        // Rounds 4-7
        MSG = _mm_add_epi32(TMSG1, _mm_load_si128(K_mm + 1));
        STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
        STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, _mm_shuffle_epi32(MSG, 0x0E));

        TMSG0 = _mm_sha256msg1_epu32(TMSG0, TMSG1);

        // Rounds 8-11
        MSG = _mm_add_epi32(TMSG2, _mm_load_si128(K_mm + 2));
        STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
        STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, _mm_shuffle_epi32(MSG, 0x0E));

        TMSG1 = _mm_sha256msg1_epu32(TMSG1, TMSG2);

        // Rounds 12-15
        MSG = _mm_add_epi32(TMSG3, _mm_load_si128(K_mm + 3));
        STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
        STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, _mm_shuffle_epi32(MSG, 0x0E));

        TMSG0 = _mm_add_epi32(TMSG0, _mm_alignr_epi8(TMSG3, TMSG2, 4));
        TMSG0 = _mm_sha256msg2_epu32(TMSG0, TMSG3);
        TMSG2 = _mm_sha256msg1_epu32(TMSG2, TMSG3);

        // Rounds 16-19
        MSG = _mm_add_epi32(TMSG0, _mm_load_si128(K_mm + 4));
        STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
        STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, _mm_shuffle_epi32(MSG, 0x0E));

        TMSG1 = _mm_add_epi32(TMSG1, _mm_alignr_epi8(TMSG0, TMSG3, 4));
        TMSG1 = _mm_sha256msg2_epu32(TMSG1, TMSG0);
        TMSG3 = _mm_sha256msg1_epu32(TMSG3, TMSG0);

        // Rounds 20-23
        MSG = _mm_add_epi32(TMSG1, _mm_load_si128(K_mm + 5));
        STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
        STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, _mm_shuffle_epi32(MSG, 0x0E));

        TMSG2 = _mm_add_epi32(TMSG2, _mm_alignr_epi8(TMSG1, TMSG0, 4));
        TMSG2 = _mm_sha256msg2_epu32(TMSG2, TMSG1);
        TMSG0 = _mm_sha256msg1_epu32(TMSG0, TMSG1);

        // Rounds 24-27
        MSG = _mm_add_epi32(TMSG2, _mm_load_si128(K_mm + 6));
        STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
        STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, _mm_shuffle_epi32(MSG, 0x0E));

        TMSG3 = _mm_add_epi32(TMSG3, _mm_alignr_epi8(TMSG2, TMSG1, 4));
        TMSG3 = _mm_sha256msg2_epu32(TMSG3, TMSG2);
        TMSG1 = _mm_sha256msg1_epu32(TMSG1, TMSG2);

        // Rounds 28-31
        MSG = _mm_add_epi32(TMSG3, _mm_load_si128(K_mm + 7));
        STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
        STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, _mm_shuffle_epi32(MSG, 0x0E));

        TMSG0 = _mm_add_epi32(TMSG0, _mm_alignr_epi8(TMSG3, TMSG2, 4));
        TMSG0 = _mm_sha256msg2_epu32(TMSG0, TMSG3);
        TMSG2 = _mm_sha256msg1_epu32(TMSG2, TMSG3);

        // Rounds 32-35
        MSG = _mm_add_epi32(TMSG0, _mm_load_si128(K_mm + 8));
        STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
        STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, _mm_shuffle_epi32(MSG, 0x0E));

        TMSG1 = _mm_add_epi32(TMSG1, _mm_alignr_epi8(TMSG0, TMSG3, 4));
        TMSG1 = _mm_sha256msg2_epu32(TMSG1, TMSG0);
        TMSG3 = _mm_sha256msg1_epu32(TMSG3, TMSG0);

        // Rounds 36-39
        MSG = _mm_add_epi32(TMSG1, _mm_load_si128(K_mm + 9));
        STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
        STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, _mm_shuffle_epi32(MSG, 0x0E));

        TMSG2 = _mm_add_epi32(TMSG2, _mm_alignr_epi8(TMSG1, TMSG0, 4));
        TMSG2 = _mm_sha256msg2_epu32(TMSG2, TMSG1);
        TMSG0 = _mm_sha256msg1_epu32(TMSG0, TMSG1);

        // Rounds 40-43
        MSG = _mm_add_epi32(TMSG2, _mm_load_si128(K_mm + 10));
        STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
        STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, _mm_shuffle_epi32(MSG, 0x0E));

        TMSG3 = _mm_add_epi32(TMSG3, _mm_alignr_epi8(TMSG2, TMSG1, 4));
        TMSG3 = _mm_sha256msg2_epu32(TMSG3, TMSG2);
        TMSG1 = _mm_sha256msg1_epu32(TMSG1, TMSG2);

        // Rounds 44-47
        MSG = _mm_add_epi32(TMSG3, _mm_load_si128(K_mm + 11));
        STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
        STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, _mm_shuffle_epi32(MSG, 0x0E));

        TMSG0 = _mm_add_epi32(TMSG0, _mm_alignr_epi8(TMSG3, TMSG2, 4));
        TMSG0 = _mm_sha256msg2_epu32(TMSG0, TMSG3);
        TMSG2 = _mm_sha256msg1_epu32(TMSG2, TMSG3);

        // Rounds 48-51
        MSG = _mm_add_epi32(TMSG0, _mm_load_si128(K_mm + 12));
        STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
        STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, _mm_shuffle_epi32(MSG, 0x0E));

        TMSG1 = _mm_add_epi32(TMSG1, _mm_alignr_epi8(TMSG0, TMSG3, 4));
        TMSG1 = _mm_sha256msg2_epu32(TMSG1, TMSG0);
        TMSG3 = _mm_sha256msg1_epu32(TMSG3, TMSG0);

        // Rounds 52-55
        MSG = _mm_add_epi32(TMSG1, _mm_load_si128(K_mm + 13));
        STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
        STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, _mm_shuffle_epi32(MSG, 0x0E));

        TMSG2 = _mm_add_epi32(TMSG2, _mm_alignr_epi8(TMSG1, TMSG0, 4));
        TMSG2 = _mm_sha256msg2_epu32(TMSG2, TMSG1);

        // Rounds 56-59
        MSG = _mm_add_epi32(TMSG2, _mm_load_si128(K_mm + 14));
        STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
        STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, _mm_shuffle_epi32(MSG, 0x0E));

        TMSG3 = _mm_add_epi32(TMSG3, _mm_alignr_epi8(TMSG2, TMSG1, 4));
        TMSG3 = _mm_sha256msg2_epu32(TMSG3, TMSG2);

        // Rounds 60-63
        MSG = _mm_add_epi32(TMSG3, _mm_load_si128(K_mm + 15));
        STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
        STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, _mm_shuffle_epi32(MSG, 0x0E));

        // Add values back to state
        STATE0 = _mm_add_epi32(STATE0, ABEF_SAVE);
        STATE1 = _mm_add_epi32(STATE1, CDGH_SAVE);

        input_mm += 4;
        num_blks--;
    }

    // Shuffle state back to correct order
    STATE0 = _mm_shuffle_epi32(STATE0, 0x1B);  // FEBA
    STATE1 = _mm_shuffle_epi32(STATE1, 0xB1);  // DCHG

    // Save state
    _mm_storeu_si128((__m128i*)&state[0], _mm_blend_epi16(STATE0, STATE1, 0xF0));  // DCBA
    _mm_storeu_si128((__m128i*)&state[4], _mm_alignr_epi8(STATE1, STATE0, 8));     // HGFE
}

#endif
#endif
