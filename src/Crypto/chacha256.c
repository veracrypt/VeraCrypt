/*
This code is written by kerukuro for cppcrypto library (http://cppcrypto.sourceforge.net/)
and released into public domain.
*/

/* adapted for VeraCrypt */

#include "chacha256.h"
#include "cpu.h"
#include "misc.h"



#define rotater32(x,n)	rotr32(x, n)
#define rotatel32(x,n)	rotl32(x, n)

#if CRYPTOPP_BOOL_SSE2_INTRINSICS_AVAILABLE
void chacha_ECRYPT_encrypt_bytes(size_t bytes, uint32* x, const unsigned char* m, unsigned char* out, unsigned char* output, unsigned int r);
#endif

static VC_INLINE void xor_block_512(const unsigned char* in, const unsigned char* prev, unsigned char* out)
{
#if CRYPTOPP_BOOL_SSE2_INTRINSICS_AVAILABLE && !defined(_UEFI) && (!defined (TC_WINDOWS_DRIVER) || (!defined (DEBUG) && defined (_WIN64)))
    if (HasSSE2())
    {
        __m128i b1 = _mm_loadu_si128((const __m128i*) in);
        __m128i p1 = _mm_loadu_si128((const __m128i*) prev);
        __m128i b2 = _mm_loadu_si128((const __m128i*) (in + 16));
        __m128i p2 = _mm_loadu_si128((const __m128i*) (prev + 16));

        _mm_storeu_si128((__m128i*) out, _mm_xor_si128(b1, p1));
        _mm_storeu_si128((__m128i*) (out + 16), _mm_xor_si128(b2, p2));

        b1 = _mm_loadu_si128((const __m128i*) (in + 32));
        p1 = _mm_loadu_si128((const __m128i*) (prev + 32));
        b2 = _mm_loadu_si128((const __m128i*) (in + 48));
        p2 = _mm_loadu_si128((const __m128i*) (prev + 48));

        _mm_storeu_si128((__m128i*) (out + 32), _mm_xor_si128(b1, p1));
        _mm_storeu_si128((__m128i*) (out + 48), _mm_xor_si128(b2, p2));

    }
    else
#endif
	{
		int i;
        for (i = 0; i < 64; i++)
            out[i] = in[i] ^ prev[i];
    }

}

static VC_INLINE void chacha_core(uint32* x, int r)
{
	int i;
    for (i = 0; i < r; i++)
    {
        x[0] += x[4];
        x[12] = rotatel32(x[12] ^ x[0], 16);
        x[8] += x[12];
        x[4] = rotatel32(x[4] ^ x[8], 12);
        x[0] += x[4];
        x[12] = rotatel32(x[12] ^ x[0], 8);
        x[8] += x[12];
        x[4] = rotatel32(x[4] ^ x[8], 7);

        x[1] += x[5];
        x[13] = rotatel32(x[13] ^ x[1], 16);
        x[9] += x[13];
        x[5] = rotatel32(x[5] ^ x[9], 12);
        x[1] += x[5];
        x[13] = rotatel32(x[13] ^ x[1], 8);
        x[9] += x[13];
        x[5] = rotatel32(x[5] ^ x[9], 7);

        x[2] += x[6];
        x[14] = rotatel32(x[14] ^ x[2], 16);
        x[10] += x[14];
        x[6] = rotatel32(x[6] ^ x[10], 12);
        x[2] += x[6];
        x[14] = rotatel32(x[14] ^ x[2], 8);
        x[10] += x[14];
        x[6] = rotatel32(x[6] ^ x[10], 7);

        x[3] += x[7];
        x[15] = rotatel32(x[15] ^ x[3], 16);
        x[11] += x[15];
        x[7] = rotatel32(x[7] ^ x[11], 12);
        x[3] += x[7];
        x[15] = rotatel32(x[15] ^ x[3], 8);
        x[11] += x[15];
        x[7] = rotatel32(x[7] ^ x[11], 7);

        x[0] += x[5];
        x[15] = rotatel32(x[15] ^ x[0], 16);
        x[10] += x[15];
        x[5] = rotatel32(x[5] ^ x[10], 12);
        x[0] += x[5];
        x[15] = rotatel32(x[15] ^ x[0], 8);
        x[10] += x[15];
        x[5] = rotatel32(x[5] ^ x[10], 7);

        x[1] += x[6];
        x[12] = rotatel32(x[12] ^ x[1], 16);
        x[11] += x[12];
        x[6] = rotatel32(x[6] ^ x[11], 12);
        x[1] += x[6];
        x[12] = rotatel32(x[12] ^ x[1], 8);
        x[11] += x[12];
        x[6] = rotatel32(x[6] ^ x[11], 7);

        x[2] += x[7];
        x[13] = rotatel32(x[13] ^ x[2], 16);
        x[8] += x[13];
        x[7] = rotatel32(x[7] ^ x[8], 12);
        x[2] += x[7];
        x[13] = rotatel32(x[13] ^ x[2], 8);
        x[8] += x[13];
        x[7] = rotatel32(x[7] ^ x[8], 7);

        x[3] += x[4];
        x[14] = rotatel32(x[14] ^ x[3], 16);
        x[9] += x[14];
        x[4] = rotatel32(x[4] ^ x[9], 12);
        x[3] += x[4];
        x[14] = rotatel32(x[14] ^ x[3], 8);
        x[9] += x[14];
        x[4] = rotatel32(x[4] ^ x[9], 7);
    }
}

static VC_INLINE void chacha_hash(const uint32* in, uint32* out, int r)
{
    uint32 x[16];
	int i;
    memcpy(x, in, 64);
    chacha_core(x, r);
    for (i = 0; i < 16; ++i)
        out[i] = x[i] + in[i];
}

static VC_INLINE void incrementSalsaCounter(uint32* input, uint32* block, int r)
{
    chacha_hash(input, block, r);
    if (!++input[12])
        ++input[13];
}

static VC_INLINE void do_encrypt(const unsigned char* in, size_t len, unsigned char* out, int r, size_t* posPtr, uint32* input, uint32* block)
{
    size_t i = 0, pos = *posPtr;
    if (pos)
    {
        while (pos < len && pos < 64)
        {
            out[i] = in[i] ^ ((unsigned char*)block)[pos++];
            ++i;
        }
        len -= i;
    }
    if (len)
        pos = 0;

#if CRYPTOPP_SSSE3_AVAILABLE && !defined(_UEFI) && (!defined (TC_WINDOWS_DRIVER) || (!defined (DEBUG) && defined (_WIN64)))
    if (HasSSSE3())
    {
        size_t fullblocks = len - len % 64;
        if (fullblocks)
        {
            chacha_ECRYPT_encrypt_bytes(fullblocks, input, in + i, out + i, (unsigned char*)block, r);
            i += fullblocks;
            len -= fullblocks;
        }
        if (len)
        {
            chacha_ECRYPT_encrypt_bytes(len, input, in + i, out + i, (unsigned char*)block, r);
            pos = len;
        }
        *posPtr = pos;
        return;
    }
#endif

    for (; len; len -= VC_MIN(64, len))
    {
        incrementSalsaCounter(input, block, r);
        if (len >= 64)
        {
            xor_block_512(in + i, (unsigned char*)block, out + i);
            i += 64;
        }
        else
        {
            for (; pos < len; pos++, i++)
                out[i] = in[i] ^ ((unsigned char*)block)[pos];
        }
    }
    *posPtr = pos;
}

void ChaCha256Init(ChaCha256Ctx* ctx, const unsigned char* key, const unsigned char* iv, int rounds)
{    
    ctx->internalRounds = rounds / 2;
    ctx->pos = 0;
    
    ctx->input_[12] = 0;
    ctx->input_[13] = 0;
    memcpy(ctx->input_ + 4, key, 32);
    memcpy(ctx->input_ + 14, iv, 8);
    ctx->input_[0] = 0x61707865;
    ctx->input_[1] = 0x3320646E;
    ctx->input_[2] = 0x79622D32;
    ctx->input_[3] = 0x6B206574;
}

void ChaCha256Encrypt(ChaCha256Ctx* ctx, const unsigned char* in, size_t len, unsigned char* out)
{
    do_encrypt(in, len, out, ctx->internalRounds, &ctx->pos, ctx->input_, ctx->block_);
}
