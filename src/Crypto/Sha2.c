/*
This code is written by kerukuro for cppcrypto library (http://cppcrypto.sourceforge.net/)
and released into public domain.
*/

/* Modified for VeraCrypt with speed optimization for C implementation */

#include "Sha2.h"
#include "Common/Endian.h"
#include "Crypto/cpu.h"
#include "Crypto/misc.h"

#ifdef _UEFI
#define NO_OPTIMIZED_VERSIONS
#endif

#ifndef NO_OPTIMIZED_VERSIONS

#if defined(__cplusplus)
extern "C"
{
#endif
#if CRYPTOPP_BOOL_X64
	void sha512_rorx(const void* M, void* D, uint_64t l);
	void sha512_sse4(const void* M, uint_64t D[8], uint_64t l);
	void sha512_avx(const void* M, void* D, uint_64t l);
#endif
	
#if CRYPTOPP_BOOL_X64 || ((CRYPTOPP_BOOL_X86 || CRYPTOPP_BOOL_X32) && !defined (TC_MACOSX))
	void sha512_compress_nayuki(uint_64t state[8], const uint_8t block[128]);
#endif
#if defined(__cplusplus)
}
#endif

#endif

typedef void (*transformFn)(sha512_ctx* ctx, void* m, uint_64t num_blks);

transformFn transfunc = NULL;

static const uint_64t K[80] = {
	LL(0x428a2f98d728ae22), LL(0x7137449123ef65cd), LL(0xb5c0fbcfec4d3b2f), LL(0xe9b5dba58189dbbc),
	LL(0x3956c25bf348b538), LL(0x59f111f1b605d019), LL(0x923f82a4af194f9b), LL(0xab1c5ed5da6d8118),
	LL(0xd807aa98a3030242), LL(0x12835b0145706fbe), LL(0x243185be4ee4b28c), LL(0x550c7dc3d5ffb4e2),
	LL(0x72be5d74f27b896f), LL(0x80deb1fe3b1696b1), LL(0x9bdc06a725c71235), LL(0xc19bf174cf692694),
	LL(0xe49b69c19ef14ad2), LL(0xefbe4786384f25e3), LL(0x0fc19dc68b8cd5b5), LL(0x240ca1cc77ac9c65),
	LL(0x2de92c6f592b0275), LL(0x4a7484aa6ea6e483), LL(0x5cb0a9dcbd41fbd4), LL(0x76f988da831153b5),
	LL(0x983e5152ee66dfab), LL(0xa831c66d2db43210), LL(0xb00327c898fb213f), LL(0xbf597fc7beef0ee4),
	LL(0xc6e00bf33da88fc2), LL(0xd5a79147930aa725), LL(0x06ca6351e003826f), LL(0x142929670a0e6e70),
	LL(0x27b70a8546d22ffc), LL(0x2e1b21385c26c926), LL(0x4d2c6dfc5ac42aed), LL(0x53380d139d95b3df),
	LL(0x650a73548baf63de), LL(0x766a0abb3c77b2a8), LL(0x81c2c92e47edaee6), LL(0x92722c851482353b),
	LL(0xa2bfe8a14cf10364), LL(0xa81a664bbc423001), LL(0xc24b8b70d0f89791), LL(0xc76c51a30654be30),
	LL(0xd192e819d6ef5218), LL(0xd69906245565a910), LL(0xf40e35855771202a), LL(0x106aa07032bbd1b8),
	LL(0x19a4c116b8d2d0c8), LL(0x1e376c085141ab53), LL(0x2748774cdf8eeb99), LL(0x34b0bcb5e19b48a8),
	LL(0x391c0cb3c5c95a63), LL(0x4ed8aa4ae3418acb), LL(0x5b9cca4f7763e373), LL(0x682e6ff3d6b2b8a3),
	LL(0x748f82ee5defb2fc), LL(0x78a5636f43172f60), LL(0x84c87814a1f0ab72), LL(0x8cc702081a6439ec),
	LL(0x90befffa23631e28), LL(0xa4506cebde82bde9), LL(0xbef9a3f7b2c67915), LL(0xc67178f2e372532b),
	LL(0xca273eceea26619c), LL(0xd186b8c721c0c207), LL(0xeada7dd6cde0eb1e), LL(0xf57d4f7fee6ed178),
	LL(0x06f067aa72176fba), LL(0x0a637dc5a2c898a6), LL(0x113f9804bef90dae), LL(0x1b710b35131c471b),
	LL(0x28db77f523047d84), LL(0x32caab7b40c72493), LL(0x3c9ebe0a15c9bebc), LL(0x431d67c49c100d4c),
	LL(0x4cc5d4becb3e42b6), LL(0x597f299cfc657e2a), LL(0x5fcb6fab3ad6faec), LL(0x6c44198c4a475817)
};


#define Ch(x,y,z)       ((z) ^ ((x) & ((y) ^ (z))))
#define Maj(x,y,z)      (((x) & (y)) | ((z) & ((x) ^ (y))))
#define sum0(x)			(rotr64((x), 28) ^ rotr64((x), 34) ^ rotr64((x), 39))
#define sum1(x)			(rotr64((x), 14) ^ rotr64((x), 18) ^ rotr64((x), 41))
#define sigma0(x)		(rotr64((x), 1) ^ rotr64((x), 8) ^ ((x) >> 7))
#define sigma1(x)		(rotr64((x), 19) ^ rotr64((x), 61) ^ ((x) >> 6))

#define WU(j) (W[j & 15] += sigma1(W[(j + 14) & 15]) + W[(j + 9) & 15] + sigma0(W[(j + 1) & 15]))

#define COMPRESS_ROUND(i, j, K) \
		   T1 = h + sum1(e) + Ch(e, f, g) + K[i + j] + (i? WU(j): W[j]); \
			T2 = sum0(a) + Maj(a, b, c); \
			h = g; \
			g = f; \
			f = e; \
			e = d + T1; \
			d = c; \
			c = b; \
			b = a; \
			a = T1 + T2;

void StdTransform(sha512_ctx* ctx, void* mp, uint_64t num_blks)
{
	uint_64t blk;
	for (blk = 0; blk < num_blks; blk++)
	{
		uint_64t W[16];
		uint_64t a,b,c,d,e,f,g,h;
		uint_64t T1, T2;
		int i;
#if defined (TC_WINDOWS_DRIVER) && defined (DEBUG)
		int	  j;
#endif

		for (i = 0; i < 128 / 8; i++)
		{
			W[i] = bswap_64((((const uint_64t*)(mp))[blk * 16 + i]));
		}

		a = ctx->hash[0];
		b = ctx->hash[1];
		c = ctx->hash[2];
		d = ctx->hash[3];
		e = ctx->hash[4];
		f = ctx->hash[5];
		g = ctx->hash[6];
		h = ctx->hash[7];

		for (i = 0; i <= 79; i+=16)
		{
#if defined (TC_WINDOWS_DRIVER) && defined (DEBUG)
			for (j = 0; j < 16; j++)
			{
				COMPRESS_ROUND(i, j, K);
			}
#else
			COMPRESS_ROUND(i, 0, K);
			COMPRESS_ROUND(i, 1, K);
			COMPRESS_ROUND(i , 2, K);
			COMPRESS_ROUND(i, 3, K);
			COMPRESS_ROUND(i, 4, K);
			COMPRESS_ROUND(i, 5, K);
			COMPRESS_ROUND(i, 6, K);
			COMPRESS_ROUND(i, 7, K);
			COMPRESS_ROUND(i, 8, K);
			COMPRESS_ROUND(i, 9, K);
			COMPRESS_ROUND(i, 10, K);
			COMPRESS_ROUND(i, 11, K);
			COMPRESS_ROUND(i, 12, K);
			COMPRESS_ROUND(i, 13, K);
			COMPRESS_ROUND(i, 14, K);
			COMPRESS_ROUND(i, 15, K);
#endif
		}
		ctx->hash[0] += a;
		ctx->hash[1] += b;
		ctx->hash[2] += c;
		ctx->hash[3] += d;
		ctx->hash[4] += e;
		ctx->hash[5] += f;
		ctx->hash[6] += g;
		ctx->hash[7] += h;
	}
}

#ifndef NO_OPTIMIZED_VERSIONS

#if CRYPTOPP_BOOL_X64
void Avx2Transform(sha512_ctx* ctx, void* mp, uint_64t num_blks)
{
	if (num_blks > 1)
		sha512_rorx(mp, ctx->hash, num_blks);
	else
		sha512_sse4(mp, ctx->hash, num_blks);
}

void AvxTransform(sha512_ctx* ctx, void* mp, uint_64t num_blks)
{
	if (num_blks > 1)
		sha512_avx(mp, ctx->hash, num_blks);
	else
		sha512_sse4(mp, ctx->hash, num_blks);
}

void SSE4Transform(sha512_ctx* ctx, void* mp, uint_64t num_blks)
{
	sha512_sse4(mp, ctx->hash, num_blks);
}
#endif

#if CRYPTOPP_BOOL_X64 || ((CRYPTOPP_BOOL_X86 || CRYPTOPP_BOOL_X32) && !defined (TC_MACOSX))

void SSE2Transform(sha512_ctx* ctx, void* mp, uint_64t num_blks)
{
	uint_64t i;
	for (i = 0; i < num_blks; i++)
		sha512_compress_nayuki(ctx->hash, (uint_8t*)mp + i * 128);
}

#endif

#endif // NO_OPTIMIZED_VERSIONS

void sha512_begin(sha512_ctx* ctx)
{
	ctx->hash[0] = LL(0x6a09e667f3bcc908);
	ctx->hash[1] = LL(0xbb67ae8584caa73b);
	ctx->hash[2] = LL(0x3c6ef372fe94f82b);
	ctx->hash[3] = LL(0xa54ff53a5f1d36f1);
	ctx->hash[4] = LL(0x510e527fade682d1);
	ctx->hash[5] = LL(0x9b05688c2b3e6c1f);
	ctx->hash[6] = LL(0x1f83d9abfb41bd6b);
	ctx->hash[7] = LL(0x5be0cd19137e2179);
	ctx->count[0] = 0;
	ctx->count[1] = 0;

	if (!transfunc)
	{
#ifndef NO_OPTIMIZED_VERSIONS
#if CRYPTOPP_BOOL_X64
		if (g_isIntel&& HasSAVX2() && HasSBMI2())
			transfunc = Avx2Transform;
		else if (g_isIntel && HasSAVX())
		{
				transfunc = AvxTransform;
		}
		else if (HasSSE41())
		{
				transfunc = SSE4Transform;
		}
		else
#endif

#if CRYPTOPP_BOOL_X64 || ((CRYPTOPP_BOOL_X86 || CRYPTOPP_BOOL_X32) && !defined (TC_MACOSX))
#if CRYPTOPP_BOOL_X64
		if (HasSSE2())
#else
		if (HasSSSE3() && HasMMX())
#endif
				transfunc = SSE2Transform;
		else
#endif

#endif
			transfunc = StdTransform;
	}
}

void sha512_end(unsigned char * result, sha512_ctx* ctx)
{
	int i;
	uint_64t mlen, pos = ctx->count[0];
	uint_8t* m = (uint_8t*) ctx->wbuf;
	m[pos++] = 0x80;
	if (pos > 112)
	{
		memset(m + pos, 0, (size_t) (128 - pos));
		transfunc(ctx, m, 1);
		pos = 0;
	}
	memset(m + pos, 0, (size_t) (128 - pos));
	mlen = bswap_64(ctx->count[1]);
	memcpy(m + (128 - 8), &mlen, 64 / 8);
	transfunc(ctx, m, 1);
	for (i = 0; i < 8; i++)
	{
		ctx->hash[i] = bswap_64(ctx->hash[i]);
	}
	memcpy(result, ctx->hash, 64);
}

void sha512_hash(const unsigned char * data, uint_64t len, sha512_ctx *ctx)
{
	uint_64t pos = ctx->count[0];
	uint_64t total = ctx->count[1];
	uint_8t* m = (uint_8t*) ctx->wbuf;
	if (pos && pos + len >= 128)
	{
		memcpy(m + pos, data, (size_t) (128 - pos));
		transfunc(ctx, m, 1);
		len -= 128 - pos;
		total += (128 - pos) * 8;
		data += 128 - pos;
		pos = 0;
	}
	if (len >= 128)
	{
		uint_64t blocks = len / 128;
		uint_64t bytes = blocks * 128;
		transfunc(ctx, (void*)data, blocks);
		len -= bytes;
		total += (bytes)* 8;
		data += bytes;
	}
	memcpy(m+pos, data, (size_t) (len));
	pos += len;
	total += len * 8;
	ctx->count[0] = pos;
	ctx->count[1] = total;
}

void sha512(unsigned char * result, const unsigned char* source, uint_64t sourceLen)
{
	sha512_ctx  ctx;

	sha512_begin(&ctx);
	sha512_hash(source, sourceLen, &ctx);
	sha512_end(result, &ctx);
}

/////////////////////////////

#ifndef NO_OPTIMIZED_VERSIONS

#if defined(__cplusplus)
extern "C"
{
#endif

#if CRYPTOPP_BOOL_X64
	void sha256_sse4(void *input_data, uint_32t digest[8], uint_64t num_blks);
	void sha256_rorx(void *input_data, uint_32t digest[8], uint_64t num_blks);
	void sha256_avx(void *input_data, uint_32t digest[8], uint_64t num_blks);
#endif

#if CRYPTOPP_BOOL_X86 || CRYPTOPP_BOOL_X32
	void sha256_compress_nayuki(uint_32t state[8], const uint_8t block[64]);
#endif

#if defined(__cplusplus)
}
#endif

#endif

CRYPTOPP_ALIGN_DATA(16) uint_32t SHA256_K[64] CRYPTOPP_SECTION_ALIGN16 = {
		0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
		0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
		0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
		0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
		0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
		0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
		0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
		0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
	};

#if (defined(CRYPTOPP_X86_ASM_AVAILABLE) || defined(CRYPTOPP_X32_ASM_AVAILABLE))

#ifdef _MSC_VER
# pragma warning(disable: 4100 4731)
#endif

static void CRYPTOPP_FASTCALL X86_SHA256_HashBlocks(uint_32t *state, const uint_32t *data, size_t len)
{
	#define LOCALS_SIZE	8*4 + 16*4 + 4*WORD_SZ
	#define H(i)		[BASE+ASM_MOD(1024+7-(i),8)*4]
	#define G(i)		H(i+1)
	#define F(i)		H(i+2)
	#define E(i)		H(i+3)
	#define D(i)		H(i+4)
	#define C(i)		H(i+5)
	#define B(i)		H(i+6)
	#define A(i)		H(i+7)
	#define Wt(i)		BASE+8*4+ASM_MOD(1024+15-(i),16)*4
	#define Wt_2(i)		Wt((i)-2)
	#define Wt_15(i)	Wt((i)-15)
	#define Wt_7(i)		Wt((i)-7)
	#define K_END		[BASE+8*4+16*4+0*WORD_SZ]
	#define STATE_SAVE	[BASE+8*4+16*4+1*WORD_SZ]
	#define DATA_SAVE	[BASE+8*4+16*4+2*WORD_SZ]
	#define DATA_END	[BASE+8*4+16*4+3*WORD_SZ]
	#define Kt(i)		WORD_REG(si)+(i)*4
#if CRYPTOPP_BOOL_X32
	#define BASE		esp+8
#elif CRYPTOPP_BOOL_X86
	#define BASE		esp+4
#elif defined(__GNUC__)
	#define BASE		r8
#else
	#define BASE		rsp
#endif

#define RA0(i, edx, edi)		\
	AS2(	add edx, [Kt(i)]	)\
	AS2(	add edx, [Wt(i)]	)\
	AS2(	add edx, H(i)		)\

#define RA1(i, edx, edi)

#define RB0(i, edx, edi)

#define RB1(i, edx, edi)	\
	AS2(	mov AS_REG_7d, [Wt_2(i)]	)\
	AS2(	mov edi, [Wt_15(i)])\
	AS2(	mov ebx, AS_REG_7d	)\
	AS2(	shr AS_REG_7d, 10		)\
	AS2(	ror ebx, 17		)\
	AS2(	xor AS_REG_7d, ebx	)\
	AS2(	ror ebx, 2		)\
	AS2(	xor ebx, AS_REG_7d	)/* s1(W_t-2) */\
	AS2(	add ebx, [Wt_7(i)])\
	AS2(	mov AS_REG_7d, edi	)\
	AS2(	shr AS_REG_7d, 3		)\
	AS2(	ror edi, 7		)\
	AS2(	add ebx, [Wt(i)])/* s1(W_t-2) + W_t-7 + W_t-16 */\
	AS2(	xor AS_REG_7d, edi	)\
	AS2(	add edx, [Kt(i)])\
	AS2(	ror edi, 11		)\
	AS2(	add edx, H(i)	)\
	AS2(	xor AS_REG_7d, edi	)/* s0(W_t-15) */\
	AS2(	add AS_REG_7d, ebx	)/* W_t = s1(W_t-2) + W_t-7 + s0(W_t-15) W_t-16*/\
	AS2(	mov [Wt(i)], AS_REG_7d)\
	AS2(	add edx, AS_REG_7d	)\

#define ROUND(i, r, eax, ecx, edi, edx)\
	/* in: edi = E	*/\
	/* unused: eax, ecx, temp: ebx, AS_REG_7d, out: edx = T1 */\
	AS2(	mov edx, F(i)	)\
	AS2(	xor edx, G(i)	)\
	AS2(	and edx, edi	)\
	AS2(	xor edx, G(i)	)/* Ch(E,F,G) = (G^(E&(F^G))) */\
	AS2(	mov AS_REG_7d, edi	)\
	AS2(	ror edi, 6		)\
	AS2(	ror AS_REG_7d, 25		)\
	RA##r(i, edx, edi		)/* H + Wt + Kt + Ch(E,F,G) */\
	AS2(	xor AS_REG_7d, edi	)\
	AS2(	ror edi, 5		)\
	AS2(	xor AS_REG_7d, edi	)/* S1(E) */\
	AS2(	add edx, AS_REG_7d	)/* T1 = S1(E) + Ch(E,F,G) + H + Wt + Kt */\
	RB##r(i, edx, edi		)/* H + Wt + Kt + Ch(E,F,G) */\
	/* in: ecx = A, eax = B^C, edx = T1 */\
	/* unused: edx, temp: ebx, AS_REG_7d, out: eax = A, ecx = B^C, edx = E */\
	AS2(	mov ebx, ecx	)\
	AS2(	xor ecx, B(i)	)/* A^B */\
	AS2(	and eax, ecx	)\
	AS2(	xor eax, B(i)	)/* Maj(A,B,C) = B^((A^B)&(B^C) */\
	AS2(	mov AS_REG_7d, ebx	)\
	AS2(	ror ebx, 2		)\
	AS2(	add eax, edx	)/* T1 + Maj(A,B,C) */\
	AS2(	add edx, D(i)	)\
	AS2(	mov D(i), edx	)\
	AS2(	ror AS_REG_7d, 22		)\
	AS2(	xor AS_REG_7d, ebx	)\
	AS2(	ror ebx, 11		)\
	AS2(	xor AS_REG_7d, ebx	)\
	AS2(	add eax, AS_REG_7d	)/* T1 + S0(A) + Maj(A,B,C) */\
	AS2(	mov H(i), eax	)\

// Unroll the use of CRYPTOPP_BOOL_X64 in assembler math. The GAS assembler on X32 (version 2.25)
//   complains "Error: invalid operands (*ABS* and *UND* sections) for `*` and `-`"
#if CRYPTOPP_BOOL_X64
#define SWAP_COPY(i)		\
	AS2(	mov		WORD_REG(bx), [WORD_REG(dx)+i*WORD_SZ])\
	AS1(	bswap	WORD_REG(bx))\
	AS2(	mov		[Wt(i*2+1)], WORD_REG(bx))
#else // X86 and X32
#define SWAP_COPY(i)		\
	AS2(	mov		WORD_REG(bx), [WORD_REG(dx)+i*WORD_SZ])\
	AS1(	bswap	WORD_REG(bx))\
	AS2(	mov		[Wt(i)], WORD_REG(bx))
#endif

#if defined(__GNUC__)
	#if CRYPTOPP_BOOL_X64
		CRYPTOPP_ALIGN_DATA(16) byte workspace[LOCALS_SIZE] ;
	#endif
	__asm__ __volatile__
	(
	#if CRYPTOPP_BOOL_X64
		"lea %4, %%r8;"
	#endif
	INTEL_NOPREFIX
#endif

#if CRYPTOPP_BOOL_X86 || CRYPTOPP_BOOL_X32
	#ifndef __GNUC__
		AS2(	mov		edi, [len])
		AS2(	lea		WORD_REG(si), [SHA256_K+48*4])
	#endif
	#if !defined(_MSC_VER) || (_MSC_VER < 1400)
		AS_PUSH_IF86(bx)
	#endif

	AS_PUSH_IF86(bp)
	AS2(	mov		ebx, esp)
	AS2(	and		esp, -16)
	AS2(	sub		WORD_REG(sp), LOCALS_SIZE)
	AS_PUSH_IF86(bx)
#endif
	AS2(	mov		STATE_SAVE, WORD_REG(cx))
	AS2(	mov		DATA_SAVE, WORD_REG(dx))
	AS2(	lea		WORD_REG(ax), [WORD_REG(di) + WORD_REG(dx)])
	AS2(	mov		DATA_END, WORD_REG(ax))
	AS2(	mov		K_END, WORD_REG(si))

#if CRYPTOPP_BOOL_SSE2_ASM_AVAILABLE
#if CRYPTOPP_BOOL_X86 || CRYPTOPP_BOOL_X32
	AS2(	test	edi, 1)
	ASJ(	jnz,	2, f)
	AS1(	dec		DWORD PTR K_END)
#endif
	AS2(	movdqu	xmm0, XMMWORD_PTR [WORD_REG(cx)+0*16])
	AS2(	movdqu	xmm1, XMMWORD_PTR [WORD_REG(cx)+1*16])
#endif

#if CRYPTOPP_BOOL_X86 || CRYPTOPP_BOOL_X32
#if CRYPTOPP_BOOL_SSE2_ASM_AVAILABLE
	ASJ(	jmp,	0, f)
#endif
	ASL(2)	// non-SSE2
	AS2(	mov		esi, ecx)
	AS2(	lea		edi, A(0))
	AS2(	mov		ecx, 8)
ATT_NOPREFIX
	AS1(	rep movsd)
INTEL_NOPREFIX
	AS2(	mov		esi, K_END)
	ASJ(	jmp,	3, f)
#endif

#if CRYPTOPP_BOOL_SSE2_ASM_AVAILABLE
	ASL(0)
	AS2(	movdqu	E(0), xmm1)
	AS2(	movdqu	A(0), xmm0)
#endif
#if CRYPTOPP_BOOL_X86 || CRYPTOPP_BOOL_X32
	ASL(3)
#endif
	AS2(	sub		WORD_REG(si), 48*4)
	SWAP_COPY(0)	SWAP_COPY(1)	SWAP_COPY(2)	SWAP_COPY(3)
	SWAP_COPY(4)	SWAP_COPY(5)	SWAP_COPY(6)	SWAP_COPY(7)
#if CRYPTOPP_BOOL_X86 || CRYPTOPP_BOOL_X32
	SWAP_COPY(8)	SWAP_COPY(9)	SWAP_COPY(10)	SWAP_COPY(11)
	SWAP_COPY(12)	SWAP_COPY(13)	SWAP_COPY(14)	SWAP_COPY(15)
#endif
	AS2(	mov		edi, E(0))	// E
	AS2(	mov		eax, B(0))	// B
	AS2(	xor		eax, C(0))	// B^C
	AS2(	mov		ecx, A(0))	// A

	ROUND(0, 0, eax, ecx, edi, edx)
	ROUND(1, 0, ecx, eax, edx, edi)
	ROUND(2, 0, eax, ecx, edi, edx)
	ROUND(3, 0, ecx, eax, edx, edi)
	ROUND(4, 0, eax, ecx, edi, edx)
	ROUND(5, 0, ecx, eax, edx, edi)
	ROUND(6, 0, eax, ecx, edi, edx)
	ROUND(7, 0, ecx, eax, edx, edi)
	ROUND(8, 0, eax, ecx, edi, edx)
	ROUND(9, 0, ecx, eax, edx, edi)
	ROUND(10, 0, eax, ecx, edi, edx)
	ROUND(11, 0, ecx, eax, edx, edi)
	ROUND(12, 0, eax, ecx, edi, edx)
	ROUND(13, 0, ecx, eax, edx, edi)
	ROUND(14, 0, eax, ecx, edi, edx)
	ROUND(15, 0, ecx, eax, edx, edi)

	ASL(1)
	AS2(add WORD_REG(si), 4*16)
	ROUND(0, 1, eax, ecx, edi, edx)
	ROUND(1, 1, ecx, eax, edx, edi)
	ROUND(2, 1, eax, ecx, edi, edx)
	ROUND(3, 1, ecx, eax, edx, edi)
	ROUND(4, 1, eax, ecx, edi, edx)
	ROUND(5, 1, ecx, eax, edx, edi)
	ROUND(6, 1, eax, ecx, edi, edx)
	ROUND(7, 1, ecx, eax, edx, edi)
	ROUND(8, 1, eax, ecx, edi, edx)
	ROUND(9, 1, ecx, eax, edx, edi)
	ROUND(10, 1, eax, ecx, edi, edx)
	ROUND(11, 1, ecx, eax, edx, edi)
	ROUND(12, 1, eax, ecx, edi, edx)
	ROUND(13, 1, ecx, eax, edx, edi)
	ROUND(14, 1, eax, ecx, edi, edx)
	ROUND(15, 1, ecx, eax, edx, edi)
	AS2(	cmp		WORD_REG(si), K_END)
	ATT_NOPREFIX
	ASJ(	jb,		1, b)
	INTEL_NOPREFIX

	AS2(	mov		WORD_REG(dx), DATA_SAVE)
	AS2(	add		WORD_REG(dx), 64)
	AS2(	mov		AS_REG_7, STATE_SAVE)
	AS2(	mov		DATA_SAVE, WORD_REG(dx))

#if CRYPTOPP_BOOL_SSE2_ASM_AVAILABLE
#if CRYPTOPP_BOOL_X86 || CRYPTOPP_BOOL_X32
	AS2(	test	DWORD PTR K_END, 1)
	ASJ(	jz,		4, f)
#endif
	AS2(	movdqu	xmm1, XMMWORD_PTR [AS_REG_7+1*16])
	AS2(	movdqu	xmm0, XMMWORD_PTR [AS_REG_7+0*16])
	AS2(	paddd	xmm1, E(0))
	AS2(	paddd	xmm0, A(0))
	AS2(	movdqu	[AS_REG_7+1*16], xmm1)
	AS2(	movdqu	[AS_REG_7+0*16], xmm0)
	AS2(	cmp		WORD_REG(dx), DATA_END)
	ATT_NOPREFIX
	ASJ(	jb,		0, b)
	INTEL_NOPREFIX
#endif

#if CRYPTOPP_BOOL_X86 || CRYPTOPP_BOOL_X32
#if CRYPTOPP_BOOL_SSE2_ASM_AVAILABLE
	ASJ(	jmp,	5, f)
	ASL(4)	// non-SSE2
#endif
	AS2(	add		[AS_REG_7+0*4], ecx)	// A
	AS2(	add		[AS_REG_7+4*4], edi)	// E
	AS2(	mov		eax, B(0))
	AS2(	mov		ebx, C(0))
	AS2(	mov		ecx, D(0))
	AS2(	add		[AS_REG_7+1*4], eax)
	AS2(	add		[AS_REG_7+2*4], ebx)
	AS2(	add		[AS_REG_7+3*4], ecx)
	AS2(	mov		eax, F(0))
	AS2(	mov		ebx, G(0))
	AS2(	mov		ecx, H(0))
	AS2(	add		[AS_REG_7+5*4], eax)
	AS2(	add		[AS_REG_7+6*4], ebx)
	AS2(	add		[AS_REG_7+7*4], ecx)
	AS2(	mov		ecx, AS_REG_7d)
	AS2(	cmp		WORD_REG(dx), DATA_END)
	ASJ(	jb,		2, b)
#if CRYPTOPP_BOOL_SSE2_ASM_AVAILABLE
	ASL(5)
#endif
#endif

	AS_POP_IF86(sp)
	AS_POP_IF86(bp)
	#if !defined(_MSC_VER) || (_MSC_VER < 1400)
		AS_POP_IF86(bx)
	#endif

#ifdef __GNUC__
	ATT_PREFIX
	:
	: "c" (state), "d" (data), "S" (SHA256_K+48), "D" (len)
	#if CRYPTOPP_BOOL_X64
		, "m" (workspace[0])
	#endif
	: "memory", "cc", "%eax"
	#if CRYPTOPP_BOOL_X64
		, "%rbx", "%r8", "%r10"
	#endif
	);
#endif
}

#endif	// (defined(CRYPTOPP_X86_ASM_AVAILABLE))

#undef sum0
#undef sum1
#undef sigma0
#undef sigma1

#define sum0(x)		(rotr32((x), 2) ^ rotr32((x), 13) ^ rotr32((x), 22))
#define sum1(x)		(rotr32((x), 6) ^ rotr32((x), 11) ^ rotr32((x), 25))
#define sigma0(x)	(rotr32((x), 7) ^ rotr32((x), 18) ^ ((x) >> 3))
#define sigma1(x)	(rotr32((x), 17) ^ rotr32((x), 19) ^ ((x) >> 10))


typedef void (*sha256transformFn)(sha256_ctx* ctx, void* m, uint_64t num_blks);

sha256transformFn sha256transfunc = NULL;

void StdSha256Transform(sha256_ctx* ctx, void* mp, uint_64t num_blks)
{
	uint_64t blk;
	for (blk = 0; blk < num_blks; blk++)
	{
		uint_32t W[16];
		uint_32t a,b,c,d,e,f,g,h;
		uint_32t T1, T2;
		int i;
#if defined (TC_WINDOWS_DRIVER) && defined (DEBUG)
		int	  j;
#endif

		for (i = 0; i < 64 / 4; i++)
		{
			W[i] = bswap_32((((const uint_32t*)(mp))[blk * 16 + i]));
		}

		a = ctx->hash[0];
		b = ctx->hash[1];
		c = ctx->hash[2];
		d = ctx->hash[3];
		e = ctx->hash[4];
		f = ctx->hash[5];
		g = ctx->hash[6];
		h = ctx->hash[7];

		for (i = 0; i <= 63; i+=16)
		{
#if defined (TC_WINDOWS_DRIVER) && defined (DEBUG)
			for (j = 0; j < 16; j++)
			{
				COMPRESS_ROUND(i, j, SHA256_K);
			}
#else
			COMPRESS_ROUND(i, 0, SHA256_K);
			COMPRESS_ROUND(i, 1, SHA256_K);
			COMPRESS_ROUND(i , 2, SHA256_K);
			COMPRESS_ROUND(i, 3, SHA256_K);
			COMPRESS_ROUND(i, 4, SHA256_K);
			COMPRESS_ROUND(i, 5, SHA256_K);
			COMPRESS_ROUND(i, 6, SHA256_K);
			COMPRESS_ROUND(i, 7, SHA256_K);
			COMPRESS_ROUND(i, 8, SHA256_K);
			COMPRESS_ROUND(i, 9, SHA256_K);
			COMPRESS_ROUND(i, 10, SHA256_K);
			COMPRESS_ROUND(i, 11, SHA256_K);
			COMPRESS_ROUND(i, 12, SHA256_K);
			COMPRESS_ROUND(i, 13, SHA256_K);
			COMPRESS_ROUND(i, 14, SHA256_K);
			COMPRESS_ROUND(i, 15, SHA256_K);
#endif
		}
		ctx->hash[0] += a;
		ctx->hash[1] += b;
		ctx->hash[2] += c;
		ctx->hash[3] += d;
		ctx->hash[4] += e;
		ctx->hash[5] += f;
		ctx->hash[6] += g;
		ctx->hash[7] += h;
	}
}

#ifndef NO_OPTIMIZED_VERSIONS

#if CRYPTOPP_BOOL_X64
void Avx2Sha256Transform(sha256_ctx* ctx, void* mp, uint_64t num_blks)
{
	if (num_blks > 1)
		sha256_rorx(mp, ctx->hash, num_blks);
	else
		sha256_sse4(mp, ctx->hash, num_blks);
}

void AvxSha256Transform(sha256_ctx* ctx, void* mp, uint_64t num_blks)
{
	if (num_blks > 1)
		sha256_avx(mp, ctx->hash, num_blks);
	else
		sha256_sse4(mp, ctx->hash, num_blks);
}

void SSE4Sha256Transform(sha256_ctx* ctx, void* mp, uint_64t num_blks)
{
	sha256_sse4(mp, ctx->hash, num_blks);
}

#endif

#if (defined(CRYPTOPP_X86_ASM_AVAILABLE) || defined(CRYPTOPP_X32_ASM_AVAILABLE))
void SSE2Sha256Transform(sha256_ctx* ctx, void* mp, uint_64t num_blks)
{
	X86_SHA256_HashBlocks(ctx->hash, (const uint_32t*)mp, (size_t)(num_blks * 64));
}
#endif

#if CRYPTOPP_BOOL_X86 || CRYPTOPP_BOOL_X32
void Sha256AsmTransform(sha256_ctx* ctx, void* mp, uint_64t num_blks)
{
	uint_64t i;
	for (i = 0; i < num_blks; i++)
		sha256_compress_nayuki(ctx->hash, (uint_8t*)mp + i * 64);
}
#endif

#endif

void sha256_begin(sha256_ctx* ctx)
{
	ctx->hash[0] = 0x6a09e667;
	ctx->hash[1] = 0xbb67ae85;
	ctx->hash[2] = 0x3c6ef372;
	ctx->hash[3] = 0xa54ff53a;
	ctx->hash[4] = 0x510e527f;
	ctx->hash[5] = 0x9b05688c;
	ctx->hash[6] = 0x1f83d9ab;
	ctx->hash[7] = 0x5be0cd19;
	ctx->count[0] = 0;
	ctx->count[1] = 0;

	if (!sha256transfunc)
	{
#ifndef NO_OPTIMIZED_VERSIONS
#ifdef _M_X64
		if (g_isIntel && HasSAVX2() && HasSBMI2())
			sha256transfunc = Avx2Sha256Transform;
		else if (g_isIntel && HasSAVX())
				sha256transfunc = AvxSha256Transform;
		else if (HasSSE41())
				sha256transfunc = SSE4Sha256Transform;
		else
#endif

#if (defined(CRYPTOPP_X86_ASM_AVAILABLE) || defined(CRYPTOPP_X32_ASM_AVAILABLE))
		if (HasSSE2 ())
			sha256transfunc = SSE2Sha256Transform;
		else
#endif

#if CRYPTOPP_BOOL_X86 || CRYPTOPP_BOOL_X32
			sha256transfunc = Sha256AsmTransform;
#else
			sha256transfunc = StdSha256Transform;
#endif
#else
		sha256transfunc = StdSha256Transform;
#endif
	}
}

void sha256_end(unsigned char * result, sha256_ctx* ctx)
{
	int i;
	uint_64t mlen, pos = ctx->count[0];
	uint_8t* m = (uint_8t*) ctx->wbuf;
	m[pos++] = 0x80;
	if (pos > 56)
	{
		memset(m + pos, 0, (size_t) (64 - pos));
		sha256transfunc(ctx, m, 1);
		pos = 0;
	}
	memset(m + pos, 0, (size_t) (56 - pos));
	mlen = bswap_64((uint_64t) ctx->count[1]);
	memcpy(m + (64 - 8), &mlen, 64 / 8);
	sha256transfunc(ctx, m, 1);
	for (i = 0; i < 8; i++)
	{
		ctx->hash[i] = bswap_32(ctx->hash[i]);
	}
	memcpy(result, ctx->hash, 32);
}

void sha256_hash(const unsigned char * data, uint_32t len, sha256_ctx *ctx)
{
	uint_32t pos = ctx->count[0];
	uint_32t total = ctx->count[1];
	uint_8t* m = (uint_8t*) ctx->wbuf;
	if (pos && pos + len >= 64)
	{
		memcpy(m + pos, data, 64 - pos);
		sha256transfunc(ctx, m, 1);
		len -= 64 - pos;
		total += (64 - pos) * 8;
		data += 64 - pos;
		pos = 0;
	}
	if (len >= 64)
	{
		uint_32t blocks = len / 64;
		uint_32t bytes = blocks * 64;
		sha256transfunc(ctx, (void*)data, blocks);
		len -= bytes;
		total += (bytes)* 8;
		data += bytes;
	}
	memcpy(m+pos, data, len);
	pos += len;
	total += len * 8;
	ctx->count[0] = pos;
	ctx->count[1] = total;
}

void sha256(unsigned char * result, const unsigned char* source, uint_32t sourceLen)
{
	sha256_ctx  ctx;

	sha256_begin(&ctx);
	sha256_hash(source, sourceLen, &ctx);
	sha256_end(result, &ctx);
}
