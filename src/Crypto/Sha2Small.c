/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 *
 * Tom St Denis, tomstdenis@gmail.com, http://libtom.org
 *
 */

/* Adapted for VeraCrypt */

#include <memory.h>
#include "Common/Tcdefs.h"
#include "Common/Endian.h"
#include "Sha2Small.h"

#pragma optimize ("tl", on)

typedef unsigned __int32 uint32;
typedef unsigned __int8 byte;

#include <stdlib.h>
#pragma intrinsic(_lrotr)
#define RORc(x,n) _lrotr(x,n)

/******************************************************************************/

/*
	The K array
 */

static const uint32 K[64] = {
	0x428a2f98UL, 0x71374491UL, 0xb5c0fbcfUL, 0xe9b5dba5UL, 0x3956c25bUL,
	0x59f111f1UL, 0x923f82a4UL, 0xab1c5ed5UL, 0xd807aa98UL, 0x12835b01UL,
	0x243185beUL, 0x550c7dc3UL, 0x72be5d74UL, 0x80deb1feUL, 0x9bdc06a7UL,
	0xc19bf174UL, 0xe49b69c1UL, 0xefbe4786UL, 0x0fc19dc6UL, 0x240ca1ccUL,
	0x2de92c6fUL, 0x4a7484aaUL, 0x5cb0a9dcUL, 0x76f988daUL, 0x983e5152UL,
	0xa831c66dUL, 0xb00327c8UL, 0xbf597fc7UL, 0xc6e00bf3UL, 0xd5a79147UL,
	0x06ca6351UL, 0x14292967UL, 0x27b70a85UL, 0x2e1b2138UL, 0x4d2c6dfcUL,
	0x53380d13UL, 0x650a7354UL, 0x766a0abbUL, 0x81c2c92eUL, 0x92722c85UL,
	0xa2bfe8a1UL, 0xa81a664bUL, 0xc24b8b70UL, 0xc76c51a3UL, 0xd192e819UL,
	0xd6990624UL, 0xf40e3585UL, 0x106aa070UL, 0x19a4c116UL, 0x1e376c08UL,
	0x2748774cUL, 0x34b0bcb5UL, 0x391c0cb3UL, 0x4ed8aa4aUL, 0x5b9cca4fUL,
	0x682e6ff3UL, 0x748f82eeUL, 0x78a5636fUL, 0x84c87814UL, 0x8cc70208UL,
	0x90befffaUL, 0xa4506cebUL, 0xbef9a3f7UL, 0xc67178f2UL
};

/*
	Various logical functions
 */
#define Ch(x,y,z)			(z ^ (x & (y ^ z)))
#define Maj(x,y,z)		(((x | y) & z) | (x & y)) 
#define S(x, n)			RORc((x),(n))
#define R(x, n)			((x)>>(n))
#define Sigma0(x)			(S(x, 2) ^ S(x, 13) ^ S(x, 22))
#define Sigma1(x)			(S(x, 6) ^ S(x, 11) ^ S(x, 25))
#define Gamma0(x)			(S(x, 7) ^ S(x, 18) ^ R(x, 3))
#define Gamma1(x)			(S(x, 17) ^ S(x, 19) ^ R(x, 10))

#define STORE32H(x, y, i) { \
(y)[i] = (unsigned char)(((x)>>24)); \
(y)[i+1] = (unsigned char)(((x)>>16)); \
(y)[i+2] = (unsigned char)(((x)>>8)); \
(y)[i+3] = (unsigned char)((x)); \
}

#define LOAD32H(x, y, i) { \
x = ((unsigned long)((y)[i])<<24) | \
((unsigned long)((y)[i+1])<<16) | \
((unsigned long)((y)[i+2])<<8)  | \
((unsigned long)((y)[i+3])); \
}

/*
	compress 512-bits
 */
static void sha256_compress(sha256_ctx * ctx, unsigned char *buf)
{

	uint32 S[8], W[64], t0, t1;
	uint32 t, w2, w15;
	int i;

/*
	copy state into S
 */
	for (i = 0; i < 8; i++) {
		S[i] = ctx->state[i];
	}

/*
	copy the state into 512-bits into W[0..15]
 */
	for (i = 0; i < 16; i++) {
		LOAD32H(W[i], buf , (4*i));
	}

/*
	fill W[16..63]
 */
	for (i = 16; i < 64; i++) {
		w2 = W[i - 2];
		w15 = W[i - 15];
		W[i] = Gamma1(w2) + W[i - 7] + Gamma0(w15) + W[i - 16];
	}

/*
	Compress
 */

#define RND(a,b,c,d,e,f,g,h,i)							\
	t0 = h + Sigma1(e) + Ch(e, f, g) + K[i] + W[i];	\
	t1 = Sigma0(a) + Maj(a, b, c);						\
	d += t0;											\
	h  = t0 + t1;

	for (i = 0; i < 64; ++i) {
		RND(S[0],S[1],S[2],S[3],S[4],S[5],S[6],S[7],i);
		t = S[7]; S[7] = S[6]; S[6] = S[5]; S[5] = S[4]; 
		S[4] = S[3]; S[3] = S[2]; S[2] = S[1]; S[1] = S[0]; S[0] = t;
	}

/*
	feedback
 */
	for (i = 0; i < 8; i++) {
		ctx->state[i] += S[i];
	}

}

/*
	init the sha256 state
 */
VOID_RETURN sha256_begin(sha256_ctx* ctx)
{
	ctx->curlen = 0;
	ctx->state[0] = 0x6A09E667UL;
	ctx->state[1] = 0xBB67AE85UL;
	ctx->state[2] = 0x3C6EF372UL;
	ctx->state[3] = 0xA54FF53AUL;
	ctx->state[4] = 0x510E527FUL;
	ctx->state[5] = 0x9B05688CUL;
	ctx->state[6] = 0x1F83D9ABUL;
	ctx->state[7] = 0x5BE0CD19UL;
	ctx->highLength = 0;
	ctx->lowLength = 0;
}

VOID_RETURN sha256_hash(unsigned char* data, unsigned int len, sha256_ctx* ctx)
{
	uint32 n;
	while (len > 0) {
		if (ctx->curlen == 0 && len >= 64) {			
			sha256_compress(ctx, (unsigned char *)data);

			n = ctx->lowLength + 512;
			if (n < ctx->lowLength) {
				ctx->highLength++;
			}
			ctx->lowLength = n;
			data		+= 64;
			len		-= 64;
		} else {
			n = min(len, 64 - ctx->curlen);
			memcpy(ctx->buf + ctx->curlen, data, (size_t)n);
			ctx->curlen	+= (unsigned int) n;
			data			+= (unsigned int) n;
			len			-= (unsigned int) n;

			if (ctx->curlen == 64) {
				sha256_compress (ctx, ctx->buf);

				n = ctx->lowLength + 512;
				if (n < ctx->lowLength) {
					ctx->highLength++;
				}
				ctx->lowLength = n;		
				ctx->curlen	= 0;
			}
		}
	}
	return;
}

VOID_RETURN sha256_end(unsigned char* hval, sha256_ctx* ctx)
{
	int i;
	uint32	n;

/*
	increase the length of the message
 */

	n = ctx->lowLength + (ctx->curlen << 3);
	if (n < ctx->lowLength) {
		ctx->highLength++;
	}
	ctx->highLength += (ctx->curlen >> 29);
	ctx->lowLength = n;

/*
	append the '1' bit
 */
	ctx->buf[ctx->curlen++] = (unsigned char)0x80;

/*
	if the length is currently above 56 bytes we append zeros then compress.
	Then we can fall back to padding zeros and length encoding like normal.
 */
	if (ctx->curlen > 56) {
		while (ctx->curlen < 64) {
			ctx->buf[ctx->curlen++] = (unsigned char)0;
		}
		sha256_compress(ctx, ctx->buf);
		ctx->curlen = 0;
	}

/*
	pad upto 56 bytes of zeroes
 */
	while (ctx->curlen < 56) {
		ctx->buf[ctx->curlen++] = (unsigned char)0;
	}

/*
	store length
 */

	STORE32H(ctx->highLength, ctx->buf, 56);
	STORE32H(ctx->lowLength, ctx->buf, 60);
	
	sha256_compress(ctx, ctx->buf);

/*
	copy output
 */
	for (i = 0; i < 8; i++) {
		STORE32H(ctx->state[i], hval, (4*i));
	}
}

/******************************************************************************/
