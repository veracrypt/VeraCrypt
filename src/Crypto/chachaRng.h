/*	$OpenBSD: arc4random.c,v 1.54 2015/09/13 08:31:47 guenther Exp $	*/

/*
 * Copyright (c) 1996, David Mazieres <dm@uun.org>
 * Copyright (c) 2008, Damien Miller <djm@openbsd.org>
 * Copyright (c) 2013, Markus Friedl <markus@openbsd.org>
 * Copyright (c) 2014, Theo de Raadt <deraadt@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/*
 * ChaCha based random number generator for OpenBSD.
 */

/*
 * Adapted for VeraCrypt
 */

#ifndef HEADER_Crypto_ChaChaRng
#define HEADER_Crypto_ChaChaRng

#include "chacha256.h"

#define CHACHA20RNG_KEYSZ	32
#define CHACHA20RNG_IVSZ	8
#define CHACHA20RNG_BLOCKSZ	64
#define CHACHA20RNG_RSBUFSZ	(16*CHACHA20RNG_BLOCKSZ)

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*GetRandSeedFn)(unsigned char* pbRandSeed, size_t cbRandSeed);

typedef struct
{
	ChaCha256Ctx m_chachaCtx; /* ChaCha20 context */
	unsigned char m_rs_buf[CHACHA20RNG_RSBUFSZ];	/* keystream blocks */
	size_t m_rs_have;	/* valid bytes at end of rs_buf */
	size_t m_rs_count; /* bytes till reseed */
	GetRandSeedFn m_getRandSeedCallback;
} ChaCha20RngCtx;

/*  key length must be equal to 40 bytes (CHACHA20RNG_KEYSZ + CHACHA20RNG_IVSZ) */
void ChaCha20RngInit (ChaCha20RngCtx* pCtx, const unsigned char* key, GetRandSeedFn rngCallback, size_t InitialBytesToSkip);
void ChaCha20RngGetBytes (ChaCha20RngCtx* pCtx, unsigned char* buffer, size_t bufferLen);

#ifdef __cplusplus
}
#endif

#endif
