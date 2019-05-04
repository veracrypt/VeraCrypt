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

#include "chachaRng.h"
#include "cpu.h"
#include "misc.h"
#include <string.h>

static VC_INLINE void ChaCha20RngReKey (ChaCha20RngCtx* pCtx, int useCallBack)
{
	/* fill rs_buf with the keystream */
	if (pCtx->m_rs_have)
		memset(pCtx->m_rs_buf + sizeof(pCtx->m_rs_buf) - pCtx->m_rs_have, 0, pCtx->m_rs_have);
	ChaCha256Encrypt(&pCtx->m_chachaCtx, pCtx->m_rs_buf, sizeof (pCtx->m_rs_buf),
	    pCtx->m_rs_buf);
	/* mix in optional user provided data */
	if (pCtx->m_getRandSeedCallback && useCallBack) {
		unsigned char dat[CHACHA20RNG_KEYSZ + CHACHA20RNG_IVSZ];
		size_t i;

		pCtx->m_getRandSeedCallback (dat, sizeof (dat));

		for (i = 0; i < (CHACHA20RNG_KEYSZ + CHACHA20RNG_IVSZ); i++)
			pCtx->m_rs_buf[i] ^= dat[i];

		burn (dat, sizeof(dat));
	}

	/* immediately reinit for backtracking resistance */
	ChaCha256Init (&pCtx->m_chachaCtx, pCtx->m_rs_buf, pCtx->m_rs_buf + CHACHA20RNG_KEYSZ, 20);
	memset(pCtx->m_rs_buf, 0, CHACHA20RNG_KEYSZ + CHACHA20RNG_IVSZ);
	pCtx->m_rs_have = sizeof (pCtx->m_rs_buf) - CHACHA20RNG_KEYSZ - CHACHA20RNG_IVSZ;
}

static VC_INLINE void ChaCha20RngStir(ChaCha20RngCtx* pCtx)
{
	ChaCha20RngReKey (pCtx, 1);

	/* invalidate rs_buf */
	pCtx->m_rs_have = 0;
	memset(pCtx->m_rs_buf, 0, CHACHA20RNG_RSBUFSZ);

	pCtx->m_rs_count = 1600000;
}

static VC_INLINE void ChaCha20RngStirIfNeeded(ChaCha20RngCtx* pCtx, size_t len)
{
	if (pCtx->m_rs_count <= len) {
		ChaCha20RngStir(pCtx);
	} else
		pCtx->m_rs_count -= len;
}

void ChaCha20RngInit (ChaCha20RngCtx* pCtx, const unsigned char* key, GetRandSeedFn rngSeedCallback, size_t InitialBytesToSkip)
{
	ChaCha256Init (&pCtx->m_chachaCtx, key, key + 32, 20);
	pCtx->m_getRandSeedCallback = rngSeedCallback;

	/* fill rs_buf with the keystream */
	pCtx->m_rs_have = 0;
	memset (pCtx->m_rs_buf, 0, sizeof (pCtx->m_rs_buf));
	pCtx->m_rs_count = 1600000;

	ChaCha20RngReKey(pCtx, 0);	

	if (InitialBytesToSkip)
		ChaCha20RngGetBytes (pCtx, NULL, InitialBytesToSkip);
}

void ChaCha20RngGetBytes (ChaCha20RngCtx* pCtx, unsigned char* buffer, size_t bufferLen)
{
	unsigned char *buf = (unsigned char*) buffer;
	unsigned char* keystream;
	size_t m;

	ChaCha20RngStirIfNeeded(pCtx, bufferLen);

	while (bufferLen > 0) {
		if (pCtx->m_rs_have > 0) {
			m = VC_MIN(bufferLen, pCtx->m_rs_have);
			keystream = pCtx->m_rs_buf + sizeof(pCtx->m_rs_buf) - pCtx->m_rs_have;
			if (buf)
			{
				memcpy(buf, keystream, m);
				buf += m;
			}
			memset(keystream, 0, m);
			bufferLen -= m;
			pCtx->m_rs_have -= m;
		}
		if (pCtx->m_rs_have == 0)
			ChaCha20RngReKey (pCtx, 0);
	}
}
