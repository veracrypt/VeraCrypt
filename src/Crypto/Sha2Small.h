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

#ifndef _SHA2_SMALL_H
#define _SHA2_SMALL_H

#include "Common/Tcdefs.h"
#include "Common/Endian.h"

#define SHA256_DIGEST_SIZE  32
#define SHA256_BLOCK_SIZE   64

#define VOID_RETURN	void
#define INT_RETURN	int

#if defined(__cplusplus)
extern "C"
{
#endif

typedef struct {

	uint32		highLength;
	uint32		lowLength;
	uint32		state[8];
	unsigned int curlen;
	unsigned char buf[64];
} sha256_ctx;

/******************************************************************************/

VOID_RETURN sha256_begin(sha256_ctx* ctx);
VOID_RETURN sha256_hash(unsigned char* data, unsigned int len, sha256_ctx* ctx);
VOID_RETURN sha256_end(unsigned char* hval, sha256_ctx* ctx);

#if defined(__cplusplus)
}
#endif

/******************************************************************************/

#endif /* _h_PS_DIGEST */
/******************************************************************************/

