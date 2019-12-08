/*
 * Copyright (c) 2013-2017 IDRIX
 * Governed by the Apache License 2.0 the full text of which is contained
 * in the file License.txt included in VeraCrypt binary and source
 * code distribution packages.
 */

#ifndef _SHA2_H
#define _SHA2_H

#include "Common/Tcdefs.h"
#include "Common/Endian.h"
#include "Crypto/config.h"

#if defined(__cplusplus)
extern "C" {
#endif

#define SHA256_DIGEST_SIZE  32
#define SHA256_BLOCK_SIZE   64

#define SHA512_DIGEST_SIZE  64
#define SHA512_BLOCK_SIZE  128

#if CRYPTOPP_BOOL_X64 && !defined(CRYPTOPP_DISABLE_ASM)
#define SHA2_ALIGN	CRYPTOPP_ALIGN_DATA(32)
#else
#define SHA2_ALIGN	CRYPTOPP_ALIGN_DATA(16)
#endif

typedef struct
{   uint_64t count[2];
    SHA2_ALIGN uint_64t hash[8];
    SHA2_ALIGN uint_64t wbuf[16];
} sha512_ctx;

typedef struct
{   uint_32t count[2];
    SHA2_ALIGN uint_32t hash[8];
    SHA2_ALIGN uint_32t wbuf[16];
} sha256_ctx;


void sha512_begin(sha512_ctx* ctx);
void sha512_hash(const unsigned char * source, uint_64t sourceLen, sha512_ctx *ctx);
void sha512_end(unsigned char * result, sha512_ctx* ctx);
void sha512(unsigned char * result, const unsigned char* source, uint_64t sourceLen);

void sha256_begin(sha256_ctx* ctx);
void sha256_hash(const unsigned char * source, uint_32t sourceLen, sha256_ctx *ctx);
void sha256_end(unsigned char * result, sha256_ctx* ctx);
void sha256(unsigned char * result, const unsigned char* source, uint_32t sourceLen);

#if defined(__cplusplus)
}
#endif



#endif
