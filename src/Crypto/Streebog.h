
/*
* Copyright (c) 2013, Alexey Degtyarev.
* All rights reserved.
*/

/* Adapted to VeraCrypt */

#ifndef STREEBOG_H
#define STREEBOG_H

#include "Common/Tcdefs.h"
#include "config.h"

#ifdef __cplusplus
extern "C" {
#endif

#define STREEBOG_ALIGN(a)	CRYPTOPP_ALIGN_DATA(a)

typedef STREEBOG_ALIGN(16) struct _STREEBOG_CTX
{
	STREEBOG_ALIGN(16) unsigned char buffer[64];
	STREEBOG_ALIGN(16) unsigned long long hash[8];
	STREEBOG_ALIGN(16) unsigned long long h[8];
	STREEBOG_ALIGN(16) unsigned long long N[8];
	STREEBOG_ALIGN(16) unsigned long long Sigma[8];
	size_t bufsize;
	unsigned int digest_size;
} STREEBOG_CTX;

void STREEBOG_init(STREEBOG_CTX *ctx);
void STREEBOG_init256(STREEBOG_CTX *ctx);
void STREEBOG_add(STREEBOG_CTX *ctx, const uint8 *msg, size_t len);
void STREEBOG_finalize(STREEBOG_CTX *ctx, uint8 *out);

#ifdef __cplusplus
}
#endif

#endif
