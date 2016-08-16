
/*
* Copyright (c) 2013, Alexey Degtyarev.
* All rights reserved.
*/

/* Adapted to VeraCrypt */

#ifndef STREEBOG_H
#define STREEBOG_H

#include "Common/Tcdefs.h"
#include "config.h"

#define ALIGN(a)	CRYPTOPP_ALIGN_DATA(a)

typedef ALIGN(16) struct _STREEBOG_CTX
{
	ALIGN(16) unsigned char buffer[64];
	ALIGN(16) unsigned long long hash[8];
	ALIGN(16) unsigned long long h[8];
	ALIGN(16) unsigned long long N[8];
	ALIGN(16) unsigned long long Sigma[8];
	size_t bufsize;
	unsigned int digest_size;
} STREEBOG_CTX;

void STREEBOG_init(STREEBOG_CTX *ctx);
void STREEBOG_init256(STREEBOG_CTX *ctx);
void STREEBOG_add(STREEBOG_CTX *ctx, const byte *msg, size_t len);
void STREEBOG_finalize(STREEBOG_CTX *ctx, byte *out);

#endif
