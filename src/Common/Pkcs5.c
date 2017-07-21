/*
 Legal Notice: Some portions of the source code contained in this file were
 derived from the source code of TrueCrypt 7.1a, which is 
 Copyright (c) 2003-2012 TrueCrypt Developers Association and which is 
 governed by the TrueCrypt License 3.0, also from the source code of
 Encryption for the Masses 2.02a, which is Copyright (c) 1998-2000 Paul Le Roux
 and which is governed by the 'License Agreement for Encryption for the Masses' 
 Modifications and additions to the original source code (contained in this file) 
 and all other portions of this file are Copyright (c) 2013-2017 IDRIX
 and are governed by the Apache License 2.0 the full text of which is
 contained in the file License.txt included in VeraCrypt binary and source
 code distribution packages. */

#include "Tcdefs.h"
#if !defined(_UEFI)
#include <memory.h>
#include <stdlib.h>
#endif
#include "Rmd160.h"
#ifndef TC_WINDOWS_BOOT
#include "Sha2.h"
#include "Whirlpool.h"
#include "cpu.h"
#include "misc.h"
#else
#pragma optimize ("t", on)
#include <string.h>
#if defined( _MSC_VER )
#  ifndef DEBUG
#    pragma intrinsic( memcpy )
#    pragma intrinsic( memset )
#  endif
#endif
#include "Sha2Small.h"
#endif
#include "Pkcs5.h"
#include "Crypto.h"

#if !defined(TC_WINDOWS_BOOT) || defined(TC_WINDOWS_BOOT_SHA2)

typedef struct hmac_sha256_ctx_struct
{
	sha256_ctx ctx;
	sha256_ctx inner_digest_ctx; /*pre-computed inner digest context */
	sha256_ctx outer_digest_ctx; /*pre-computed outer digest context */
	char k[PKCS5_SALT_SIZE + 4]; /* enough to hold (salt_len + 4) and also the SHA256 hash */
	char u[SHA256_DIGESTSIZE];
} hmac_sha256_ctx;

void hmac_sha256_internal
(
	  char *d,		/* input data. d pointer is guaranteed to be at least 32-bytes long */
	  int ld,		/* length of input data in bytes */
	  hmac_sha256_ctx* hmac /* HMAC-SHA256 context which holds temporary variables */
)
{
	sha256_ctx* ctx = &(hmac->ctx);

	/**** Restore Precomputed Inner Digest Context ****/

	memcpy (ctx, &(hmac->inner_digest_ctx), sizeof (sha256_ctx));

	sha256_hash ((unsigned char *) d, ld, ctx);

	sha256_end ((unsigned char *) d, ctx); /* d = inner digest */

	/**** Restore Precomputed Outer Digest Context ****/

	memcpy (ctx, &(hmac->outer_digest_ctx), sizeof (sha256_ctx));

	sha256_hash ((unsigned char *) d, SHA256_DIGESTSIZE, ctx);

	sha256_end ((unsigned char *) d, ctx); /* d = outer digest */
}

#ifndef TC_WINDOWS_BOOT
void hmac_sha256
(
	char *k,    /* secret key */
	int lk,    /* length of the key in bytes */
	char *d,    /* data */
	int ld    /* length of data in bytes */
)
{
	hmac_sha256_ctx hmac;
	sha256_ctx* ctx;
	char* buf = hmac.k;
	int b;
	char key[SHA256_DIGESTSIZE];
#if defined (DEVICE_DRIVER)
	NTSTATUS saveStatus = STATUS_INVALID_PARAMETER;
#ifdef _WIN64
	XSTATE_SAVE SaveState;
	if (g_isIntel && HasSAVX())
		saveStatus = KeSaveExtendedProcessorState(XSTATE_MASK_GSSE, &SaveState);
#else
	KFLOATING_SAVE floatingPointState;	
	if (HasSSE2())
		saveStatus = KeSaveFloatingPointState (&floatingPointState);
#endif
#endif
    /* If the key is longer than the hash algorithm block size,
	   let key = sha256(key), as per HMAC specifications. */
	if (lk > SHA256_BLOCKSIZE)
	{
		sha256_ctx tctx;

		sha256_begin (&tctx);
		sha256_hash ((unsigned char *) k, lk, &tctx);
		sha256_end ((unsigned char *) key, &tctx);

		k = key;
		lk = SHA256_DIGESTSIZE;

		burn (&tctx, sizeof(tctx));		// Prevent leaks
	}

	/**** Precompute HMAC Inner Digest ****/

	ctx = &(hmac.inner_digest_ctx);
	sha256_begin (ctx);

	/* Pad the key for inner digest */
	for (b = 0; b < lk; ++b)
		buf[b] = (char) (k[b] ^ 0x36);
	memset (&buf[lk], 0x36, SHA256_BLOCKSIZE - lk);

	sha256_hash ((unsigned char *) buf, SHA256_BLOCKSIZE, ctx);

	/**** Precompute HMAC Outer Digest ****/

	ctx = &(hmac.outer_digest_ctx);
	sha256_begin (ctx);

	for (b = 0; b < lk; ++b)
		buf[b] = (char) (k[b] ^ 0x5C);
	memset (&buf[lk], 0x5C, SHA256_BLOCKSIZE - lk);

	sha256_hash ((unsigned char *) buf, SHA256_BLOCKSIZE, ctx);

	hmac_sha256_internal(d, ld, &hmac);

#if defined (DEVICE_DRIVER)
	if (NT_SUCCESS (saveStatus))
#ifdef _WIN64
		KeRestoreExtendedProcessorState(&SaveState);
#else
		KeRestoreFloatingPointState (&floatingPointState);
#endif
#endif

	/* Prevent leaks */
	burn(&hmac, sizeof(hmac));
	burn(key, sizeof(key));
}
#endif

static void derive_u_sha256 (char *salt, int salt_len, uint32 iterations, int b, hmac_sha256_ctx* hmac)
{
	char* k = hmac->k;
	char* u = hmac->u;
	uint32 c;
	int i;	

#ifdef TC_WINDOWS_BOOT
	/* In bootloader mode, least significant bit of iterations is a boolean (TRUE for boot derivation mode, FALSE otherwise)
	 * and the most significant 16 bits hold the pim value
	 * This enables us to save code space needed for implementing other features.
	 */
	c = iterations >> 16;
	i = ((int) iterations) & 0x01;
	if (i)
		c = (c == 0)? 200000 : c << 11;
	else
		c = (c == 0)? 500000 : 15000 + c * 1000;
#else
	c = iterations;
#endif

	/* iteration 1 */
	memcpy (k, salt, salt_len);	/* salt */
	
	/* big-endian block number */
#ifdef TC_WINDOWS_BOOT
    /* specific case of 16-bit bootloader: b is a 16-bit integer that is always < 256 */
	memset (&k[salt_len], 0, 3);
	k[salt_len + 3] = (char) b;
#else
    b = bswap_32 (b);
    memcpy (&k[salt_len], &b, 4);
#endif	

	hmac_sha256_internal (k, salt_len + 4, hmac);
	memcpy (u, k, SHA256_DIGESTSIZE);

	/* remaining iterations */
	while (c > 1)
	{
		hmac_sha256_internal (k, SHA256_DIGESTSIZE, hmac);
		for (i = 0; i < SHA256_DIGESTSIZE; i++)
		{
			u[i] ^= k[i];
		}
		c--;
	}
}


void derive_key_sha256 (char *pwd, int pwd_len, char *salt, int salt_len, uint32 iterations, char *dk, int dklen)
{	
	hmac_sha256_ctx hmac;
	sha256_ctx* ctx;
	char* buf = hmac.k;
	int b, l, r;
#ifndef TC_WINDOWS_BOOT
	char key[SHA256_DIGESTSIZE];
#if defined (DEVICE_DRIVER)
	NTSTATUS saveStatus = STATUS_INVALID_PARAMETER;
#ifdef _WIN64
	XSTATE_SAVE SaveState;
	if (g_isIntel && HasSAVX())
		saveStatus = KeSaveExtendedProcessorState(XSTATE_MASK_GSSE, &SaveState);
#else
	KFLOATING_SAVE floatingPointState;	
	if (HasSSE2())
		saveStatus = KeSaveFloatingPointState (&floatingPointState);
#endif
#endif
    /* If the password is longer than the hash algorithm block size,
	   let pwd = sha256(pwd), as per HMAC specifications. */
	if (pwd_len > SHA256_BLOCKSIZE)
	{
		sha256_ctx tctx;

		sha256_begin (&tctx);
		sha256_hash ((unsigned char *) pwd, pwd_len, &tctx);
		sha256_end ((unsigned char *) key, &tctx);

		pwd = key;
		pwd_len = SHA256_DIGESTSIZE;

		burn (&tctx, sizeof(tctx));		// Prevent leaks
	}
#endif

	if (dklen % SHA256_DIGESTSIZE)
	{
		l = 1 + dklen / SHA256_DIGESTSIZE;
	}
	else
	{
		l = dklen / SHA256_DIGESTSIZE;
	}

	r = dklen - (l - 1) * SHA256_DIGESTSIZE;

	/**** Precompute HMAC Inner Digest ****/

	ctx = &(hmac.inner_digest_ctx);
	sha256_begin (ctx);

	/* Pad the key for inner digest */
	for (b = 0; b < pwd_len; ++b)
		buf[b] = (char) (pwd[b] ^ 0x36);
	memset (&buf[pwd_len], 0x36, SHA256_BLOCKSIZE - pwd_len);

	sha256_hash ((unsigned char *) buf, SHA256_BLOCKSIZE, ctx);

	/**** Precompute HMAC Outer Digest ****/

	ctx = &(hmac.outer_digest_ctx);
	sha256_begin (ctx);

	for (b = 0; b < pwd_len; ++b)
		buf[b] = (char) (pwd[b] ^ 0x5C);
	memset (&buf[pwd_len], 0x5C, SHA256_BLOCKSIZE - pwd_len);

	sha256_hash ((unsigned char *) buf, SHA256_BLOCKSIZE, ctx);

	/* first l - 1 blocks */
	for (b = 1; b < l; b++)
	{
		derive_u_sha256 (salt, salt_len, iterations, b, &hmac);
		memcpy (dk, hmac.u, SHA256_DIGESTSIZE);
		dk += SHA256_DIGESTSIZE;
	}

	/* last block */
	derive_u_sha256 (salt, salt_len, iterations, b, &hmac);
	memcpy (dk, hmac.u, r);

#if defined (DEVICE_DRIVER)
	if (NT_SUCCESS (saveStatus))
#ifdef _WIN64
		KeRestoreExtendedProcessorState(&SaveState);
#else
		KeRestoreFloatingPointState (&floatingPointState);
#endif
#endif

	/* Prevent possible leaks. */
	burn (&hmac, sizeof(hmac));
#ifndef TC_WINDOWS_BOOT
	burn (key, sizeof(key));
#endif
}

#endif

#ifndef TC_WINDOWS_BOOT

typedef struct hmac_sha512_ctx_struct
{
	sha512_ctx ctx;
	sha512_ctx inner_digest_ctx; /*pre-computed inner digest context */
	sha512_ctx outer_digest_ctx; /*pre-computed outer digest context */
	char k[SHA512_BLOCKSIZE]; /* enough to hold (salt_len + 4) and also the SHA512 hash */
	char u[SHA512_DIGESTSIZE];
} hmac_sha512_ctx;

void hmac_sha512_internal
(
	  char *d,		/* data and also output buffer of at least 64 bytes */
	  int ld,			/* length of data in bytes */
	  hmac_sha512_ctx* hmac
)
{
	sha512_ctx* ctx = &(hmac->ctx);

	/**** Restore Precomputed Inner Digest Context ****/

	memcpy (ctx, &(hmac->inner_digest_ctx), sizeof (sha512_ctx));

	sha512_hash ((unsigned char *) d, ld, ctx);

	sha512_end ((unsigned char *) d, ctx);

	/**** Restore Precomputed Outer Digest Context ****/

	memcpy (ctx, &(hmac->outer_digest_ctx), sizeof (sha512_ctx));

	sha512_hash ((unsigned char *) d, SHA512_DIGESTSIZE, ctx);

	sha512_end ((unsigned char *) d, ctx);
}

void hmac_sha512
(
	  char *k,		/* secret key */
	  int lk,		/* length of the key in bytes */
	  char *d,		/* data and also output buffer of at least 64 bytes */
	  int ld			/* length of data in bytes */	  
)
{
	hmac_sha512_ctx hmac;
	sha512_ctx* ctx;
	char* buf = hmac.k;
	int b;
	char key[SHA512_DIGESTSIZE];
#if defined (DEVICE_DRIVER)
	NTSTATUS saveStatus = STATUS_INVALID_PARAMETER;
#ifdef _WIN64
	XSTATE_SAVE SaveState;
	if (g_isIntel && HasSAVX())
		saveStatus = KeSaveExtendedProcessorState(XSTATE_MASK_GSSE, &SaveState);
#else
	KFLOATING_SAVE floatingPointState;	
	if (HasSSSE3() && HasMMX())
		saveStatus = KeSaveFloatingPointState (&floatingPointState);
#endif
#endif

    /* If the key is longer than the hash algorithm block size,
	   let key = sha512(key), as per HMAC specifications. */
	if (lk > SHA512_BLOCKSIZE)
	{
		sha512_ctx tctx;

		sha512_begin (&tctx);
		sha512_hash ((unsigned char *) k, lk, &tctx);
		sha512_end ((unsigned char *) key, &tctx);

		k = key;
		lk = SHA512_DIGESTSIZE;

		burn (&tctx, sizeof(tctx));		// Prevent leaks
	}

	/**** Precompute HMAC Inner Digest ****/

	ctx = &(hmac.inner_digest_ctx);
	sha512_begin (ctx);

	/* Pad the key for inner digest */
	for (b = 0; b < lk; ++b)
		buf[b] = (char) (k[b] ^ 0x36);
	memset (&buf[lk], 0x36, SHA512_BLOCKSIZE - lk);

	sha512_hash ((unsigned char *) buf, SHA512_BLOCKSIZE, ctx);

	/**** Precompute HMAC Outer Digest ****/

	ctx = &(hmac.outer_digest_ctx);
	sha512_begin (ctx);

	for (b = 0; b < lk; ++b)
		buf[b] = (char) (k[b] ^ 0x5C);
	memset (&buf[lk], 0x5C, SHA512_BLOCKSIZE - lk);

	sha512_hash ((unsigned char *) buf, SHA512_BLOCKSIZE, ctx);

	hmac_sha512_internal (d, ld, &hmac);

#if defined (DEVICE_DRIVER)
	if (NT_SUCCESS (saveStatus))
#ifdef _WIN64
		KeRestoreExtendedProcessorState(&SaveState);
#else
		KeRestoreFloatingPointState (&floatingPointState);
#endif
#endif

	/* Prevent leaks */
	burn (&hmac, sizeof(hmac));
	burn (key, sizeof(key));
}

static void derive_u_sha512 (char *salt, int salt_len, uint32 iterations, int b, hmac_sha512_ctx* hmac)
{
	char* k = hmac->k;
	char* u = hmac->u;
	uint32 c, i;

	/* iteration 1 */
	memcpy (k, salt, salt_len);	/* salt */
	/* big-endian block number */
    b = bswap_32 (b);
	memcpy (&k[salt_len], &b, 4);

	hmac_sha512_internal (k, salt_len + 4, hmac);
	memcpy (u, k, SHA512_DIGESTSIZE);

	/* remaining iterations */
	for (c = 1; c < iterations; c++)
	{
		hmac_sha512_internal (k, SHA512_DIGESTSIZE, hmac);
		for (i = 0; i < SHA512_DIGESTSIZE; i++)
		{
			u[i] ^= k[i];
		}
	}
}


void derive_key_sha512 (char *pwd, int pwd_len, char *salt, int salt_len, uint32 iterations, char *dk, int dklen)
{
	hmac_sha512_ctx hmac;
	sha512_ctx* ctx;
	char* buf = hmac.k;
	int b, l, r;
	char key[SHA512_DIGESTSIZE];
#if defined (DEVICE_DRIVER)
	NTSTATUS saveStatus = STATUS_INVALID_PARAMETER;
#ifdef _WIN64
	XSTATE_SAVE SaveState;
	if (g_isIntel && HasSAVX())
		saveStatus = KeSaveExtendedProcessorState(XSTATE_MASK_GSSE, &SaveState);
#else
	KFLOATING_SAVE floatingPointState;	
	if (HasSSSE3() && HasMMX())
		saveStatus = KeSaveFloatingPointState (&floatingPointState);
#endif
#endif

    /* If the password is longer than the hash algorithm block size,
	   let pwd = sha512(pwd), as per HMAC specifications. */
	if (pwd_len > SHA512_BLOCKSIZE)
	{
		sha512_ctx tctx;

		sha512_begin (&tctx);
		sha512_hash ((unsigned char *) pwd, pwd_len, &tctx);
		sha512_end ((unsigned char *) key, &tctx);

		pwd = key;
		pwd_len = SHA512_DIGESTSIZE;

		burn (&tctx, sizeof(tctx));		// Prevent leaks
	}

	if (dklen % SHA512_DIGESTSIZE)
	{
		l = 1 + dklen / SHA512_DIGESTSIZE;
	}
	else
	{
		l = dklen / SHA512_DIGESTSIZE;
	}

	r = dklen - (l - 1) * SHA512_DIGESTSIZE;

	/**** Precompute HMAC Inner Digest ****/

	ctx = &(hmac.inner_digest_ctx);
	sha512_begin (ctx);

	/* Pad the key for inner digest */
	for (b = 0; b < pwd_len; ++b)
		buf[b] = (char) (pwd[b] ^ 0x36);
	memset (&buf[pwd_len], 0x36, SHA512_BLOCKSIZE - pwd_len);

	sha512_hash ((unsigned char *) buf, SHA512_BLOCKSIZE, ctx);

	/**** Precompute HMAC Outer Digest ****/

	ctx = &(hmac.outer_digest_ctx);
	sha512_begin (ctx);

	for (b = 0; b < pwd_len; ++b)
		buf[b] = (char) (pwd[b] ^ 0x5C);
	memset (&buf[pwd_len], 0x5C, SHA512_BLOCKSIZE - pwd_len);

	sha512_hash ((unsigned char *) buf, SHA512_BLOCKSIZE, ctx);

	/* first l - 1 blocks */
	for (b = 1; b < l; b++)
	{
		derive_u_sha512 (salt, salt_len, iterations, b, &hmac);
		memcpy (dk, hmac.u, SHA512_DIGESTSIZE);
		dk += SHA512_DIGESTSIZE;
	}

	/* last block */
	derive_u_sha512 (salt, salt_len, iterations, b, &hmac);
	memcpy (dk, hmac.u, r);

#if defined (DEVICE_DRIVER)
	if (NT_SUCCESS (saveStatus))
#ifdef _WIN64
		KeRestoreExtendedProcessorState(&SaveState);
#else
		KeRestoreFloatingPointState (&floatingPointState);
#endif
#endif

	/* Prevent possible leaks. */
	burn (&hmac, sizeof(hmac));
	burn (key, sizeof(key));
}

#endif // TC_WINDOWS_BOOT

#if !defined(TC_WINDOWS_BOOT) || defined(TC_WINDOWS_BOOT_RIPEMD160)

typedef struct hmac_ripemd160_ctx_struct
{
	RMD160_CTX context;
	RMD160_CTX inner_digest_ctx; /*pre-computed inner digest context */
	RMD160_CTX outer_digest_ctx; /*pre-computed outer digest context */
	char k[PKCS5_SALT_SIZE + 4]; /* enough to hold (salt_len + 4) and also the RIPEMD-160 hash */
	char u[RIPEMD160_DIGESTSIZE];
} hmac_ripemd160_ctx;

void hmac_ripemd160_internal (char *input_digest, int len, hmac_ripemd160_ctx* hmac)
{
	RMD160_CTX* context = &(hmac->context);

	/**** Restore Precomputed Inner Digest Context ****/

	memcpy (context, &(hmac->inner_digest_ctx), sizeof (RMD160_CTX));

	RMD160Update(context, (const unsigned char *) input_digest, len); /* then text of datagram */
	RMD160Final((unsigned char *) input_digest, context);         /* finish up 1st pass */

	/**** Restore Precomputed Outer Digest Context ****/

	memcpy (context, &(hmac->outer_digest_ctx), sizeof (RMD160_CTX));

	/* results of 1st hash */
	RMD160Update(context, (const unsigned char *) input_digest, RIPEMD160_DIGESTSIZE);
	RMD160Final((unsigned char *) input_digest, context);         /* finish up 2nd pass */
}

#ifndef TC_WINDOWS_BOOT
void hmac_ripemd160 (char *key, int keylen, char *input_digest, int len)
{
	hmac_ripemd160_ctx hmac;
	RMD160_CTX* ctx;
	unsigned char* k_pad = (unsigned char*) hmac.k;  /* inner/outer padding - key XORd with ipad */
	unsigned char tk[RIPEMD160_DIGESTSIZE];
	int i;

	/* If the key is longer than the hash algorithm block size,
	let key = ripemd160(key), as per HMAC specifications. */
	if (keylen > RIPEMD160_BLOCKSIZE) 
	{
		RMD160_CTX      tctx;

		RMD160Init(&tctx);
		RMD160Update(&tctx, (const unsigned char *) key, keylen);
		RMD160Final(tk, &tctx);

		key = (char *) tk;
		keylen = RIPEMD160_DIGESTSIZE;

		burn (&tctx, sizeof(tctx));	// Prevent leaks
	}   

	/* perform inner RIPEMD-160 */
	ctx = &(hmac.inner_digest_ctx);
	/* start out by storing key in pads */
	memset(k_pad, 0x36, 64);
	/* XOR key with ipad and opad values */
	for (i=0; i<keylen; i++) 
	{
		k_pad[i] ^= key[i];
	}

	RMD160Init(ctx);           /* init context for 1st pass */
	RMD160Update(ctx, k_pad, RIPEMD160_BLOCKSIZE);  /* start with inner pad */

	/* perform outer RIPEMD-160 */
	ctx = &(hmac.outer_digest_ctx);
	memset(k_pad, 0x5c, 64);
	for (i=0; i<keylen; i++) 
	{
		k_pad[i] ^= key[i];
	}

	RMD160Init(ctx);           /* init context for 2nd pass */
	RMD160Update(ctx, k_pad, RIPEMD160_BLOCKSIZE);  /* start with outer pad */

	hmac_ripemd160_internal (input_digest, len, &hmac);

	burn (&hmac, sizeof(hmac));
	burn (tk, sizeof(tk));
}
#endif


static void derive_u_ripemd160 (char *salt, int salt_len, uint32 iterations, int b, hmac_ripemd160_ctx* hmac)
{
	char* k = hmac->k;
	char* u = hmac->u;
	uint32 c;
	int i;

#ifdef TC_WINDOWS_BOOT
	/* In bootloader mode, least significant bit of iterations is a boolean (TRUE for boot derivation mode, FALSE otherwise)
	 * and the most significant 16 bits hold the pim value
	 * This enables us to save code space needed for implementing other features.
	 */
	c = iterations >> 16;
	i = ((int) iterations) & 0x01;
	if (i)
		c = (c == 0)? 327661 : c << 11;
	else
		c = (c == 0)? 655331 : 15000 + c * 1000;
#else
	c  = iterations;
#endif

	/* iteration 1 */
	memcpy (k, salt, salt_len);	/* salt */
	
	/* big-endian block number */
#ifdef TC_WINDOWS_BOOT
    /* specific case of 16-bit bootloader: b is a 16-bit integer that is always < 256*/
	memset (&k[salt_len], 0, 3);
	k[salt_len + 3] = (char) b;
#else
    b = bswap_32 (b);
    memcpy (&k[salt_len], &b, 4);
#endif	

	hmac_ripemd160_internal (k, salt_len + 4, hmac);
	memcpy (u, k, RIPEMD160_DIGESTSIZE);

	/* remaining iterations */
	while ( c > 1)
	{
		hmac_ripemd160_internal (k, RIPEMD160_DIGESTSIZE, hmac);
		for (i = 0; i < RIPEMD160_DIGESTSIZE; i++)
		{
			u[i] ^= k[i];
		}
		c--;
	}
}

void derive_key_ripemd160 (char *pwd, int pwd_len, char *salt, int salt_len, uint32 iterations, char *dk, int dklen)
{	
	int b, l, r;
	hmac_ripemd160_ctx hmac;
	RMD160_CTX* ctx;
	unsigned char* k_pad = (unsigned char*) hmac.k;
#ifndef TC_WINDOWS_BOOT
	unsigned char tk[RIPEMD160_DIGESTSIZE];
    /* If the password is longer than the hash algorithm block size,
	   let password = ripemd160(password), as per HMAC specifications. */
	if (pwd_len > RIPEMD160_BLOCKSIZE) 
	{
        RMD160_CTX      tctx;

        RMD160Init(&tctx);
        RMD160Update(&tctx, (const unsigned char *) pwd, pwd_len);
        RMD160Final(tk, &tctx);

        pwd = (char *) tk;
        pwd_len = RIPEMD160_DIGESTSIZE;

		burn (&tctx, sizeof(tctx));	// Prevent leaks
    }
#endif

	if (dklen % RIPEMD160_DIGESTSIZE)
	{
		l = 1 + dklen / RIPEMD160_DIGESTSIZE;
	}
	else
	{
		l = dklen / RIPEMD160_DIGESTSIZE;
	}

	r = dklen - (l - 1) * RIPEMD160_DIGESTSIZE;

	/* perform inner RIPEMD-160 */
	ctx = &(hmac.inner_digest_ctx);
	/* start out by storing key in pads */
	memset(k_pad, 0x36, 64);
	/* XOR key with ipad and opad values */
	for (b=0; b<pwd_len; b++) 
	{
		k_pad[b] ^= pwd[b];
	}

	RMD160Init(ctx);           /* init context for 1st pass */
	RMD160Update(ctx, k_pad, RIPEMD160_BLOCKSIZE);  /* start with inner pad */

	/* perform outer RIPEMD-160 */
	ctx = &(hmac.outer_digest_ctx);
	memset(k_pad, 0x5c, 64);
	for (b=0; b<pwd_len; b++) 
	{
		k_pad[b] ^= pwd[b];
	}

	RMD160Init(ctx);           /* init context for 2nd pass */
	RMD160Update(ctx, k_pad, RIPEMD160_BLOCKSIZE);  /* start with outer pad */

	/* first l - 1 blocks */
	for (b = 1; b < l; b++)
	{
		derive_u_ripemd160 (salt, salt_len, iterations, b, &hmac);
		memcpy (dk, hmac.u, RIPEMD160_DIGESTSIZE);
		dk += RIPEMD160_DIGESTSIZE;
	}

	/* last block */
	derive_u_ripemd160 (salt, salt_len, iterations, b, &hmac);
	memcpy (dk, hmac.u, r);


	/* Prevent possible leaks. */
	burn (&hmac, sizeof(hmac));
#ifndef TC_WINDOWS_BOOT
	burn (tk, sizeof(tk));
#endif
}
#endif // TC_WINDOWS_BOOT

#ifndef TC_WINDOWS_BOOT

typedef struct hmac_whirlpool_ctx_struct
{
	WHIRLPOOL_CTX ctx;
	WHIRLPOOL_CTX inner_digest_ctx; /*pre-computed inner digest context */
	WHIRLPOOL_CTX outer_digest_ctx; /*pre-computed outer digest context */
	CRYPTOPP_ALIGN_DATA(16) char k[PKCS5_SALT_SIZE + 4]; /* enough to hold (salt_len + 4) and also the Whirlpool hash */
	char u[WHIRLPOOL_DIGESTSIZE];
} hmac_whirlpool_ctx;

void hmac_whirlpool_internal
(
	  char *d,		/* input/output data. d pointer is guaranteed to be at least 64-bytes long */
	  int ld,		/* length of input data in bytes */
	  hmac_whirlpool_ctx* hmac /* HMAC-Whirlpool context which holds temporary variables */
)
{
	WHIRLPOOL_CTX* ctx = &(hmac->ctx);

	/**** Restore Precomputed Inner Digest Context ****/

	memcpy (ctx, &(hmac->inner_digest_ctx), sizeof (WHIRLPOOL_CTX));

	WHIRLPOOL_add ((unsigned char *) d, ld, ctx);

	WHIRLPOOL_finalize (ctx, (unsigned char *) d);

	/**** Restore Precomputed Outer Digest Context ****/

	memcpy (ctx, &(hmac->outer_digest_ctx), sizeof (WHIRLPOOL_CTX));

	WHIRLPOOL_add ((unsigned char *) d, WHIRLPOOL_DIGESTSIZE, ctx);

	WHIRLPOOL_finalize (ctx, (unsigned char *) d);
}

void hmac_whirlpool
(
	  char *k,		/* secret key */
	  int lk,		/* length of the key in bytes */
	  char *d,		/* input data. d pointer is guaranteed to be at least 32-bytes long */
	  int ld		/* length of data in bytes */
)
{
	hmac_whirlpool_ctx hmac;
	WHIRLPOOL_CTX* ctx;
	char* buf = hmac.k;
	int b;
	char key[WHIRLPOOL_DIGESTSIZE];
#if defined (DEVICE_DRIVER) && !defined (_WIN64)
	KFLOATING_SAVE floatingPointState;
	NTSTATUS saveStatus = STATUS_INVALID_PARAMETER;
	if (HasISSE())
		saveStatus = KeSaveFloatingPointState (&floatingPointState);
#endif
    /* If the key is longer than the hash algorithm block size,
	   let key = whirlpool(key), as per HMAC specifications. */
	if (lk > WHIRLPOOL_BLOCKSIZE)
	{
		WHIRLPOOL_CTX tctx;

		WHIRLPOOL_init (&tctx);
		WHIRLPOOL_add ((unsigned char *) k, lk, &tctx);
		WHIRLPOOL_finalize (&tctx, (unsigned char *) key);

		k = key;
		lk = WHIRLPOOL_DIGESTSIZE;

		burn (&tctx, sizeof(tctx));		// Prevent leaks
	}

	/**** Precompute HMAC Inner Digest ****/

	ctx = &(hmac.inner_digest_ctx);
	WHIRLPOOL_init (ctx);

	/* Pad the key for inner digest */
	for (b = 0; b < lk; ++b)
		buf[b] = (char) (k[b] ^ 0x36);
	memset (&buf[lk], 0x36, WHIRLPOOL_BLOCKSIZE - lk);

	WHIRLPOOL_add ((unsigned char *) buf, WHIRLPOOL_BLOCKSIZE, ctx);

	/**** Precompute HMAC Outer Digest ****/

	ctx = &(hmac.outer_digest_ctx);
	WHIRLPOOL_init (ctx);

	for (b = 0; b < lk; ++b)
		buf[b] = (char) (k[b] ^ 0x5C);
	memset (&buf[lk], 0x5C, WHIRLPOOL_BLOCKSIZE - lk);

	WHIRLPOOL_add ((unsigned char *) buf, WHIRLPOOL_BLOCKSIZE, ctx);

	hmac_whirlpool_internal(d, ld, &hmac);

#if defined (DEVICE_DRIVER) && !defined (_WIN64)
	if (NT_SUCCESS (saveStatus))
		KeRestoreFloatingPointState (&floatingPointState);
#endif
	/* Prevent leaks */
	burn(&hmac, sizeof(hmac));
}

static void derive_u_whirlpool (char *salt, int salt_len, uint32 iterations, int b, hmac_whirlpool_ctx* hmac)
{
	char* u = hmac->u;
	char* k = hmac->k;
	uint32 c, i;

	/* iteration 1 */
	memcpy (k, salt, salt_len);	/* salt */
	/* big-endian block number */
    b = bswap_32 (b);
	memcpy (&k[salt_len], &b, 4);

	hmac_whirlpool_internal (k, salt_len + 4, hmac);
	memcpy (u, k, WHIRLPOOL_DIGESTSIZE);

	/* remaining iterations */
	for (c = 1; c < iterations; c++)
	{
		hmac_whirlpool_internal (k, WHIRLPOOL_DIGESTSIZE, hmac);
		for (i = 0; i < WHIRLPOOL_DIGESTSIZE; i++)
		{
			u[i] ^= k[i];
		}
	}
}

void derive_key_whirlpool (char *pwd, int pwd_len, char *salt, int salt_len, uint32 iterations, char *dk, int dklen)
{
	hmac_whirlpool_ctx hmac;
	WHIRLPOOL_CTX* ctx;
	char* buf = hmac.k;
	char key[WHIRLPOOL_DIGESTSIZE];
	int b, l, r;
#if defined (DEVICE_DRIVER) && !defined (_WIN64)
	KFLOATING_SAVE floatingPointState;
	NTSTATUS saveStatus = STATUS_INVALID_PARAMETER;
	if (HasISSE())
		saveStatus = KeSaveFloatingPointState (&floatingPointState);
#endif
    /* If the password is longer than the hash algorithm block size,
	   let pwd = whirlpool(pwd), as per HMAC specifications. */
	if (pwd_len > WHIRLPOOL_BLOCKSIZE)
	{
		WHIRLPOOL_CTX tctx;

		WHIRLPOOL_init (&tctx);
		WHIRLPOOL_add ((unsigned char *) pwd, pwd_len, &tctx);
		WHIRLPOOL_finalize (&tctx, (unsigned char *) key);

		pwd = key;
		pwd_len = WHIRLPOOL_DIGESTSIZE;

		burn (&tctx, sizeof(tctx));		// Prevent leaks
	}

	if (dklen % WHIRLPOOL_DIGESTSIZE)
	{
		l = 1 + dklen / WHIRLPOOL_DIGESTSIZE;
	}
	else
	{
		l = dklen / WHIRLPOOL_DIGESTSIZE;
	}

	r = dklen - (l - 1) * WHIRLPOOL_DIGESTSIZE;

	/**** Precompute HMAC Inner Digest ****/

	ctx = &(hmac.inner_digest_ctx);
	WHIRLPOOL_init (ctx);

	/* Pad the key for inner digest */
	for (b = 0; b < pwd_len; ++b)
		buf[b] = (char) (pwd[b] ^ 0x36);
	memset (&buf[pwd_len], 0x36, WHIRLPOOL_BLOCKSIZE - pwd_len);

	WHIRLPOOL_add ((unsigned char *) buf, WHIRLPOOL_BLOCKSIZE, ctx);

	/**** Precompute HMAC Outer Digest ****/

	ctx = &(hmac.outer_digest_ctx);
	WHIRLPOOL_init (ctx);

	for (b = 0; b < pwd_len; ++b)
		buf[b] = (char) (pwd[b] ^ 0x5C);
	memset (&buf[pwd_len], 0x5C, WHIRLPOOL_BLOCKSIZE - pwd_len);

	WHIRLPOOL_add ((unsigned char *) buf, WHIRLPOOL_BLOCKSIZE, ctx);

	/* first l - 1 blocks */
	for (b = 1; b < l; b++)
	{
		derive_u_whirlpool (salt, salt_len, iterations, b, &hmac);
		memcpy (dk, hmac.u, WHIRLPOOL_DIGESTSIZE);
		dk += WHIRLPOOL_DIGESTSIZE;
	}

	/* last block */
	derive_u_whirlpool (salt, salt_len, iterations, b, &hmac);
	memcpy (dk, hmac.u, r);

#if defined (DEVICE_DRIVER) && !defined (_WIN64)
	if (NT_SUCCESS (saveStatus))
		KeRestoreFloatingPointState (&floatingPointState);
#endif

	/* Prevent possible leaks. */
	burn (&hmac, sizeof(hmac));
	burn (key, sizeof(key));
}


typedef struct hmac_streebog_ctx_struct
{
	STREEBOG_CTX ctx;
	STREEBOG_CTX inner_digest_ctx; /*pre-computed inner digest context */
	STREEBOG_CTX outer_digest_ctx; /*pre-computed outer digest context */
	CRYPTOPP_ALIGN_DATA(16) char k[PKCS5_SALT_SIZE + 4]; /* enough to hold (salt_len + 4) and also the Streebog hash */
	char u[STREEBOG_DIGESTSIZE];
} hmac_streebog_ctx;

void hmac_streebog_internal
(
	  char *d,		/* input/output data. d pointer is guaranteed to be at least 64-bytes long */
	  int ld,		/* length of input data in bytes */
	  hmac_streebog_ctx* hmac /* HMAC-Whirlpool context which holds temporary variables */
)
{
	STREEBOG_CTX* ctx = &(hmac->ctx);

	/**** Restore Precomputed Inner Digest Context ****/

	memcpy (ctx, &(hmac->inner_digest_ctx), sizeof (STREEBOG_CTX));

	STREEBOG_add (ctx, (unsigned char *) d, ld);

	STREEBOG_finalize (ctx, (unsigned char *) d);

	/**** Restore Precomputed Outer Digest Context ****/

	memcpy (ctx, &(hmac->outer_digest_ctx), sizeof (STREEBOG_CTX));

	STREEBOG_add (ctx, (unsigned char *) d, STREEBOG_DIGESTSIZE);

	STREEBOG_finalize (ctx, (unsigned char *) d);
}

void hmac_streebog
(
	  char *k,		/* secret key */
	  int lk,		/* length of the key in bytes */
	  char *d,		/* input data. d pointer is guaranteed to be at least 32-bytes long */
	  int ld		/* length of data in bytes */
)
{
	hmac_streebog_ctx hmac;
	STREEBOG_CTX* ctx;
	char* buf = hmac.k;
	int b;
	CRYPTOPP_ALIGN_DATA(16) char key[STREEBOG_DIGESTSIZE];
#if defined (DEVICE_DRIVER) && !defined (_WIN64)
	KFLOATING_SAVE floatingPointState;
	NTSTATUS saveStatus = STATUS_INVALID_PARAMETER;
	if (HasSSE2() || HasSSE41())
		saveStatus = KeSaveFloatingPointState (&floatingPointState);
#endif
    /* If the key is longer than the hash algorithm block size,
	   let key = streebog(key), as per HMAC specifications. */
	if (lk > STREEBOG_BLOCKSIZE)
	{
		STREEBOG_CTX tctx;

		STREEBOG_init (&tctx);
		STREEBOG_add (&tctx, (unsigned char *) k, lk);
		STREEBOG_finalize (&tctx, (unsigned char *) key);

		k = key;
		lk = STREEBOG_DIGESTSIZE;

		burn (&tctx, sizeof(tctx));		// Prevent leaks
	}

	/**** Precompute HMAC Inner Digest ****/

	ctx = &(hmac.inner_digest_ctx);
	STREEBOG_init (ctx);

	/* Pad the key for inner digest */
	for (b = 0; b < lk; ++b)
		buf[b] = (char) (k[b] ^ 0x36);
	memset (&buf[lk], 0x36, STREEBOG_BLOCKSIZE - lk);

	STREEBOG_add (ctx, (unsigned char *) buf, STREEBOG_BLOCKSIZE);

	/**** Precompute HMAC Outer Digest ****/

	ctx = &(hmac.outer_digest_ctx);
	STREEBOG_init (ctx);

	for (b = 0; b < lk; ++b)
		buf[b] = (char) (k[b] ^ 0x5C);
	memset (&buf[lk], 0x5C, STREEBOG_BLOCKSIZE - lk);

	STREEBOG_add (ctx, (unsigned char *) buf, STREEBOG_BLOCKSIZE);

	hmac_streebog_internal(d, ld, &hmac);

#if defined (DEVICE_DRIVER) && !defined (_WIN64)
	if (NT_SUCCESS (saveStatus))
		KeRestoreFloatingPointState (&floatingPointState);
#endif
	/* Prevent leaks */
	burn(&hmac, sizeof(hmac));
}

static void derive_u_streebog (char *salt, int salt_len, uint32 iterations, int b, hmac_streebog_ctx* hmac)
{
	char* u = hmac->u;
	char* k = hmac->k;
	uint32 c, i;

	/* iteration 1 */
	memcpy (k, salt, salt_len);	/* salt */
	/* big-endian block number */
    b = bswap_32 (b);
	memcpy (&k[salt_len], &b, 4);

	hmac_streebog_internal (k, salt_len + 4, hmac);
	memcpy (u, k, STREEBOG_DIGESTSIZE);

	/* remaining iterations */
	for (c = 1; c < iterations; c++)
	{
		hmac_streebog_internal (k, STREEBOG_DIGESTSIZE, hmac);
		for (i = 0; i < STREEBOG_DIGESTSIZE; i++)
		{
			u[i] ^= k[i];
		}
	}
}

void derive_key_streebog (char *pwd, int pwd_len, char *salt, int salt_len, uint32 iterations, char *dk, int dklen)
{
	hmac_streebog_ctx hmac;
	STREEBOG_CTX* ctx;
	char* buf = hmac.k;
	char key[STREEBOG_DIGESTSIZE];
	int b, l, r;
#if defined (DEVICE_DRIVER) && !defined (_WIN64)
	KFLOATING_SAVE floatingPointState;
	NTSTATUS saveStatus = STATUS_INVALID_PARAMETER;
	if (HasSSE2() || HasSSE41())
		saveStatus = KeSaveFloatingPointState (&floatingPointState);
#endif
    /* If the password is longer than the hash algorithm block size,
	   let pwd = streebog(pwd), as per HMAC specifications. */
	if (pwd_len > STREEBOG_BLOCKSIZE)
	{
		STREEBOG_CTX tctx;

		STREEBOG_init (&tctx);
		STREEBOG_add (&tctx, (unsigned char *) pwd, pwd_len);
		STREEBOG_finalize (&tctx, (unsigned char *) key);

		pwd = key;
		pwd_len = STREEBOG_DIGESTSIZE;

		burn (&tctx, sizeof(tctx));		// Prevent leaks
	}

	if (dklen % STREEBOG_DIGESTSIZE)
	{
		l = 1 + dklen / STREEBOG_DIGESTSIZE;
	}
	else
	{
		l = dklen / STREEBOG_DIGESTSIZE;
	}

	r = dklen - (l - 1) * STREEBOG_DIGESTSIZE;

	/**** Precompute HMAC Inner Digest ****/

	ctx = &(hmac.inner_digest_ctx);
	STREEBOG_init (ctx);

	/* Pad the key for inner digest */
	for (b = 0; b < pwd_len; ++b)
		buf[b] = (char) (pwd[b] ^ 0x36);
	memset (&buf[pwd_len], 0x36, STREEBOG_BLOCKSIZE - pwd_len);

	STREEBOG_add (ctx, (unsigned char *) buf, STREEBOG_BLOCKSIZE);

	/**** Precompute HMAC Outer Digest ****/

	ctx = &(hmac.outer_digest_ctx);
	STREEBOG_init (ctx);

	for (b = 0; b < pwd_len; ++b)
		buf[b] = (char) (pwd[b] ^ 0x5C);
	memset (&buf[pwd_len], 0x5C, STREEBOG_BLOCKSIZE - pwd_len);

	STREEBOG_add (ctx, (unsigned char *) buf, STREEBOG_BLOCKSIZE);

	/* first l - 1 blocks */
	for (b = 1; b < l; b++)
	{
		derive_u_streebog (salt, salt_len, iterations, b, &hmac);
		memcpy (dk, hmac.u, STREEBOG_DIGESTSIZE);
		dk += STREEBOG_DIGESTSIZE;
	}

	/* last block */
	derive_u_streebog (salt, salt_len, iterations, b, &hmac);
	memcpy (dk, hmac.u, r);

#if defined (DEVICE_DRIVER) && !defined (_WIN64)
	if (NT_SUCCESS (saveStatus))
		KeRestoreFloatingPointState (&floatingPointState);
#endif

	/* Prevent possible leaks. */
	burn (&hmac, sizeof(hmac));
	burn (key, sizeof(key));
}

wchar_t *get_pkcs5_prf_name (int pkcs5_prf_id)
{
	switch (pkcs5_prf_id)
	{
	case SHA512:	
		return L"HMAC-SHA-512";

	case SHA256:	
		return L"HMAC-SHA-256";

	case RIPEMD160:	
		return L"HMAC-RIPEMD-160";

	case WHIRLPOOL:	
		return L"HMAC-Whirlpool";

	case STREEBOG:
		return L"HMAC-STREEBOG";

	default:		
		return L"(Unknown)";
	}
}



int get_pkcs5_iteration_count (int pkcs5_prf_id, int pim, BOOL truecryptMode, BOOL bBoot)
{
	if (	(pim < 0)
		|| (truecryptMode && pim > 0) /* No PIM for TrueCrypt mode */
		)
	{
		return 0;
	}

	switch (pkcs5_prf_id)
	{

	case RIPEMD160:	
		if (truecryptMode)
			return bBoot ? 1000 : 2000;
		else if (pim == 0)
			return bBoot? 327661 : 655331;
		else
		{
			return bBoot? pim * 2048 : 15000 + pim * 1000;
		}

	case SHA512:	
		return truecryptMode? 1000 : ((pim == 0)? 500000 : 15000 + pim * 1000);

	case WHIRLPOOL:	
		return truecryptMode? 1000 : ((pim == 0)? 500000 : 15000 + pim * 1000);

	case SHA256:
		if (truecryptMode)
			return 0; // SHA-256 not supported by TrueCrypt
		else if (pim == 0)
			return bBoot? 200000 : 500000;
		else
		{
			return bBoot? pim * 2048 : 15000 + pim * 1000;
		}

	case STREEBOG:	
		if (truecryptMode)
			return 1000;
		else if (pim == 0)
			return bBoot? 200000 : 500000;
		else
		{
			return bBoot? pim * 2048 : 15000 + pim * 1000;
		}

	default:		
		TC_THROW_FATAL_EXCEPTION;	// Unknown/wrong ID
	}
	return 0;
}

int is_pkcs5_prf_supported (int pkcs5_prf_id, BOOL truecryptMode, PRF_BOOT_TYPE bootType)
{
   if (pkcs5_prf_id == 0) // auto-detection always supported
      return 1;

   if (truecryptMode)
   {
      if (  (bootType == PRF_BOOT_GPT) 
         || (bootType == PRF_BOOT_MBR && pkcs5_prf_id != RIPEMD160) 
         || (bootType == PRF_BOOT_NO && pkcs5_prf_id != SHA512 && pkcs5_prf_id != WHIRLPOOL && pkcs5_prf_id != RIPEMD160)
         )
         return 0;
   }
   else
   {
      if (  (bootType == PRF_BOOT_MBR && pkcs5_prf_id != RIPEMD160 && pkcs5_prf_id != SHA256)
         || (bootType != PRF_BOOT_MBR && (pkcs5_prf_id < FIRST_PRF_ID || pkcs5_prf_id > LAST_PRF_ID))
         )
         return 0;
   }

   return 1;

}

#endif //!TC_WINDOWS_BOOT
