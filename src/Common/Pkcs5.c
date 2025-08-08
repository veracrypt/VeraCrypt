/*
 Legal Notice: Some portions of the source code contained in this file were
 derived from the source code of TrueCrypt 7.1a, which is 
 Copyright (c) 2003-2012 TrueCrypt Developers Association and which is 
 governed by the TrueCrypt License 3.0, also from the source code of
 Encryption for the Masses 2.02a, which is Copyright (c) 1998-2000 Paul Le Roux
 and which is governed by the 'License Agreement for Encryption for the Masses' 
 Modifications and additions to the original source code (contained in this file) 
 and all other portions of this file are Copyright (c) 2013-2025 AM Crypto
 and are governed by the Apache License 2.0 the full text of which is
 contained in the file License.txt included in VeraCrypt binary and source
 code distribution packages. */

#include "Tcdefs.h"
#if !defined(_UEFI)
#include <memory.h>
#include <stdlib.h>
#endif
#include "blake2s.h"
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
	unsigned char k[PKCS5_SALT_SIZE + 4]; /* enough to hold (salt_len + 4) and also the SHA256 hash */
	unsigned char u[SHA256_DIGESTSIZE];
} hmac_sha256_ctx;

void hmac_sha256_internal
(
	unsigned char *d,		/* input data. d pointer is guaranteed to be at least 32-bytes long */
	  int ld,		/* length of input data in bytes */
	  hmac_sha256_ctx* hmac /* HMAC-SHA256 context which holds temporary variables */
)
{
	sha256_ctx* ctx = &(hmac->ctx);

	/**** Restore Precomputed Inner Digest Context ****/

	memcpy (ctx, &(hmac->inner_digest_ctx), sizeof (sha256_ctx));

	sha256_hash (d, ld, ctx);

	sha256_end (d, ctx); /* d = inner digest */

	/**** Restore Precomputed Outer Digest Context ****/

	memcpy (ctx, &(hmac->outer_digest_ctx), sizeof (sha256_ctx));

	sha256_hash (d, SHA256_DIGESTSIZE, ctx);

	sha256_end (d, ctx); /* d = outer digest */
}

#ifndef TC_WINDOWS_BOOT
void hmac_sha256
(
	unsigned char *k,    /* secret key */
	int lk,    /* length of the key in bytes */
	unsigned char *d,    /* data */
	int ld    /* length of data in bytes */
)
{
	hmac_sha256_ctx hmac;
	sha256_ctx* ctx;
	unsigned char* buf = hmac.k;
	int b;
	unsigned char key[SHA256_DIGESTSIZE];
#if defined (DEVICE_DRIVER) && !defined(_M_ARM64)
	NTSTATUS saveStatus = STATUS_INVALID_PARAMETER;
	XSTATE_SAVE SaveState;
	if (IsCpuIntel() && HasSAVX())
		saveStatus = KeSaveExtendedProcessorState(XSTATE_MASK_GSSE, &SaveState);
#endif
    /* If the key is longer than the hash algorithm block size,
	   let key = sha256(key), as per HMAC specifications. */
	if (lk > SHA256_BLOCKSIZE)
	{
		sha256_ctx tctx;

		sha256_begin (&tctx);
		sha256_hash (k, lk, &tctx);
		sha256_end (key, &tctx);

		k = key;
		lk = SHA256_DIGESTSIZE;

		burn (&tctx, sizeof(tctx));		// Prevent leaks
	}

	/**** Precompute HMAC Inner Digest ****/

	ctx = &(hmac.inner_digest_ctx);
	sha256_begin (ctx);

	/* Pad the key for inner digest */
	for (b = 0; b < lk; ++b)
		buf[b] = (unsigned char) (k[b] ^ 0x36);
	memset (&buf[lk], 0x36, SHA256_BLOCKSIZE - lk);

	sha256_hash (buf, SHA256_BLOCKSIZE, ctx);

	/**** Precompute HMAC Outer Digest ****/

	ctx = &(hmac.outer_digest_ctx);
	sha256_begin (ctx);

	for (b = 0; b < lk; ++b)
		buf[b] = (unsigned char) (k[b] ^ 0x5C);
	memset (&buf[lk], 0x5C, SHA256_BLOCKSIZE - lk);

	sha256_hash (buf, SHA256_BLOCKSIZE, ctx);

	hmac_sha256_internal(d, ld, &hmac);

#if defined (DEVICE_DRIVER) && !defined(_M_ARM64)
	if (NT_SUCCESS (saveStatus))
		KeRestoreExtendedProcessorState(&SaveState);
#endif

	/* Prevent leaks */
	burn(&hmac, sizeof(hmac));
	burn(key, sizeof(key));
}
#endif

static void derive_u_sha256 (const unsigned char *salt, int salt_len, uint32 iterations, int b, hmac_sha256_ctx* hmac
#ifndef TC_WINDOWS_BOOT
	, long volatile *pAbortKeyDerivation
#endif
)
{
	unsigned char* k = hmac->k;
	unsigned char* u = hmac->u;
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
	k[salt_len + 3] = (unsigned char) b;
#else
    b = bswap_32 (b);
    memcpy (&k[salt_len], &b, 4);
#endif	

	hmac_sha256_internal (k, salt_len + 4, hmac);
	memcpy (u, k, SHA256_DIGESTSIZE);

	/* remaining iterations */
	while (c > 1)
	{
#ifndef TC_WINDOWS_BOOT
		// CANCELLATION CHECK: Check every 1024 iterations
		if (pAbortKeyDerivation && (c & 1023) == 0 && *pAbortKeyDerivation == 1)
			return; // Abort derivation
#endif
		hmac_sha256_internal (k, SHA256_DIGESTSIZE, hmac);
		for (i = 0; i < SHA256_DIGESTSIZE; i++)
		{
			u[i] ^= k[i];
		}
		c--;
	}
}


void derive_key_sha256 (const unsigned char *pwd, int pwd_len, const unsigned char *salt, int salt_len, uint32 iterations, unsigned char *dk, int dklen
#ifndef TC_WINDOWS_BOOT
	, long volatile *pAbortKeyDerivation
#endif
)
{	
	hmac_sha256_ctx hmac;
	sha256_ctx* ctx;
	unsigned char* buf = hmac.k;
	int b, l, r;
#ifndef TC_WINDOWS_BOOT
	unsigned char key[SHA256_DIGESTSIZE];
#if defined (DEVICE_DRIVER) && !defined(_M_ARM64)
	NTSTATUS saveStatus = STATUS_INVALID_PARAMETER;
	XSTATE_SAVE SaveState;
	if (IsCpuIntel() && HasSAVX())
		saveStatus = KeSaveExtendedProcessorState(XSTATE_MASK_GSSE, &SaveState);
#endif
    /* If the password is longer than the hash algorithm block size,
	   let pwd = sha256(pwd), as per HMAC specifications. */
	if (pwd_len > SHA256_BLOCKSIZE)
	{
		sha256_ctx tctx;

		sha256_begin (&tctx);
		sha256_hash (pwd, pwd_len, &tctx);
		sha256_end (key, &tctx);

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
		buf[b] = (unsigned char) (pwd[b] ^ 0x36);
	memset (&buf[pwd_len], 0x36, SHA256_BLOCKSIZE - pwd_len);

	sha256_hash (buf, SHA256_BLOCKSIZE, ctx);

	/**** Precompute HMAC Outer Digest ****/

	ctx = &(hmac.outer_digest_ctx);
	sha256_begin (ctx);

	for (b = 0; b < pwd_len; ++b)
		buf[b] = (unsigned char) (pwd[b] ^ 0x5C);
	memset (&buf[pwd_len], 0x5C, SHA256_BLOCKSIZE - pwd_len);

	sha256_hash (buf, SHA256_BLOCKSIZE, ctx);

	/* first l - 1 blocks */
	for (b = 1; b < l; b++)
	{
#ifndef TC_WINDOWS_BOOT
		derive_u_sha256 (salt, salt_len, iterations, b, &hmac, pAbortKeyDerivation);
		// Check if the derivation was aborted
		if (pAbortKeyDerivation && *pAbortKeyDerivation == 1)
			goto cancelled;
#else
		derive_u_sha256 (salt, salt_len, iterations, b, &hmac);
#endif
		memcpy (dk, hmac.u, SHA256_DIGESTSIZE);
		dk += SHA256_DIGESTSIZE;
	}

	/* last block */
#ifndef TC_WINDOWS_BOOT
	derive_u_sha256 (salt, salt_len, iterations, b, &hmac, pAbortKeyDerivation);
	// Check if the derivation was aborted (in case of only one block)
	if (pAbortKeyDerivation && *pAbortKeyDerivation == 1)
		goto cancelled;
#else
	derive_u_sha256 (salt, salt_len, iterations, b, &hmac);
#endif
	memcpy (dk, hmac.u, r);

#if defined (DEVICE_DRIVER) && !defined(_M_ARM64)
	if (NT_SUCCESS (saveStatus))
		KeRestoreExtendedProcessorState(&SaveState);
#endif
#ifndef TC_WINDOWS_BOOT
cancelled:
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
	unsigned char k[SHA512_BLOCKSIZE]; /* enough to hold (salt_len + 4) and also the SHA512 hash */
	unsigned char u[SHA512_DIGESTSIZE];
} hmac_sha512_ctx;

void hmac_sha512_internal
(
	unsigned char *d,		/* data and also output buffer of at least 64 bytes */
	  int ld,			/* length of data in bytes */
	  hmac_sha512_ctx* hmac
)
{
	sha512_ctx* ctx = &(hmac->ctx);

	/**** Restore Precomputed Inner Digest Context ****/

	memcpy (ctx, &(hmac->inner_digest_ctx), sizeof (sha512_ctx));

	sha512_hash (d, ld, ctx);

	sha512_end (d, ctx);

	/**** Restore Precomputed Outer Digest Context ****/

	memcpy (ctx, &(hmac->outer_digest_ctx), sizeof (sha512_ctx));

	sha512_hash (d, SHA512_DIGESTSIZE, ctx);

	sha512_end (d, ctx);
}

void hmac_sha512
(
	  unsigned char *k,		/* secret key */
	  int lk,		/* length of the key in bytes */
 	  unsigned char *d,		/* data and also output buffer of at least 64 bytes */
	  int ld			/* length of data in bytes */	  
)
{
	hmac_sha512_ctx hmac;
	sha512_ctx* ctx;
	unsigned char* buf = hmac.k;
	int b;
	unsigned char key[SHA512_DIGESTSIZE];
#if defined (DEVICE_DRIVER) && !defined(_M_ARM64)
	NTSTATUS saveStatus = STATUS_INVALID_PARAMETER;
	XSTATE_SAVE SaveState;
	if (IsCpuIntel() && HasSAVX())
		saveStatus = KeSaveExtendedProcessorState(XSTATE_MASK_GSSE, &SaveState);
#endif

    /* If the key is longer than the hash algorithm block size,
	   let key = sha512(key), as per HMAC specifications. */
	if (lk > SHA512_BLOCKSIZE)
	{
		sha512_ctx tctx;

		sha512_begin (&tctx);
		sha512_hash (k, lk, &tctx);
		sha512_end (key, &tctx);

		k = key;
		lk = SHA512_DIGESTSIZE;

		burn (&tctx, sizeof(tctx));		// Prevent leaks
	}

	/**** Precompute HMAC Inner Digest ****/

	ctx = &(hmac.inner_digest_ctx);
	sha512_begin (ctx);

	/* Pad the key for inner digest */
	for (b = 0; b < lk; ++b)
		buf[b] = (unsigned char) (k[b] ^ 0x36);
	memset (&buf[lk], 0x36, SHA512_BLOCKSIZE - lk);

	sha512_hash (buf, SHA512_BLOCKSIZE, ctx);

	/**** Precompute HMAC Outer Digest ****/

	ctx = &(hmac.outer_digest_ctx);
	sha512_begin (ctx);

	for (b = 0; b < lk; ++b)
		buf[b] = (unsigned char) (k[b] ^ 0x5C);
	memset (&buf[lk], 0x5C, SHA512_BLOCKSIZE - lk);

	sha512_hash (buf, SHA512_BLOCKSIZE, ctx);

	hmac_sha512_internal (d, ld, &hmac);

#if defined (DEVICE_DRIVER) && !defined(_M_ARM64)
	if (NT_SUCCESS (saveStatus))
		KeRestoreExtendedProcessorState(&SaveState);
#endif

	/* Prevent leaks */
	burn (&hmac, sizeof(hmac));
	burn (key, sizeof(key));
}

static void derive_u_sha512 (const unsigned char *salt, int salt_len, uint32 iterations, int b, hmac_sha512_ctx* hmac, long volatile *pAbortKeyDerivation)
{
	unsigned char* k = hmac->k;
	unsigned char* u = hmac->u;
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
		// CANCELLATION CHECK: Check every 1024 iterations
		if (pAbortKeyDerivation && (c & 1023) == 0 && *pAbortKeyDerivation == 1)
			return; // Abort derivation
		hmac_sha512_internal (k, SHA512_DIGESTSIZE, hmac);
		for (i = 0; i < SHA512_DIGESTSIZE; i++)
		{
			u[i] ^= k[i];
		}
	}
}


void derive_key_sha512 (const unsigned char *pwd, int pwd_len, const unsigned char *salt, int salt_len, uint32 iterations, unsigned char *dk, int dklen, long volatile *pAbortKeyDerivation)
{
	hmac_sha512_ctx hmac;
	sha512_ctx* ctx;
	unsigned char* buf = hmac.k;
	int b, l, r;
	unsigned char key[SHA512_DIGESTSIZE];
#if defined (DEVICE_DRIVER) && !defined(_M_ARM64)
	NTSTATUS saveStatus = STATUS_INVALID_PARAMETER;
	XSTATE_SAVE SaveState;
	if (IsCpuIntel() && HasSAVX())
		saveStatus = KeSaveExtendedProcessorState(XSTATE_MASK_GSSE, &SaveState);
#endif

    /* If the password is longer than the hash algorithm block size,
	   let pwd = sha512(pwd), as per HMAC specifications. */
	if (pwd_len > SHA512_BLOCKSIZE)
	{
		sha512_ctx tctx;

		sha512_begin (&tctx);
		sha512_hash (pwd, pwd_len, &tctx);
		sha512_end (key, &tctx);

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
		buf[b] = (unsigned char) (pwd[b] ^ 0x36);
	memset (&buf[pwd_len], 0x36, SHA512_BLOCKSIZE - pwd_len);

	sha512_hash (buf, SHA512_BLOCKSIZE, ctx);

	/**** Precompute HMAC Outer Digest ****/

	ctx = &(hmac.outer_digest_ctx);
	sha512_begin (ctx);

	for (b = 0; b < pwd_len; ++b)
		buf[b] = (unsigned char) (pwd[b] ^ 0x5C);
	memset (&buf[pwd_len], 0x5C, SHA512_BLOCKSIZE - pwd_len);

	sha512_hash (buf, SHA512_BLOCKSIZE, ctx);

	/* first l - 1 blocks */
	for (b = 1; b < l; b++)
	{
		derive_u_sha512 (salt, salt_len, iterations, b, &hmac, pAbortKeyDerivation);
		// Check if the derivation was aborted
		if (pAbortKeyDerivation && *pAbortKeyDerivation == 1)
			goto cancelled;
		memcpy (dk, hmac.u, SHA512_DIGESTSIZE);
		dk += SHA512_DIGESTSIZE;
	}

	/* last block */
	derive_u_sha512 (salt, salt_len, iterations, b, &hmac, pAbortKeyDerivation);
	// Check if the derivation was aborted (in case of only one block)
	if (pAbortKeyDerivation && *pAbortKeyDerivation == 1)
		goto cancelled;
	memcpy (dk, hmac.u, r);

#if defined (DEVICE_DRIVER) && !defined(_M_ARM64)
	if (NT_SUCCESS (saveStatus))
		KeRestoreExtendedProcessorState(&SaveState);
#endif
cancelled:
	/* Prevent possible leaks. */
	burn (&hmac, sizeof(hmac));
	burn (key, sizeof(key));
}

#endif // TC_WINDOWS_BOOT

#if !defined(TC_WINDOWS_BOOT) || defined(TC_WINDOWS_BOOT_BLAKE2S)

typedef struct hmac_blake2s_ctx_struct
{
	blake2s_state ctx;
	blake2s_state inner_digest_ctx; /*pre-computed inner digest context */
	blake2s_state outer_digest_ctx; /*pre-computed outer digest context */
	unsigned char k[PKCS5_SALT_SIZE + 4]; /* enough to hold (salt_len + 4) and also the Blake2s hash */
	unsigned char u[BLAKE2S_DIGESTSIZE];
} hmac_blake2s_ctx;

void hmac_blake2s_internal
(
	unsigned char *d,		/* input data. d pointer is guaranteed to be at least 32-bytes long */
	  int ld,		/* length of input data in bytes */
	  hmac_blake2s_ctx* hmac /* HMAC-BLAKE2S context which holds temporary variables */
)
{
	blake2s_state* ctx = &(hmac->ctx);

	/**** Restore Precomputed Inner Digest Context ****/

	memcpy (ctx, &(hmac->inner_digest_ctx), sizeof (blake2s_state));

	blake2s_update (ctx, d, ld);

	blake2s_final (ctx, d); /* d = inner digest */

	/**** Restore Precomputed Outer Digest Context ****/

	memcpy (ctx, &(hmac->outer_digest_ctx), sizeof (blake2s_state));

	blake2s_update (ctx, d, BLAKE2S_DIGESTSIZE);

	blake2s_final (ctx, d); /* d = outer digest */
}

#ifndef TC_WINDOWS_BOOT
void hmac_blake2s
(
	unsigned char *k,    /* secret key */
	int lk,    /* length of the key in bytes */
	unsigned char *d,    /* data */
	int ld    /* length of data in bytes */
)
{
	hmac_blake2s_ctx hmac;
	blake2s_state* ctx;
	unsigned char* buf = hmac.k;
	int b;
	unsigned char key[BLAKE2S_DIGESTSIZE];
#if defined (DEVICE_DRIVER) && !defined(_M_ARM64)
	NTSTATUS saveStatus = STATUS_INVALID_PARAMETER;
	XSTATE_SAVE SaveState;
	if (IsCpuIntel() && HasSAVX())
		saveStatus = KeSaveExtendedProcessorState(XSTATE_MASK_GSSE, &SaveState);
#endif
    /* If the key is longer than the hash algorithm block size,
	   let key = blake2s(key), as per HMAC specifications. */
	if (lk > BLAKE2S_BLOCKSIZE)
	{
		blake2s_state tctx;

		blake2s_init (&tctx);
		blake2s_update (&tctx, k, lk);
		blake2s_final (&tctx, key);

		k = key;
		lk = BLAKE2S_DIGESTSIZE;

		burn (&tctx, sizeof(tctx));		// Prevent leaks
	}

	/**** Precompute HMAC Inner Digest ****/

	ctx = &(hmac.inner_digest_ctx);
	blake2s_init (ctx);

	/* Pad the key for inner digest */
	for (b = 0; b < lk; ++b)
		buf[b] = (unsigned char) (k[b] ^ 0x36);
	memset (&buf[lk], 0x36, BLAKE2S_BLOCKSIZE - lk);

	blake2s_update (ctx, buf, BLAKE2S_BLOCKSIZE);

	/**** Precompute HMAC Outer Digest ****/

	ctx = &(hmac.outer_digest_ctx);
	blake2s_init (ctx);

	for (b = 0; b < lk; ++b)
		buf[b] = (unsigned char) (k[b] ^ 0x5C);
	memset (&buf[lk], 0x5C, BLAKE2S_BLOCKSIZE - lk);

	blake2s_update (ctx, buf, BLAKE2S_BLOCKSIZE);

	hmac_blake2s_internal(d, ld, &hmac);

#if defined (DEVICE_DRIVER) && !defined(_M_ARM64)
	if (NT_SUCCESS (saveStatus))
		KeRestoreExtendedProcessorState(&SaveState);
#endif

	/* Prevent leaks */
	burn(&hmac, sizeof(hmac));
	burn(key, sizeof(key));
}
#endif

static void derive_u_blake2s (const unsigned char *salt, int salt_len, uint32 iterations, int b, hmac_blake2s_ctx* hmac
#ifndef TC_WINDOWS_BOOT
	, volatile long *pAbortKeyDerivation
#endif
)
{
	unsigned char* k = hmac->k;
	unsigned char* u = hmac->u;
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
	k[salt_len + 3] = (unsigned char) b;
#else
    b = bswap_32 (b);
    memcpy (&k[salt_len], &b, 4);
#endif	

	hmac_blake2s_internal (k, salt_len + 4, hmac);
	memcpy (u, k, BLAKE2S_DIGESTSIZE);

	/* remaining iterations */
	while (c > 1)
	{
#ifndef TC_WINDOWS_BOOT
		// CANCELLATION CHECK: Check every 1024 iterations
		if (pAbortKeyDerivation && (c & 1023) == 0 && *pAbortKeyDerivation)
			return; // Abort derivation
#endif
		hmac_blake2s_internal (k, BLAKE2S_DIGESTSIZE, hmac);
		for (i = 0; i < BLAKE2S_DIGESTSIZE; i++)
		{
			u[i] ^= k[i];
		}
		c--;
	}
}


void derive_key_blake2s (const unsigned char *pwd, int pwd_len, const unsigned char *salt, int salt_len, uint32 iterations, unsigned char *dk, int dklen
#ifndef TC_WINDOWS_BOOT
	, volatile long *pAbortKeyDerivation
#endif
)
{	
	hmac_blake2s_ctx hmac;
	blake2s_state* ctx;
	unsigned char* buf = hmac.k;
	int b, l, r;
#ifndef TC_WINDOWS_BOOT
	unsigned char key[BLAKE2S_DIGESTSIZE];
#if defined (DEVICE_DRIVER) && !defined(_M_ARM64)
	NTSTATUS saveStatus = STATUS_INVALID_PARAMETER;
	XSTATE_SAVE SaveState;
	if (IsCpuIntel() && HasSAVX())
		saveStatus = KeSaveExtendedProcessorState(XSTATE_MASK_GSSE, &SaveState);
#endif
    /* If the password is longer than the hash algorithm block size,
	   let pwd = blake2s(pwd), as per HMAC specifications. */
	if (pwd_len > BLAKE2S_BLOCKSIZE)
	{
		blake2s_state tctx;

		blake2s_init (&tctx);
		blake2s_update (&tctx, pwd, pwd_len);
		blake2s_final (&tctx, key);

		pwd = key;
		pwd_len = BLAKE2S_DIGESTSIZE;

		burn (&tctx, sizeof(tctx));		// Prevent leaks
	}
#endif

	if (dklen % BLAKE2S_DIGESTSIZE)
	{
		l = 1 + dklen / BLAKE2S_DIGESTSIZE;
	}
	else
	{
		l = dklen / BLAKE2S_DIGESTSIZE;
	}

	r = dklen - (l - 1) * BLAKE2S_DIGESTSIZE;

	/**** Precompute HMAC Inner Digest ****/

	ctx = &(hmac.inner_digest_ctx);
	blake2s_init (ctx);

	/* Pad the key for inner digest */
	for (b = 0; b < pwd_len; ++b)
		buf[b] = (unsigned char) (pwd[b] ^ 0x36);
	memset (&buf[pwd_len], 0x36, BLAKE2S_BLOCKSIZE - pwd_len);

	blake2s_update (ctx, buf, BLAKE2S_BLOCKSIZE);

	/**** Precompute HMAC Outer Digest ****/

	ctx = &(hmac.outer_digest_ctx);
	blake2s_init (ctx);

	for (b = 0; b < pwd_len; ++b)
		buf[b] = (unsigned char) (pwd[b] ^ 0x5C);
	memset (&buf[pwd_len], 0x5C, BLAKE2S_BLOCKSIZE - pwd_len);

	blake2s_update (ctx, buf, BLAKE2S_BLOCKSIZE);

	/* first l - 1 blocks */
	for (b = 1; b < l; b++)
	{
#ifndef TC_WINDOWS_BOOT
		derive_u_blake2s (salt, salt_len, iterations, b, &hmac, pAbortKeyDerivation);
		// Check if the derivation was aborted
		if (pAbortKeyDerivation && *pAbortKeyDerivation)
			goto cancelled;
#else
		derive_u_blake2s (salt, salt_len, iterations, b, &hmac);
#endif
		memcpy (dk, hmac.u, BLAKE2S_DIGESTSIZE);
		dk += BLAKE2S_DIGESTSIZE;
	}

	/* last block */
#ifndef TC_WINDOWS_BOOT
	derive_u_blake2s (salt, salt_len, iterations, b, &hmac, pAbortKeyDerivation);
	// Check if the derivation was aborted (in case of only one block)
	if (pAbortKeyDerivation && *pAbortKeyDerivation)
		goto cancelled;
#else
	derive_u_blake2s (salt, salt_len, iterations, b, &hmac);
#endif
	memcpy (dk, hmac.u, r);

#if defined (DEVICE_DRIVER) && !defined(_M_ARM64)
	if (NT_SUCCESS (saveStatus))
		KeRestoreExtendedProcessorState(&SaveState);
#endif
#ifndef TC_WINDOWS_BOOT
cancelled:
#endif
	/* Prevent possible leaks. */
	burn (&hmac, sizeof(hmac));
#ifndef TC_WINDOWS_BOOT
	burn (key, sizeof(key));
#endif
}

#endif

#ifndef TC_WINDOWS_BOOT

typedef struct hmac_whirlpool_ctx_struct
{
	WHIRLPOOL_CTX ctx;
	WHIRLPOOL_CTX inner_digest_ctx; /*pre-computed inner digest context */
	WHIRLPOOL_CTX outer_digest_ctx; /*pre-computed outer digest context */
	CRYPTOPP_ALIGN_DATA(16) unsigned char k[PKCS5_SALT_SIZE + 4]; /* enough to hold (salt_len + 4) and also the Whirlpool hash */
	unsigned char u[WHIRLPOOL_DIGESTSIZE];
} hmac_whirlpool_ctx;

void hmac_whirlpool_internal
(
	unsigned char *d,		/* input/output data. d pointer is guaranteed to be at least 64-bytes long */
	  int ld,		/* length of input data in bytes */
	  hmac_whirlpool_ctx* hmac /* HMAC-Whirlpool context which holds temporary variables */
)
{
	WHIRLPOOL_CTX* ctx = &(hmac->ctx);

	/**** Restore Precomputed Inner Digest Context ****/

	memcpy (ctx, &(hmac->inner_digest_ctx), sizeof (WHIRLPOOL_CTX));

	WHIRLPOOL_add (d, ld, ctx);

	WHIRLPOOL_finalize (ctx, d);

	/**** Restore Precomputed Outer Digest Context ****/

	memcpy (ctx, &(hmac->outer_digest_ctx), sizeof (WHIRLPOOL_CTX));

	WHIRLPOOL_add (d, WHIRLPOOL_DIGESTSIZE, ctx);

	WHIRLPOOL_finalize (ctx, d);
}

void hmac_whirlpool
(
	  unsigned char *k,		/* secret key */
	  int lk,		/* length of the key in bytes */
	  unsigned char *d,		/* input data. d pointer is guaranteed to be at least 32-bytes long */
	  int ld		/* length of data in bytes */
)
{
	hmac_whirlpool_ctx hmac;
	WHIRLPOOL_CTX* ctx;
	unsigned char* buf = hmac.k;
	int b;
	unsigned char key[WHIRLPOOL_DIGESTSIZE];
    /* If the key is longer than the hash algorithm block size,
	   let key = whirlpool(key), as per HMAC specifications. */
	if (lk > WHIRLPOOL_BLOCKSIZE)
	{
		WHIRLPOOL_CTX tctx;

		WHIRLPOOL_init (&tctx);
		WHIRLPOOL_add (k, lk, &tctx);
		WHIRLPOOL_finalize (&tctx, key);

		k = key;
		lk = WHIRLPOOL_DIGESTSIZE;

		burn (&tctx, sizeof(tctx));		// Prevent leaks
	}

	/**** Precompute HMAC Inner Digest ****/

	ctx = &(hmac.inner_digest_ctx);
	WHIRLPOOL_init (ctx);

	/* Pad the key for inner digest */
	for (b = 0; b < lk; ++b)
		buf[b] = (unsigned char) (k[b] ^ 0x36);
	memset (&buf[lk], 0x36, WHIRLPOOL_BLOCKSIZE - lk);

	WHIRLPOOL_add (buf, WHIRLPOOL_BLOCKSIZE, ctx);

	/**** Precompute HMAC Outer Digest ****/

	ctx = &(hmac.outer_digest_ctx);
	WHIRLPOOL_init (ctx);

	for (b = 0; b < lk; ++b)
		buf[b] = (unsigned char) (k[b] ^ 0x5C);
	memset (&buf[lk], 0x5C, WHIRLPOOL_BLOCKSIZE - lk);

	WHIRLPOOL_add (buf, WHIRLPOOL_BLOCKSIZE, ctx);

	hmac_whirlpool_internal(d, ld, &hmac);

	/* Prevent leaks */
	burn(&hmac, sizeof(hmac));
}

static void derive_u_whirlpool (const unsigned char *salt, int salt_len, uint32 iterations, int b, hmac_whirlpool_ctx* hmac, volatile long *pAbortKeyDerivation)
{
	unsigned char* u = hmac->u;
	unsigned char* k = hmac->k;
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
		// CANCELLATION CHECK: Check every 1024 iterations
		if (pAbortKeyDerivation && (c & 1023) == 0 && *pAbortKeyDerivation)
			return; // Abort derivation
		hmac_whirlpool_internal (k, WHIRLPOOL_DIGESTSIZE, hmac);
		for (i = 0; i < WHIRLPOOL_DIGESTSIZE; i++)
		{
			u[i] ^= k[i];
		}
	}
}

void derive_key_whirlpool (const unsigned char *pwd, int pwd_len, const unsigned char *salt, int salt_len, uint32 iterations, unsigned char *dk, int dklen, volatile long *pAbortKeyDerivation)
{
	hmac_whirlpool_ctx hmac;
	WHIRLPOOL_CTX* ctx;
	unsigned char* buf = hmac.k;
	unsigned char key[WHIRLPOOL_DIGESTSIZE];
	int b, l, r;
    /* If the password is longer than the hash algorithm block size,
	   let pwd = whirlpool(pwd), as per HMAC specifications. */
	if (pwd_len > WHIRLPOOL_BLOCKSIZE)
	{
		WHIRLPOOL_CTX tctx;

		WHIRLPOOL_init (&tctx);
		WHIRLPOOL_add (pwd, pwd_len, &tctx);
		WHIRLPOOL_finalize (&tctx, key);

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
		buf[b] = (unsigned char) (pwd[b] ^ 0x36);
	memset (&buf[pwd_len], 0x36, WHIRLPOOL_BLOCKSIZE - pwd_len);

	WHIRLPOOL_add (buf, WHIRLPOOL_BLOCKSIZE, ctx);

	/**** Precompute HMAC Outer Digest ****/

	ctx = &(hmac.outer_digest_ctx);
	WHIRLPOOL_init (ctx);

	for (b = 0; b < pwd_len; ++b)
		buf[b] = (unsigned char) (pwd[b] ^ 0x5C);
	memset (&buf[pwd_len], 0x5C, WHIRLPOOL_BLOCKSIZE - pwd_len);

	WHIRLPOOL_add (buf, WHIRLPOOL_BLOCKSIZE, ctx);

	/* first l - 1 blocks */
	for (b = 1; b < l; b++)
	{
		derive_u_whirlpool (salt, salt_len, iterations, b, &hmac, pAbortKeyDerivation);
		// Check if the derivation was aborted
		if (pAbortKeyDerivation && *pAbortKeyDerivation)
			goto cancelled;
		memcpy (dk, hmac.u, WHIRLPOOL_DIGESTSIZE);
		dk += WHIRLPOOL_DIGESTSIZE;
	}

	/* last block */
	derive_u_whirlpool (salt, salt_len, iterations, b, &hmac, pAbortKeyDerivation);
	// Check if the derivation was aborted (in case of only one block)
	if (pAbortKeyDerivation && *pAbortKeyDerivation)
		goto cancelled;
	memcpy (dk, hmac.u, r);
cancelled:
	/* Prevent possible leaks. */
	burn (&hmac, sizeof(hmac));
	burn (key, sizeof(key));
}


typedef struct hmac_streebog_ctx_struct
{
	STREEBOG_CTX ctx;
	STREEBOG_CTX inner_digest_ctx; /*pre-computed inner digest context */
	STREEBOG_CTX outer_digest_ctx; /*pre-computed outer digest context */
	CRYPTOPP_ALIGN_DATA(16) unsigned char k[PKCS5_SALT_SIZE + 4]; /* enough to hold (salt_len + 4) and also the Streebog hash */
	unsigned char u[STREEBOG_DIGESTSIZE];
} hmac_streebog_ctx;

void hmac_streebog_internal
(
	  unsigned char *d,		/* input/output data. d pointer is guaranteed to be at least 64-bytes long */
	  int ld,		/* length of input data in bytes */
	  hmac_streebog_ctx* hmac /* HMAC-Whirlpool context which holds temporary variables */
)
{
	STREEBOG_CTX* ctx = &(hmac->ctx);

	/**** Restore Precomputed Inner Digest Context ****/

	memcpy (ctx, &(hmac->inner_digest_ctx), sizeof (STREEBOG_CTX));

	STREEBOG_add (ctx, d, ld);

	STREEBOG_finalize (ctx, d);

	/**** Restore Precomputed Outer Digest Context ****/

	memcpy (ctx, &(hmac->outer_digest_ctx), sizeof (STREEBOG_CTX));

	STREEBOG_add (ctx, d, STREEBOG_DIGESTSIZE);

	STREEBOG_finalize (ctx, d);
}

void hmac_streebog
(
	  unsigned char *k,		/* secret key */
	  int lk,		/* length of the key in bytes */
	  unsigned char *d,		/* input data. d pointer is guaranteed to be at least 32-bytes long */
	  int ld		/* length of data in bytes */
)
{
	hmac_streebog_ctx hmac;
	STREEBOG_CTX* ctx;
	unsigned char* buf = hmac.k;
	int b;
	CRYPTOPP_ALIGN_DATA(16) unsigned char key[STREEBOG_DIGESTSIZE];
    /* If the key is longer than the hash algorithm block size,
	   let key = streebog(key), as per HMAC specifications. */
	if (lk > STREEBOG_BLOCKSIZE)
	{
		STREEBOG_CTX tctx;

		STREEBOG_init (&tctx);
		STREEBOG_add (&tctx, k, lk);
		STREEBOG_finalize (&tctx, key);

		k = key;
		lk = STREEBOG_DIGESTSIZE;

		burn (&tctx, sizeof(tctx));		// Prevent leaks
	}

	/**** Precompute HMAC Inner Digest ****/

	ctx = &(hmac.inner_digest_ctx);
	STREEBOG_init (ctx);

	/* Pad the key for inner digest */
	for (b = 0; b < lk; ++b)
		buf[b] = (unsigned char) (k[b] ^ 0x36);
	memset (&buf[lk], 0x36, STREEBOG_BLOCKSIZE - lk);

	STREEBOG_add (ctx, buf, STREEBOG_BLOCKSIZE);

	/**** Precompute HMAC Outer Digest ****/

	ctx = &(hmac.outer_digest_ctx);
	STREEBOG_init (ctx);

	for (b = 0; b < lk; ++b)
		buf[b] = (unsigned char) (k[b] ^ 0x5C);
	memset (&buf[lk], 0x5C, STREEBOG_BLOCKSIZE - lk);

	STREEBOG_add (ctx, buf, STREEBOG_BLOCKSIZE);

	hmac_streebog_internal(d, ld, &hmac);

	/* Prevent leaks */
	burn(&hmac, sizeof(hmac));
}

static void derive_u_streebog (const unsigned char *salt, int salt_len, uint32 iterations, int b, hmac_streebog_ctx* hmac, volatile long *pAbortKeyDerivation)
{
	unsigned char* u = hmac->u;
	unsigned char* k = hmac->k;
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
		// CANCELLATION CHECK: Check every 1024 iterations
		if (pAbortKeyDerivation && (c & 1023) == 0 && *pAbortKeyDerivation)
			return; // Abort derivation
		hmac_streebog_internal (k, STREEBOG_DIGESTSIZE, hmac);
		for (i = 0; i < STREEBOG_DIGESTSIZE; i++)
		{
			u[i] ^= k[i];
		}
	}
}

void derive_key_streebog (const unsigned char *pwd, int pwd_len, const unsigned char *salt, int salt_len, uint32 iterations, unsigned char *dk, int dklen, volatile long *pAbortKeyDerivation)
{
	hmac_streebog_ctx hmac;
	STREEBOG_CTX* ctx;
	unsigned char* buf = hmac.k;
	unsigned char key[STREEBOG_DIGESTSIZE];
	int b, l, r;
    /* If the password is longer than the hash algorithm block size,
	   let pwd = streebog(pwd), as per HMAC specifications. */
	if (pwd_len > STREEBOG_BLOCKSIZE)
	{
		STREEBOG_CTX tctx;

		STREEBOG_init (&tctx);
		STREEBOG_add (&tctx, pwd, pwd_len);
		STREEBOG_finalize (&tctx, key);

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
		buf[b] = (unsigned char) (pwd[b] ^ 0x36);
	memset (&buf[pwd_len], 0x36, STREEBOG_BLOCKSIZE - pwd_len);

	STREEBOG_add (ctx, buf, STREEBOG_BLOCKSIZE);

	/**** Precompute HMAC Outer Digest ****/

	ctx = &(hmac.outer_digest_ctx);
	STREEBOG_init (ctx);

	for (b = 0; b < pwd_len; ++b)
		buf[b] = (unsigned char) (pwd[b] ^ 0x5C);
	memset (&buf[pwd_len], 0x5C, STREEBOG_BLOCKSIZE - pwd_len);

	STREEBOG_add (ctx, buf, STREEBOG_BLOCKSIZE);

	/* first l - 1 blocks */
	for (b = 1; b < l; b++)
	{
		derive_u_streebog (salt, salt_len, iterations, b, &hmac, pAbortKeyDerivation);
		// Check if the derivation was aborted
		if (pAbortKeyDerivation && *pAbortKeyDerivation)
			goto cancelled;
		memcpy (dk, hmac.u, STREEBOG_DIGESTSIZE);
		dk += STREEBOG_DIGESTSIZE;
	}

	/* last block */
	derive_u_streebog (salt, salt_len, iterations, b, &hmac, pAbortKeyDerivation);
	// Check if the derivation was aborted (in case of only one block)
	if (pAbortKeyDerivation && *pAbortKeyDerivation)
		goto cancelled;
	memcpy (dk, hmac.u, r);
cancelled:
	/* Prevent possible leaks. */
	burn (&hmac, sizeof(hmac));
	burn (key, sizeof(key));
}

wchar_t *get_kdf_name (int kdf_id)
{
	switch (kdf_id)
	{
	case SHA512:	
		return L"SHA512-PBKDF2";

	case SHA256:	
		return L"SHA256-PBKDF2";

	case BLAKE2S:	
		return L"BLAKE2S-PBKDF2";

	case WHIRLPOOL:	
		return L"Whirlpool-PBKDF2";

	case STREEBOG:
		return L"STREEBOG-PBKDF2";

	case ARGON2:
		return L"Argon2";

	default:		
		return L"(Unknown)";
	}
}



int get_pkcs5_iteration_count(int pkcs5_prf_id, int pim, BOOL bBoot, int* pMemoryCost)
{
	int iteration_count = 0;
	*pMemoryCost = 0;

	if (pim >= 0)
	{
		switch (pkcs5_prf_id)
		{
		case BLAKE2S:
			if (pim == 0)
				iteration_count = bBoot ? 200000 : 500000;
			else
				iteration_count = bBoot ? pim * 2048 : 15000 + pim * 1000;
			break;

		case SHA512:
			iteration_count = (pim == 0) ? 500000 : 15000 + pim * 1000;
			break;

		case WHIRLPOOL:
			iteration_count = (pim == 0) ? 500000 : 15000 + pim * 1000;
			break;

		case SHA256:
			if (pim == 0)
				iteration_count = bBoot ? 200000 : 500000;
			else
				iteration_count = bBoot ? pim * 2048 : 15000 + pim * 1000;
			break;

		case STREEBOG:
			if (pim == 0)
				iteration_count = bBoot ? 200000 : 500000;
			else
				iteration_count = bBoot ? pim * 2048 : 15000 + pim * 1000;
			break;

		case ARGON2:
			get_argon2_params (pim, &iteration_count, pMemoryCost);
			break;

		default:
			TC_THROW_FATAL_EXCEPTION; // Unknown/wrong ID
		}
	}

	return iteration_count;
}

int is_pkcs5_prf_supported (int pkcs5_prf_id, PRF_BOOT_TYPE bootType)
{
   if (pkcs5_prf_id == 0) // auto-detection always supported
      return 1;

   if (  (bootType == PRF_BOOT_MBR && pkcs5_prf_id != BLAKE2S && pkcs5_prf_id != SHA256)
		|| (bootType != PRF_BOOT_MBR && (pkcs5_prf_id < FIRST_PRF_ID || pkcs5_prf_id > LAST_PRF_ID))
		)
      return 0;
   // we don't support Argon2 in pre-boot authentication
   if ((bootType == PRF_BOOT_MBR || bootType == PRF_BOOT_GPT) && pkcs5_prf_id == ARGON2)
      return 0;	
   return 1;

}

void derive_key_argon2(const unsigned char *pwd, int pwd_len, const unsigned char *salt, int salt_len, uint32 iterations, uint32 memcost, unsigned char *dk, int dklen, volatile long *pAbortKeyDerivation)
{
#if defined (DEVICE_DRIVER) && !defined(_M_ARM64)
	NTSTATUS saveStatus = STATUS_INVALID_PARAMETER;
	XSTATE_SAVE SaveState;
	if (HasSAVX2())
		saveStatus = KeSaveExtendedProcessorState(XSTATE_MASK_GSSE, &SaveState);
#endif
	if (0 != argon2id_hash_raw(
		iterations, // number of iterations
		memcost, // memory cost in KiB
		1, // parallelism factor (number of threads)
		pwd, pwd_len, // password and its length
		salt, salt_len, // salt and its length
		dk, dklen,// derived key and its length
		pAbortKeyDerivation 
	))
	{
		// If the Argon2 derivation fails, we fill the derived key with zeroes
		memset(dk, 0, dklen);
	}
#if defined (DEVICE_DRIVER) && !defined(_M_ARM64)
	if (NT_SUCCESS(saveStatus))
		KeRestoreExtendedProcessorState(&SaveState);
#endif
}

/**
 * get_argon2_params
 * 
 * This function calculates the memory cost (in KiB) and time cost (iterations) for 
 * the Argon2id key derivation function based on the Personal Iteration Multiplier (PIM) value.
 * 
 * Parameters:
 *   - pim: The Personal Iteration Multiplier (PIM), which controls the memory and time costs.
 *          If pim < 0, it is clamped to 0.
 *          If pim == 0, the default value of 12 is used.
 *   - pIterations: Pointer to an integer where the calculated time cost (iterations) will be stored.
 *   - pMemcost: Pointer to an integer where the calculated memory cost (in KiB) will be stored.
 * 
 * Formulas:
 *   - Memory Cost (m_cost) in MiB:
 *     m_cost(pim) = min(64 MiB + (pim - 1) * 32 MiB, 1024 MiB)
 *     This formula increases the memory cost by 32 MiB for each increment of PIM, starting from 64 MiB.
 *     The memory cost is capped at 1024 MiB when PIM reaches 31 or higher.
 *     The result is converted to KiB before being stored in *pMemcost:
 *     *pMemcost = m_cost(pim) * 1024
 * 
 *   - Time Cost (t_cost) in iterations:
 *     If PIM <= 31:
 *        t_cost(pim) = 3 + floor((pim - 1) / 3)
 *     If PIM > 31:
 *        t_cost(pim) = 13 + (pim - 31)
 *     This formula increases the time cost by 1 iteration for every 3 increments of PIM when PIM <= 31.
 *     For PIM > 31, the time cost increases by 1 iteration for each increment in PIM.
 *     The calculated time cost is stored in *pIterations.
 * 
 * Example:
 *   - For PIM = 12:
 *     Memory Cost = 64 + (12 - 1) * 32 = 416 MiB (425,984 KiB)
 *     Time Cost = 3 + floor((12 - 1) / 3) = 6 iterations
 * 
 *   - For PIM = 31:
 *     Memory Cost = 64 + (31 - 1) * 32 = 1024 MiB (capped)
 *     Time Cost = 3 + floor((31 - 1) / 3) = 13 iterations
 * 
 *   - For PIM = 32:
 *     Memory Cost = 1024 MiB (capped)
 *     Time Cost = 13 + (32 - 31) = 14 iterations
 * 
 */
void get_argon2_params(int pim, int* pIterations, int* pMemcost)
{
    // Ensure PIM is at least 0
    if (pim < 0)
    {
        pim = 0;
    }

	// Default PIM value is 12
	// which leads to 416 MiB memory cost and 6 iterations
	if (pim == 0)
	{
		pim = 12;
	}

    // Compute the memory cost (m_cost) in MiB
    int m_cost_mib = 64 + (pim - 1) * 32;

    // Cap the memory cost at 1024 MiB
    if (m_cost_mib > 1024)
    {
        m_cost_mib = 1024;
    }

    // Convert memory cost to KiB for Argon2
    *pMemcost = m_cost_mib * 1024; // m_cost in KiB

    // Compute the time cost (t_cost)
    if (pim <= 31)
    {
        *pIterations = 3 + ((pim - 1) / 3);
    }
    else
    {
        *pIterations = 13 + (pim - 31);
    }
}

#endif //!TC_WINDOWS_BOOT
