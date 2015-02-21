/*
 Legal Notice: Some portions of the source code contained in this file were
 derived from the source code of Encryption for the Masses 2.02a, which is
 Copyright (c) 1998-2000 Paul Le Roux and which is governed by the 'License
 Agreement for Encryption for the Masses'. Modifications and additions to
 the original source code (contained in this file) and all other portions
 of this file are Copyright (c) 2003-2009 TrueCrypt Developers Association
 and are governed by the TrueCrypt License 3.0 the full text of which is
 contained in the file License.txt included in TrueCrypt binary and source
 code distribution packages. */

#include "Tcdefs.h"

#include <memory.h>
#include "Rmd160.h"
#ifndef TC_WINDOWS_BOOT
#include "Sha2.h"
#include "Whirlpool.h"
#else
#include "Sha2Small.h"
#endif
#include "Pkcs5.h"
#include "Crypto.h"

void hmac_truncate
  (
	  char *d1,		/* data to be truncated */
	  char *d2,		/* truncated data */
	  int len		/* length in bytes to keep */
)
{
	int i;
	for (i = 0; i < len; i++)
		d2[i] = d1[i];
}

#if !defined(TC_WINDOWS_BOOT) || defined(TC_WINDOWS_BOOT_SHA2)

typedef struct hmac_sha256_ctx_struct
{
	sha256_ctx ctx;
	char buf[SHA256_BLOCKSIZE];
	char k[PKCS5_SALT_SIZE + 4]; /* enough to hold (salt_len + 4) and also the SHA256 hash */
	char u[SHA256_DIGESTSIZE];
} hmac_sha256_ctx;

void hmac_sha256_internal
(
	  char *k,		/* secret key. It's ensured to be always <= 32 bytes */
	  int lk,		/* length of the key in bytes */
	  char *d,		/* input data. d pointer is guaranteed to be at least 32-bytes long */
	  int ld,		/* length of input data in bytes */
	  hmac_sha256_ctx* hmac /* HMAC-SHA256 context which holds temporary variables */
)
{
	int i;
	sha256_ctx* ctx = &(hmac->ctx);
	char* buf = hmac->buf;

	/**** Inner Digest ****/

	sha256_begin (ctx);

	/* Pad the key for inner digest */
	for (i = 0; i < lk; ++i)
		buf[i] = (char) (k[i] ^ 0x36);
	for (i = lk; i < SHA256_BLOCKSIZE; ++i)
		buf[i] = 0x36;

	sha256_hash ((unsigned char *) buf, SHA256_BLOCKSIZE, ctx);
	sha256_hash ((unsigned char *) d, ld, ctx);

	sha256_end ((unsigned char *) d, ctx); /* d = inner digest */

	/**** Outer Digest ****/

	sha256_begin (ctx);

	for (i = 0; i < lk; ++i)
		buf[i] = (char) (k[i] ^ 0x5C);
	for (i = lk; i < SHA256_BLOCKSIZE; ++i)
		buf[i] = 0x5C;

	sha256_hash ((unsigned char *) buf, SHA256_BLOCKSIZE, ctx);
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
	char key[SHA256_DIGESTSIZE];
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
	hmac_sha256_internal(k, lk, d, ld, &hmac);
	/* Prevent leaks */
	burn(&hmac, sizeof(hmac));
	burn(key, sizeof(key));
}
#endif

static void derive_u_sha256 (char *pwd, int pwd_len, char *salt, int salt_len, int iterations, int b, hmac_sha256_ctx* hmac)
{
	char* k = hmac->k;
	char* u = hmac->u;
	uint32 c;
	int i;	

#ifdef TC_WINDOWS_BOOT
	/* In bootloader, iterations is a boolean : TRUE for boot derivation mode, FALSE otherwise 
	 * This enables us to save code space needed for implementing other features.
	 */
	if (iterations)
		c = 200000;
	else
		c = 500000;
#else
	c = iterations;
#endif

	/* iteration 1 */
	memcpy (k, salt, salt_len);	/* salt */
	
	/* big-endian block number */
	memset (&k[salt_len], 0, 3);
	k[salt_len + 3] = (char) b;

	hmac_sha256_internal (pwd, pwd_len, k, salt_len + 4, hmac);
	memcpy (u, k, SHA256_DIGESTSIZE);

	/* remaining iterations */
	while (c > 1)
	{
		hmac_sha256_internal (pwd, pwd_len, k, SHA256_DIGESTSIZE, hmac);
		for (i = 0; i < SHA256_DIGESTSIZE; i++)
		{
			u[i] ^= k[i];
		}
		c--;
	}
}


void derive_key_sha256 (char *pwd, int pwd_len, char *salt, int salt_len, int iterations, char *dk, int dklen)
{	
	hmac_sha256_ctx hmac;
	int b, l, r;
#ifndef TC_WINDOWS_BOOT
	char key[SHA256_DIGESTSIZE];
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

	/* first l - 1 blocks */
	for (b = 1; b < l; b++)
	{
		derive_u_sha256 (pwd, pwd_len, salt, salt_len, iterations, b, &hmac);
		memcpy (dk, hmac.u, SHA256_DIGESTSIZE);
		dk += SHA256_DIGESTSIZE;
	}

	/* last block */
	derive_u_sha256 (pwd, pwd_len, salt, salt_len, iterations, b, &hmac);
	memcpy (dk, hmac.u, r);


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
	char buf[SHA512_BLOCKSIZE];
	char k[PKCS5_SALT_SIZE + 4]; /* enough to hold (salt_len + 4) and also the SHA512 hash */
	char u[SHA512_DIGESTSIZE];
} hmac_sha512_ctx;

void hmac_sha512_internal
(
	  char *k,		/* secret key */
	  int lk,		/* length of the key in bytes */
	  char *d,		/* data and also output buffer of at least 64 bytes */
	  int ld,			/* length of data in bytes */
	  hmac_sha512_ctx* hmac
)
{
	sha512_ctx* ctx = &(hmac->ctx);
	char* buf = hmac->buf;
	int i;

	/**** Inner Digest ****/

	sha512_begin (ctx);

	/* Pad the key for inner digest */
	for (i = 0; i < lk; ++i)
		buf[i] = (char) (k[i] ^ 0x36);
	for (i = lk; i < SHA512_BLOCKSIZE; ++i)
		buf[i] = 0x36;

	sha512_hash ((unsigned char *) buf, SHA512_BLOCKSIZE, ctx);
	sha512_hash ((unsigned char *) d, ld, ctx);

	sha512_end ((unsigned char *) d, ctx);

	/**** Outer Digest ****/

	sha512_begin (ctx);

	for (i = 0; i < lk; ++i)
		buf[i] = (char) (k[i] ^ 0x5C);
	for (i = lk; i < SHA512_BLOCKSIZE; ++i)
		buf[i] = 0x5C;

	sha512_hash ((unsigned char *) buf, SHA512_BLOCKSIZE, ctx);
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
	char key[SHA512_DIGESTSIZE];

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

	hmac_sha512_internal (k, lk, d, ld, &hmac);

	/* Prevent leaks */
	burn (&hmac, sizeof(hmac));
	burn (key, sizeof(key));
}

static void derive_u_sha512 (char *pwd, int pwd_len, char *salt, int salt_len, int iterations, int b, hmac_sha512_ctx* hmac)
{
	char* k = hmac->k;
	char* u = hmac->u;
	int c, i;

	/* iteration 1 */
	memcpy (k, salt, salt_len);	/* salt */
	/* big-endian block number */
	memset (&k[salt_len], 0, 3);
	k[salt_len + 3] = (char) b;

	hmac_sha512_internal (pwd, pwd_len, k, salt_len + 4, hmac);
	memcpy (u, k, SHA512_DIGESTSIZE);

	/* remaining iterations */
	for (c = 1; c < iterations; c++)
	{
		hmac_sha512_internal (pwd, pwd_len, k, SHA512_DIGESTSIZE, hmac);
		for (i = 0; i < SHA512_DIGESTSIZE; i++)
		{
			u[i] ^= k[i];
		}
	}
}


void derive_key_sha512 (char *pwd, int pwd_len, char *salt, int salt_len, int iterations, char *dk, int dklen)
{
	hmac_sha512_ctx hmac;
	int b, l, r;
	char key[SHA512_DIGESTSIZE];

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

	/* first l - 1 blocks */
	for (b = 1; b < l; b++)
	{
		derive_u_sha512 (pwd, pwd_len, salt, salt_len, iterations, b, &hmac);
		memcpy (dk, hmac.u, SHA512_DIGESTSIZE);
		dk += SHA512_DIGESTSIZE;
	}

	/* last block */
	derive_u_sha512 (pwd, pwd_len, salt, salt_len, iterations, b, &hmac);
	memcpy (dk, hmac.u, r);


	/* Prevent possible leaks. */
	burn (&hmac, sizeof(hmac));
	burn (key, sizeof(key));
}

#endif // TC_WINDOWS_BOOT

#if !defined(TC_WINDOWS_BOOT) || defined(TC_WINDOWS_BOOT_RIPEMD160)

typedef struct hmac_ripemd160_ctx_struct
{
	RMD160_CTX context;
	char k_pad[65];
	char k[PKCS5_SALT_SIZE + 4]; /* enough to hold (salt_len + 4) and also the RIPEMD-160 hash */
	char u[RIPEMD160_DIGESTSIZE];
} hmac_ripemd160_ctx;

void hmac_ripemd160_internal (char *key, int keylen, char *input_digest, int len, hmac_ripemd160_ctx* hmac)
{
	RMD160_CTX* context = &(hmac->context);
   unsigned char* k_pad = hmac->k_pad;  /* inner/outer padding - key XORd with ipad */
   int i;

	/*

	RMD160(K XOR opad, RMD160(K XOR ipad, text))

	where K is an n byte key
	ipad is the byte 0x36 repeated RIPEMD160_BLOCKSIZE times
	opad is the byte 0x5c repeated RIPEMD160_BLOCKSIZE times
	and text is the data being protected */


	/* start out by storing key in pads */
	memset(k_pad, 0x36, 65);

    /* XOR key with ipad and opad values */
    for (i=0; i<keylen; i++) 
	{
        k_pad[i] ^= key[i];
    }

    /* perform inner RIPEMD-160 */

    RMD160Init(context);           /* init context for 1st pass */
    RMD160Update(context, k_pad, RIPEMD160_BLOCKSIZE);  /* start with inner pad */
    RMD160Update(context, (const unsigned char *) input_digest, len); /* then text of datagram */
    RMD160Final((unsigned char *) input_digest, context);         /* finish up 1st pass */

    /* perform outer RIPEMD-160 */
    memset(k_pad, 0x5c, 65);
    for (i=0; i<keylen; i++) 
	 {
        k_pad[i] ^= key[i];
    }

    RMD160Init(context);           /* init context for 2nd pass */
    RMD160Update(context, k_pad, RIPEMD160_BLOCKSIZE);  /* start with outer pad */
    /* results of 1st hash */
    RMD160Update(context, (const unsigned char *) input_digest, RIPEMD160_DIGESTSIZE);
    RMD160Final((unsigned char *) input_digest, context);         /* finish up 2nd pass */
}

#ifndef TC_WINDOWS_BOOT
void hmac_ripemd160 (char *key, int keylen, char *input_digest, int len)
{
	hmac_ripemd160_ctx hmac;
	unsigned char tk[RIPEMD160_DIGESTSIZE];

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

	hmac_ripemd160_internal (key, keylen, input_digest, len, &hmac);

	burn (&hmac, sizeof(hmac));
	burn (tk, sizeof(tk));
}
#endif


static void derive_u_ripemd160 (char *pwd, int pwd_len, char *salt, int salt_len, int iterations, int b, hmac_ripemd160_ctx* hmac)
{
	char* k = hmac->k;
	char* u = hmac->u;
	uint32 c;
	int i;

#ifdef TC_WINDOWS_BOOT
	/* In bootloader, iterations is a boolean : TRUE for boot derivation mode, FALSE otherwise 
	 * This enables us to save code space needed for implementing other features.
	 */
	if (iterations)
		c = 327661;
	else
		c = 655331;
#else
	c  = iterations;
#endif

	/* iteration 1 */
	memcpy (k, salt, salt_len);	/* salt */
	
	/* big-endian block number */
	memset (&k[salt_len], 0, 3);
	k[salt_len + 3] = (char) b;

	hmac_ripemd160_internal (pwd, pwd_len, k, salt_len + 4, hmac);
	memcpy (u, k, RIPEMD160_DIGESTSIZE);

	/* remaining iterations */
	while ( c > 1)
	{
		hmac_ripemd160_internal (pwd, pwd_len, k, RIPEMD160_DIGESTSIZE, hmac);
		for (i = 0; i < RIPEMD160_DIGESTSIZE; i++)
		{
			u[i] ^= k[i];
		}
		c--;
	}
}

void derive_key_ripemd160 (char *pwd, int pwd_len, char *salt, int salt_len, int iterations, char *dk, int dklen)
{	
	int b, l, r;
	hmac_ripemd160_ctx hmac;
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

	/* first l - 1 blocks */
	for (b = 1; b < l; b++)
	{
		derive_u_ripemd160 (pwd, pwd_len, salt, salt_len, iterations, b, &hmac);
		memcpy (dk, hmac.u, RIPEMD160_DIGESTSIZE);
		dk += RIPEMD160_DIGESTSIZE;
	}

	/* last block */
	derive_u_ripemd160 (pwd, pwd_len, salt, salt_len, iterations, b, &hmac);
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
	char buf[WHIRLPOOL_BLOCKSIZE];
	char k[PKCS5_SALT_SIZE + 4]; /* enough to hold (salt_len + 4) and also the Whirlpool hash */
	char u[WHIRLPOOL_DIGESTSIZE];
} hmac_whirlpool_ctx;

void hmac_whirlpool_internal
(
	  char *k,		/* secret key */
	  int lk,		/* length of the key in bytes */
	  char *d,		/* input/output data. d pointer is guaranteed to be at least 64-bytes long */
	  int ld,		/* length of input data in bytes */
	  hmac_whirlpool_ctx* hmac /* HMAC-Whirlpool context which holds temporary variables */
)
{
	WHIRLPOOL_CTX* ctx = &(hmac->ctx);
	char* buf = hmac->buf;
	int i;

	/**** Inner Digest ****/

	WHIRLPOOL_init (ctx);

	/* Pad the key for inner digest */
	for (i = 0; i < lk; ++i)
		buf[i] = (char) (k[i] ^ 0x36);
	for (i = lk; i < WHIRLPOOL_BLOCKSIZE; ++i)
		buf[i] = 0x36;

	WHIRLPOOL_add ((unsigned char *) buf, WHIRLPOOL_BLOCKSIZE * 8, ctx);
	WHIRLPOOL_add ((unsigned char *) d, ld * 8, ctx);

	WHIRLPOOL_finalize (ctx, (unsigned char *) d);

	/**** Outer Digest ****/

	WHIRLPOOL_init (ctx);

	for (i = 0; i < lk; ++i)
		buf[i] = (char) (k[i] ^ 0x5C);
	for (i = lk; i < WHIRLPOOL_BLOCKSIZE; ++i)
		buf[i] = 0x5C;

	WHIRLPOOL_add ((unsigned char *) buf, WHIRLPOOL_BLOCKSIZE * 8, ctx);
	WHIRLPOOL_add ((unsigned char *) d, WHIRLPOOL_DIGESTSIZE * 8, ctx);

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
	char key[WHIRLPOOL_DIGESTSIZE];
    /* If the key is longer than the hash algorithm block size,
	   let key = whirlpool(key), as per HMAC specifications. */
	if (lk > WHIRLPOOL_BLOCKSIZE)
	{
		WHIRLPOOL_CTX tctx;

		WHIRLPOOL_init (&tctx);
		WHIRLPOOL_add ((unsigned char *) k, lk * 8, &tctx);
		WHIRLPOOL_finalize (&tctx, (unsigned char *) key);

		k = key;
		lk = WHIRLPOOL_DIGESTSIZE;

		burn (&tctx, sizeof(tctx));		// Prevent leaks
	}

	hmac_whirlpool_internal(k, lk, d, ld, &hmac);
	/* Prevent leaks */
	burn(&hmac, sizeof(hmac));
}

static void derive_u_whirlpool (char *pwd, int pwd_len, char *salt, int salt_len, int iterations, int b, hmac_whirlpool_ctx* hmac)
{
	char* u = hmac->u;
	char* k = hmac->k;
	int c, i;

	/* iteration 1 */
	memcpy (k, salt, salt_len);	/* salt */
	/* big-endian block number */
	memset (&k[salt_len], 0, 3);	
	k[salt_len + 3] = (char) b;

	hmac_whirlpool_internal (pwd, pwd_len, k, salt_len + 4, hmac);
	memcpy (u, k, WHIRLPOOL_DIGESTSIZE);

	/* remaining iterations */
	for (c = 1; c < iterations; c++)
	{
		hmac_whirlpool_internal (pwd, pwd_len, k, WHIRLPOOL_DIGESTSIZE, hmac);
		for (i = 0; i < WHIRLPOOL_DIGESTSIZE; i++)
		{
			u[i] ^= k[i];
		}
	}
}

void derive_key_whirlpool (char *pwd, int pwd_len, char *salt, int salt_len, int iterations, char *dk, int dklen)
{
	hmac_whirlpool_ctx hmac;
	char key[WHIRLPOOL_DIGESTSIZE];
	int b, l, r;
    /* If the password is longer than the hash algorithm block size,
	   let pwd = whirlpool(pwd), as per HMAC specifications. */
	if (pwd_len > WHIRLPOOL_BLOCKSIZE)
	{
		WHIRLPOOL_CTX tctx;

		WHIRLPOOL_init (&tctx);
		WHIRLPOOL_add ((unsigned char *) pwd, pwd_len * 8, &tctx);
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

	/* first l - 1 blocks */
	for (b = 1; b < l; b++)
	{
		derive_u_whirlpool (pwd, pwd_len, salt, salt_len, iterations, b, &hmac);
		memcpy (dk, hmac.u, WHIRLPOOL_DIGESTSIZE);
		dk += WHIRLPOOL_DIGESTSIZE;
	}

	/* last block */
	derive_u_whirlpool (pwd, pwd_len, salt, salt_len, iterations, b, &hmac);
	memcpy (dk, hmac.u, r);


	/* Prevent possible leaks. */
	burn (&hmac, sizeof(hmac));
	burn (key, sizeof(key));
}


char *get_pkcs5_prf_name (int pkcs5_prf_id)
{
	switch (pkcs5_prf_id)
	{
	case SHA512:	
		return "HMAC-SHA-512";

	case SHA256:	
		return "HMAC-SHA-256";

	case RIPEMD160:	
		return "HMAC-RIPEMD-160";

	case WHIRLPOOL:	
		return "HMAC-Whirlpool";

	default:		
		return "(Unknown)";
	}
}



int get_pkcs5_iteration_count (int pkcs5_prf_id, BOOL truecryptMode, BOOL bBoot)
{
	switch (pkcs5_prf_id)
	{

	case RIPEMD160:	
		if (truecryptMode)
			return bBoot ? 1000 : 2000;
		else
			return bBoot? 327661 : 655331;

	case SHA512:	
		return truecryptMode? 1000 : 500000;

	case WHIRLPOOL:	
		return truecryptMode? 1000 : 500000;

	case SHA256:
		if (truecryptMode)
			return 0; // SHA-256 not supported by TrueCrypt
		else
			return bBoot? 200000 : 500000;

	default:		
		TC_THROW_FATAL_EXCEPTION;	// Unknown/wrong ID
	}
	return 0;
}

#endif //!TC_WINDOWS_BOOT
