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

#ifndef TC_WINDOWS_BOOT

void hmac_sha512
(
	  char *k,		/* secret key */
	  int lk,		/* length of the key in bytes */
	  char *d,		/* data */
	  int ld,		/* length of data in bytes */
	  char *out,		/* output buffer, at least "t" bytes */
	  int t
)
{
	sha512_ctx ictx, octx;
	char isha[SHA512_DIGESTSIZE], osha[SHA512_DIGESTSIZE];
	char key[SHA512_DIGESTSIZE];
	char buf[SHA512_BLOCKSIZE];
	int i;

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

	/**** Inner Digest ****/

	sha512_begin (&ictx);

	/* Pad the key for inner digest */
	for (i = 0; i < lk; ++i)
		buf[i] = (char) (k[i] ^ 0x36);
	for (i = lk; i < SHA512_BLOCKSIZE; ++i)
		buf[i] = 0x36;

	sha512_hash ((unsigned char *) buf, SHA512_BLOCKSIZE, &ictx);
	sha512_hash ((unsigned char *) d, ld, &ictx);

	sha512_end ((unsigned char *) isha, &ictx);

	/**** Outer Digest ****/

	sha512_begin (&octx);

	for (i = 0; i < lk; ++i)
		buf[i] = (char) (k[i] ^ 0x5C);
	for (i = lk; i < SHA512_BLOCKSIZE; ++i)
		buf[i] = 0x5C;

	sha512_hash ((unsigned char *) buf, SHA512_BLOCKSIZE, &octx);
	sha512_hash ((unsigned char *) isha, SHA512_DIGESTSIZE, &octx);

	sha512_end ((unsigned char *) osha, &octx);

	/* truncate and print the results */
	t = t > SHA512_DIGESTSIZE ? SHA512_DIGESTSIZE : t;
	hmac_truncate (osha, out, t);

	/* Prevent leaks */
	burn (&ictx, sizeof(ictx));
	burn (&octx, sizeof(octx));
	burn (isha, sizeof(isha));
	burn (osha, sizeof(osha));
	burn (buf, sizeof(buf));
	burn (key, sizeof(key));
}


void derive_u_sha512 (char *pwd, int pwd_len, char *salt, int salt_len, int iterations, char *u, int b)
{
	char j[SHA512_DIGESTSIZE], k[SHA512_DIGESTSIZE];
	char init[128];
	char counter[4];
	int c, i;

	/* iteration 1 */
	memset (counter, 0, 4);
	counter[3] = (char) b;
	memcpy (init, salt, salt_len);	/* salt */
	memcpy (&init[salt_len], counter, 4);	/* big-endian block number */
	hmac_sha512 (pwd, pwd_len, init, salt_len + 4, j, SHA512_DIGESTSIZE);
	memcpy (u, j, SHA512_DIGESTSIZE);

	/* remaining iterations */
	for (c = 1; c < iterations; c++)
	{
		hmac_sha512 (pwd, pwd_len, j, SHA512_DIGESTSIZE, k, SHA512_DIGESTSIZE);
		for (i = 0; i < SHA512_DIGESTSIZE; i++)
		{
			u[i] ^= k[i];
			j[i] = k[i];
		}
	}

	/* Prevent possible leaks. */
	burn (j, sizeof(j));
	burn (k, sizeof(k));
}


void derive_key_sha512 (char *pwd, int pwd_len, char *salt, int salt_len, int iterations, char *dk, int dklen)
{
	char u[SHA512_DIGESTSIZE];
	int b, l, r;

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
		derive_u_sha512 (pwd, pwd_len, salt, salt_len, iterations, u, b);
		memcpy (dk, u, SHA512_DIGESTSIZE);
		dk += SHA512_DIGESTSIZE;
	}

	/* last block */
	derive_u_sha512 (pwd, pwd_len, salt, salt_len, iterations, u, b);
	memcpy (dk, u, r);


	/* Prevent possible leaks. */
	burn (u, sizeof(u));
}

#endif // TC_WINDOWS_BOOT

void hmac_ripemd160 (char *key, int keylen, char *input, int len, char *digest)
{
    RMD160_CTX context;
    unsigned char k_ipad[65];  /* inner padding - key XORd with ipad */
    unsigned char k_opad[65];  /* outer padding - key XORd with opad */
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

	/*

	RMD160(K XOR opad, RMD160(K XOR ipad, text))

	where K is an n byte key
	ipad is the byte 0x36 repeated RIPEMD160_BLOCKSIZE times
	opad is the byte 0x5c repeated RIPEMD160_BLOCKSIZE times
	and text is the data being protected */


	/* start out by storing key in pads */
	memset(k_ipad, 0x36, sizeof(k_ipad));
    memset(k_opad, 0x5c, sizeof(k_opad));

    /* XOR key with ipad and opad values */
    for (i=0; i<keylen; i++) 
	{
        k_ipad[i] ^= key[i];
        k_opad[i] ^= key[i];
    }

    /* perform inner RIPEMD-160 */

    RMD160Init(&context);           /* init context for 1st pass */
    RMD160Update(&context, k_ipad, RIPEMD160_BLOCKSIZE);  /* start with inner pad */
    RMD160Update(&context, (const unsigned char *) input, len); /* then text of datagram */
    RMD160Final((unsigned char *) digest, &context);         /* finish up 1st pass */

    /* perform outer RIPEMD-160 */
    RMD160Init(&context);           /* init context for 2nd pass */
    RMD160Update(&context, k_opad, RIPEMD160_BLOCKSIZE);  /* start with outer pad */
    /* results of 1st hash */
    RMD160Update(&context, (const unsigned char *) digest, RIPEMD160_DIGESTSIZE);
    RMD160Final((unsigned char *) digest, &context);         /* finish up 2nd pass */

	/* Prevent possible leaks. */
    burn (k_ipad, sizeof(k_ipad));
    burn (k_opad, sizeof(k_opad));
	burn (tk, sizeof(tk));
	burn (&context, sizeof(context));
}

void derive_u_ripemd160 (BOOL bNotTest, char *pwd, int pwd_len, char *salt, int salt_len, int iterations, char *u, int b)
{
	char j[RIPEMD160_DIGESTSIZE], k[RIPEMD160_DIGESTSIZE];
	char init[128];
	char counter[4];
	int c, i, l;
   int EnhanceSecurityLoops = (bNotTest)? 20 : 1;

	/* iteration 1 */
	memset (counter, 0, 4);
	counter[3] = (char) b;
	memcpy (init, salt, salt_len);	/* salt */
	memcpy (&init[salt_len], counter, 4);	/* big-endian block number */
	hmac_ripemd160 (pwd, pwd_len, init, salt_len + 4, j);
	memcpy (u, j, RIPEMD160_DIGESTSIZE);

	/* remaining iterations */
	for (l = 0; l < EnhanceSecurityLoops; l++)
	{
		for (c = 1; c < iterations; c++)
		{
			hmac_ripemd160 (pwd, pwd_len, j, RIPEMD160_DIGESTSIZE, k);
			for (i = 0; i < RIPEMD160_DIGESTSIZE; i++)
			{
				u[i] ^= k[i];
				j[i] = k[i];
			}
		}
	}

   /* add extra 10 loops to ensure backward compatibilty with the previous count (327661 for boot, 655331 for normal) */
   if (iterations == 32767)
   {
      /* case of normal partition : add 10 iterations to have a total of 655331 = (32767 - 1)*20 + 1 + 10 */
		for (c = 0; c < 10; c++)
		{
			hmac_ripemd160 (pwd, pwd_len, j, RIPEMD160_DIGESTSIZE, k);
			for (i = 0; i < RIPEMD160_DIGESTSIZE; i++)
			{
				u[i] ^= k[i];
				j[i] = k[i];
			}
		}
   }

	/* Prevent possible leaks. */
	burn (j, sizeof(j));
	burn (k, sizeof(k));
}

void derive_key_ripemd160 (BOOL bNotTest, char *pwd, int pwd_len, char *salt, int salt_len, int iterations, char *dk, int dklen)
{
	char u[RIPEMD160_DIGESTSIZE];
	int b, l, r;

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
		derive_u_ripemd160 (bNotTest, pwd, pwd_len, salt, salt_len, iterations, u, b);
		memcpy (dk, u, RIPEMD160_DIGESTSIZE);
		dk += RIPEMD160_DIGESTSIZE;
	}

	/* last block */
	derive_u_ripemd160 (bNotTest, pwd, pwd_len, salt, salt_len, iterations, u, b);
	memcpy (dk, u, r);


	/* Prevent possible leaks. */
	burn (u, sizeof(u));
}

#ifndef TC_WINDOWS_BOOT

void hmac_whirlpool
(
	  char *k,		/* secret key */
	  int lk,		/* length of the key in bytes */
	  char *d,		/* data */
	  int ld,		/* length of data in bytes */
	  char *out,	/* output buffer, at least "t" bytes */
	  int t
)
{
	WHIRLPOOL_CTX ictx, octx;
	char iwhi[WHIRLPOOL_DIGESTSIZE], owhi[WHIRLPOOL_DIGESTSIZE];
	char key[WHIRLPOOL_DIGESTSIZE];
	char buf[WHIRLPOOL_BLOCKSIZE];
	int i;

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

	/**** Inner Digest ****/

	WHIRLPOOL_init (&ictx);

	/* Pad the key for inner digest */
	for (i = 0; i < lk; ++i)
		buf[i] = (char) (k[i] ^ 0x36);
	for (i = lk; i < WHIRLPOOL_BLOCKSIZE; ++i)
		buf[i] = 0x36;

	WHIRLPOOL_add ((unsigned char *) buf, WHIRLPOOL_BLOCKSIZE * 8, &ictx);
	WHIRLPOOL_add ((unsigned char *) d, ld * 8, &ictx);

	WHIRLPOOL_finalize (&ictx, (unsigned char *) iwhi);

	/**** Outer Digest ****/

	WHIRLPOOL_init (&octx);

	for (i = 0; i < lk; ++i)
		buf[i] = (char) (k[i] ^ 0x5C);
	for (i = lk; i < WHIRLPOOL_BLOCKSIZE; ++i)
		buf[i] = 0x5C;

	WHIRLPOOL_add ((unsigned char *) buf, WHIRLPOOL_BLOCKSIZE * 8, &octx);
	WHIRLPOOL_add ((unsigned char *) iwhi, WHIRLPOOL_DIGESTSIZE * 8, &octx);

	WHIRLPOOL_finalize (&octx, (unsigned char *) owhi);

	/* truncate and print the results */
	t = t > WHIRLPOOL_DIGESTSIZE ? WHIRLPOOL_DIGESTSIZE : t;
	hmac_truncate (owhi, out, t);

	/* Prevent possible leaks. */
	burn (&ictx, sizeof(ictx));
	burn (&octx, sizeof(octx));
	burn (owhi, sizeof(owhi));
	burn (iwhi, sizeof(iwhi));
	burn (buf, sizeof(buf));
	burn (key, sizeof(key));
}

void derive_u_whirlpool (char *pwd, int pwd_len, char *salt, int salt_len, int iterations, char *u, int b)
{
	char j[WHIRLPOOL_DIGESTSIZE], k[WHIRLPOOL_DIGESTSIZE];
	char init[128];
	char counter[4];
	int c, i;

	/* iteration 1 */
	memset (counter, 0, 4);
	counter[3] = (char) b;
	memcpy (init, salt, salt_len);	/* salt */
	memcpy (&init[salt_len], counter, 4);	/* big-endian block number */
	hmac_whirlpool (pwd, pwd_len, init, salt_len + 4, j, WHIRLPOOL_DIGESTSIZE);
	memcpy (u, j, WHIRLPOOL_DIGESTSIZE);

	/* remaining iterations */
	for (c = 1; c < iterations; c++)
	{
		hmac_whirlpool (pwd, pwd_len, j, WHIRLPOOL_DIGESTSIZE, k, WHIRLPOOL_DIGESTSIZE);
		for (i = 0; i < WHIRLPOOL_DIGESTSIZE; i++)
		{
			u[i] ^= k[i];
			j[i] = k[i];
		}
	}

	/* Prevent possible leaks. */
	burn (j, sizeof(j));
	burn (k, sizeof(k));
}

void derive_key_whirlpool (char *pwd, int pwd_len, char *salt, int salt_len, int iterations, char *dk, int dklen)
{
	char u[WHIRLPOOL_DIGESTSIZE];
	int b, l, r;

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
		derive_u_whirlpool (pwd, pwd_len, salt, salt_len, iterations, u, b);
		memcpy (dk, u, WHIRLPOOL_DIGESTSIZE);
		dk += WHIRLPOOL_DIGESTSIZE;
	}

	/* last block */
	derive_u_whirlpool (pwd, pwd_len, salt, salt_len, iterations, u, b);
	memcpy (dk, u, r);


	/* Prevent possible leaks. */
	burn (u, sizeof(u));
}


char *get_pkcs5_prf_name (int pkcs5_prf_id)
{
	switch (pkcs5_prf_id)
	{
	case SHA512:	
		return "HMAC-SHA-512";

	case RIPEMD160:	
		return "HMAC-RIPEMD-160";

	case WHIRLPOOL:	
		return "HMAC-Whirlpool";

	default:		
		return "(Unknown)";
	}
}

#endif //!TC_WINDOWS_BOOT


int get_pkcs5_iteration_count (int pkcs5_prf_id, BOOL bBoot)
{
	switch (pkcs5_prf_id)
	{

	case RIPEMD160:	
		return bBoot? 16384 : 32767; /* we multiply this number by 10 inside derive_u_ripemd160 */

#ifndef TC_WINDOWS_BOOT

	case SHA512:	
		return 500000;

	case WHIRLPOOL:	
		return 500000;
#endif

	default:		
		TC_THROW_FATAL_EXCEPTION;	// Unknown/wrong ID
	}
	return 0;
}
