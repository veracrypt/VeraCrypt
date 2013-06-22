/*
 ---------------------------------------------------------------------------
 Copyright (c) 2002, Dr Brian Gladman, Worcester, UK.   All rights reserved.

 LICENSE TERMS

 The free distribution and use of this software is allowed (with or without
 changes) provided that:

  1. source code distributions include the above copyright notice, this
     list of conditions and the following disclaimer;

  2. binary distributions include the above copyright notice, this list
     of conditions and the following disclaimer in their documentation;

  3. the name of the copyright holder is not used to endorse products
     built using this software without specific written permission.

 DISCLAIMER

 This software is provided 'as is' with no explicit or implied warranties
 in respect of its properties, including, but not limited to, correctness
 and/or fitness for purpose.
 ---------------------------------------------------------------------------
 Issue Date: 01/08/2005
*/

#ifndef _SHA2_H
#define _SHA2_H

#include "Common/Tcdefs.h"
#include "Common/Endian.h"

#define SHA_64BIT

/* define the hash functions that you need  */
#define SHA_2   /* for dynamic hash length  */
#define SHA_224
#define SHA_256
#ifdef SHA_64BIT
#  define SHA_384
#  define SHA_512
#  define NEED_UINT_64T
#endif

#ifndef EXIT_SUCCESS
#define EXIT_SUCCESS    0
#define EXIT_FAILURE    1
#endif

#define li_64(h) 0x##h##ull

#define VOID_RETURN	void
#define INT_RETURN	int

#if defined(__cplusplus)
extern "C"
{
#endif

/* Note that the following function prototypes are the same */
/* for both the bit and byte oriented implementations.  But */
/* the length fields are in bytes or bits as is appropriate */
/* for the version used.  Bit sequences are arrays of bytes */
/* in which bit sequence indexes increase from the most to  */
/* the least significant end of each byte                   */

#define SHA224_DIGEST_SIZE  28
#define SHA224_BLOCK_SIZE   64
#define SHA256_DIGEST_SIZE  32
#define SHA256_BLOCK_SIZE   64

/* type to hold the SHA256 (and SHA224) context */

typedef struct
{   uint_32t count[2];
    uint_32t hash[8];
    uint_32t wbuf[16];
} sha256_ctx;

typedef sha256_ctx  sha224_ctx;

VOID_RETURN sha256_compile(sha256_ctx ctx[1]);

VOID_RETURN sha224_begin(sha224_ctx ctx[1]);
#define sha224_hash sha256_hash
VOID_RETURN sha224_end(unsigned char hval[], sha224_ctx ctx[1]);
VOID_RETURN sha224(unsigned char hval[], const unsigned char data[], unsigned long len);

VOID_RETURN sha256_begin(sha256_ctx ctx[1]);
VOID_RETURN sha256_hash(const unsigned char data[], unsigned long len, sha256_ctx ctx[1]);
VOID_RETURN sha256_end(unsigned char hval[], sha256_ctx ctx[1]);
VOID_RETURN sha256(unsigned char hval[], const unsigned char data[], unsigned long len);

#ifndef SHA_64BIT

typedef struct
{   union
    { sha256_ctx  ctx256[1];
    } uu[1];
    uint_32t    sha2_len;
} sha2_ctx;

#define SHA2_MAX_DIGEST_SIZE    SHA256_DIGEST_SIZE

#else

#define SHA384_DIGEST_SIZE  48
#define SHA384_BLOCK_SIZE  128
#define SHA512_DIGEST_SIZE  64
#define SHA512_BLOCK_SIZE  128
#define SHA2_MAX_DIGEST_SIZE    SHA512_DIGEST_SIZE

/* type to hold the SHA384 (and SHA512) context */

typedef struct
{   uint_64t count[2];
    uint_64t hash[8];
    uint_64t wbuf[16];
} sha512_ctx;

typedef sha512_ctx  sha384_ctx;

typedef struct
{   union
    { sha256_ctx  ctx256[1];
      sha512_ctx  ctx512[1];
    } uu[1];
    uint_32t    sha2_len;
} sha2_ctx;

VOID_RETURN sha512_compile(sha512_ctx ctx[1]);

VOID_RETURN sha384_begin(sha384_ctx ctx[1]);
#define sha384_hash sha512_hash
VOID_RETURN sha384_end(unsigned char hval[], sha384_ctx ctx[1]);
VOID_RETURN sha384(unsigned char hval[], const unsigned char data[], unsigned long len);

VOID_RETURN sha512_begin(sha512_ctx ctx[1]);
VOID_RETURN sha512_hash(const unsigned char data[], unsigned long len, sha512_ctx ctx[1]);
VOID_RETURN sha512_end(unsigned char hval[], sha512_ctx ctx[1]);
VOID_RETURN sha512(unsigned char hval[], const unsigned char data[], unsigned long len);

INT_RETURN  sha2_begin(unsigned long size, sha2_ctx ctx[1]);
VOID_RETURN sha2_hash(const unsigned char data[], unsigned long len, sha2_ctx ctx[1]);
VOID_RETURN sha2_end(unsigned char hval[], sha2_ctx ctx[1]);
INT_RETURN  sha2(unsigned char hval[], unsigned long size, const unsigned char data[], unsigned long len);

#endif

#if defined(__cplusplus)
}
#endif

#endif
