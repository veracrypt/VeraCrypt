
/*
 Copyright (c) 2008-2011 TrueCrypt Developers Association. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/



#ifndef GOST_CIPHER_H
#define GOST_CIPHER_H

#include "Common/Tcdefs.h"
#include "config.h"

#ifdef __cplusplus
extern "C" {
#endif

//In unsigned chars
#define GOST_KEYSIZE	32
#define GOST_BLOCKSIZE	8
#define GOST_SBOX_SIZE	16

//Production setting, but can be turned off to compare the algorithm with other implementations
#define CIPHER_GOST89
#define GOST_DYNAMIC_SBOXES

#if defined(CIPHER_GOST89)

#ifndef rotl32
#define rotl32(b, shift) ((b << shift) | (b >> (32 - shift)))
#endif

#ifdef GST_WINDOWS_BOOT
typedef int gst_word;
typedef long gst_dword;
typedef unsigned int gst_uword;
typedef unsigned long gst_udword;
#else
typedef short gst_word;
typedef int gst_dword;
typedef unsigned short gst_uword;
typedef unsigned int gst_udword;
#endif

typedef struct gost_kds
{
	CRYPTOPP_ALIGN_DATA(16) byte key[32];
	gst_udword	sbox_cvt[256 * 4];
	byte			sbox[8][16];
} gost_kds;

#define GOST_KS				(sizeof(gost_kds))

void gost_encrypt(const byte *in, byte *out, gost_kds *ks, int count);
void gost_decrypt(const byte *in, byte *out, gost_kds *ks, int count);
void gost_set_key(const byte *key, gost_kds *ks, int useDynamicSbox);

#else 
#define GOST_KS				(0)
#endif

#ifdef __cplusplus
}
#endif


#endif
