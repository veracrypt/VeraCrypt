/** @file
GOST89 implementation

Copyright (c) 2016. Disk Cryptography Services for EFI (DCS), Alex Kolotnikov

This program and the accompanying materials
are licensed and made available under the terms and conditions
of the Apache License, Version 2.0.  
The full text of the license may be found at
https://opensource.org/licenses/Apache-2.0

Dynamic SBOX idea is from GostCrypt project. Copyright (c) 2008-2011 TrueCrypt Developers Association
**/



#include "GostCipher.h"
#include "Streebog.h"
#include "cpu.h"

#if defined(CIPHER_GOST89)

// Crypto Pro
byte S_CryptoPro[8][16] = {
	{0x1,0x3,0xA,0x9,0x5,0xB,0x4,0xF,0x8,0x6,0x7,0xE,0xD,0x0,0x2,0xC},
	{0xD,0xE,0x4,0x1,0x7,0x0,0x5,0xA,0x3,0xC,0x8,0xF,0x6,0x2,0x9,0xB},
	{0x7,0x6,0x2,0x4,0xD,0x9,0xF,0x0,0xA,0x1,0x5,0xB,0x8,0xE,0xC,0x3},
	{0x7,0x6,0x4,0xB,0x9,0xC,0x2,0xA,0x1,0x8,0x0,0xE,0xF,0xD,0x3,0x5},
	{0x4,0xA,0x7,0xC,0x0,0xF,0x2,0x8,0xE,0x1,0x6,0x5,0xD,0xB,0x9,0x3},
	{0x7,0xF,0xC,0xE,0x9,0x4,0x1,0x0,0x3,0xB,0x5,0x2,0x6,0xA,0x8,0xD},
	{0x5,0xF,0x4,0x0,0x2,0xD,0xB,0x9,0x1,0x7,0x6,0x3,0xC,0xE,0xA,0x8},
	{0xA,0x4,0x5,0x6,0x8,0x1,0x3,0x7,0xD,0xC,0xE,0x0,0x9,0x2,0xB,0xF}
	};

// TC26
byte S_TC26[8][16] =
{
	{ 0xc, 0x4, 0x6, 0x2, 0xa, 0x5, 0xb, 0x9, 0xe, 0x8, 0xd, 0x7, 0x0, 0x3, 0xf, 0x1 },
	{ 0x6, 0x8, 0x2, 0x3, 0x9, 0xa, 0x5, 0xc, 0x1, 0xe, 0x4, 0x7, 0xb, 0xd, 0x0, 0xf },
	{ 0xb, 0x3, 0x5, 0x8, 0x2, 0xf, 0xa, 0xd, 0xe, 0x1, 0x7, 0x4, 0xc, 0x9, 0x6, 0x0 },
	{ 0xc, 0x8, 0x2, 0x1, 0xd, 0x4, 0xf, 0x6, 0x7, 0x0, 0xa, 0x5, 0x3, 0xe, 0x9, 0xb },
	{ 0x7, 0xf, 0x5, 0xa, 0x8, 0x1, 0x6, 0xd, 0x0, 0x9, 0x3, 0xe, 0xb, 0x4, 0x2, 0xc },
	{ 0x5, 0xd, 0xf, 0x6, 0x9, 0x2, 0xc, 0xa, 0xb, 0x7, 0x8, 0x1, 0x4, 0x3, 0xe, 0x0 },
	{ 0x8, 0xe, 0x2, 0x5, 0x6, 0x9, 0x1, 0xc, 0xf, 0x4, 0xb, 0x0, 0xd, 0xa, 0x3, 0x7 },
	{ 0x1, 0x7, 0xe, 0xd, 0x0, 0x5, 0x8, 0x3, 0x4, 0xf, 0xa, 0x6, 0x9, 0xc, 0xb, 0x2 },
};

void gost_prepare_kds(gost_kds* kds) {
	uint32 i;
	// Build substitution tables. 
	for (i = 0; i < 256; ++i) {
		uint32 p;
		p = kds->sbox[7][i >> 4] << 4 | kds->sbox[6][i & 15];
		p = p << 24; p = p << 11 | p >> 21;
		kds->sbox_cvt[i] = p; // S87

		p = kds->sbox[5][i >> 4] << 4 | kds->sbox[4][i & 15];
		p = p << 16; p = p << 11 | p >> 21;
		kds->sbox_cvt[256 + i] = p; // S65

		p = kds->sbox[3][i >> 4] << 4 | kds->sbox[2][i & 15];
		p = p << 8; p = p << 11 | p >> 21;
		kds->sbox_cvt[256 * 2 + i] = p; // S43

		p = kds->sbox[1][i >> 4] << 4 | kds->sbox[0][i & 15];
		p = p << 11 | p >> 21;
		kds->sbox_cvt[256 * 3 + i] = p; // S21
	}
}


static void xor_s_box(byte s_box[8][16], byte *seed)
{
   int i;
   for (i = 0; i < 16; i++)
   {
      s_box[0][i] ^= (seed[ (i * 4) + 0 ]   ) & 0xF;
      s_box[1][i] ^= (seed[ (i * 4) + 0 ]>>4) & 0xF;
      s_box[2][i] ^= (seed[ (i * 4) + 1 ]   ) & 0xF;
      s_box[3][i] ^= (seed[ (i * 4) + 1 ]>>4) & 0xF;
      s_box[4][i] ^= (seed[ (i * 4) + 2 ]   ) & 0xF;
      s_box[5][i] ^= (seed[ (i * 4) + 2 ]>>4) & 0xF;
      s_box[6][i] ^= (seed[ (i * 4) + 3 ]   ) & 0xF;
      s_box[7][i] ^= (seed[ (i * 4) + 3 ]>>4) & 0xF;
   }
}

void gost_set_key(const byte *key, gost_kds *ks, int useDynamicSbox)
{
	memcpy(ks->key, key, GOST_KEYSIZE);
	memcpy(ks->sbox, S_TC26, sizeof(ks->sbox));

    if (useDynamicSbox)
    {
	    STREEBOG_CTX sctx;
	    byte sbox_seed[64];
#if defined (DEVICE_DRIVER) && !defined (_WIN64)
	    KFLOATING_SAVE floatingPointState;
	    NTSTATUS saveStatus = STATUS_SUCCESS;
	    if (HasSSE2() || HasSSE41())
		    saveStatus = KeSaveFloatingPointState (&floatingPointState);
#endif
	    //Generate pseudorandom data based on the key
	    STREEBOG_init(&sctx);
	    STREEBOG_add(&sctx, ks->key, 32);
	    STREEBOG_finalize(&sctx, sbox_seed);

#if defined (DEVICE_DRIVER) && !defined (_WIN64)
	    if (NT_SUCCESS (saveStatus) && (HasSSE2() || HasSSE41()))
		    KeRestoreFloatingPointState (&floatingPointState);
#endif

	    xor_s_box(ks->sbox, sbox_seed);
    }

	gost_prepare_kds(ks);
}

static uint32 f(uint32 v, uint32* sbox){
   byte* x =(byte*) &v;
   /* Do substitutions */
   return sbox[x[3]] | sbox[256 + x[2]] | sbox[256*2 + x[1]] | sbox[256*3 + x[0]];
}

void gost_encrypt_block(uint64 in_, uint64* out_, gost_kds* kds) {
   uint32* in  = (uint32*)&in_;
   uint32* out = (uint32*)out_;
	uint32* key = (uint32*)kds->key;
	uint32* sbox = kds->sbox_cvt;

   // As named in the GOST
   uint32 n1 = in[0];
   uint32 n2 = in[1];

	n2 ^= f(n1+key[0], sbox);
   n1 ^= f(n2+key[1], sbox);
   n2 ^= f(n1+key[2], sbox);
   n1 ^= f(n2+key[3], sbox);
   n2 ^= f(n1+key[4], sbox);
   n1 ^= f(n2+key[5], sbox);
   n2 ^= f(n1+key[6], sbox);
   n1 ^= f(n2+key[7], sbox);

   n2 ^= f(n1+key[0], sbox);
   n1 ^= f(n2+key[1], sbox);
   n2 ^= f(n1+key[2], sbox);
   n1 ^= f(n2+key[3], sbox);
   n2 ^= f(n1+key[4], sbox);
   n1 ^= f(n2+key[5], sbox);
   n2 ^= f(n1+key[6], sbox);
   n1 ^= f(n2+key[7], sbox);

   n2 ^= f(n1+key[0], sbox);
   n1 ^= f(n2+key[1], sbox);
   n2 ^= f(n1+key[2], sbox);
   n1 ^= f(n2+key[3], sbox);
   n2 ^= f(n1+key[4], sbox);
   n1 ^= f(n2+key[5], sbox);
   n2 ^= f(n1+key[6], sbox);
   n1 ^= f(n2+key[7], sbox);

   n2 ^= f(n1+key[7], sbox);
   n1 ^= f(n2+key[6], sbox);
   n2 ^= f(n1+key[5], sbox);
   n1 ^= f(n2+key[4], sbox);
   n2 ^= f(n1+key[3], sbox);
   n1 ^= f(n2+key[2], sbox);
   n2 ^= f(n1+key[1], sbox);
   n1 ^= f(n2+key[0], sbox);

   // There is no swap after the last round
   out[0] = n2;
   out[1] = n1;
}

void gost_decrypt_block(uint64 in_, uint64* out_, gost_kds* kds) {
   uint32* in  = (uint32*)&in_;
   uint32* out = (uint32*)out_;
	uint32* key = (uint32*)kds->key;
	uint32* sbox = kds->sbox_cvt;

   // As named in the GOST
   uint32 n1 = in[0];
   uint32 n2 = in[1];

   n2 ^= f(n1+key[0], sbox);
   n1 ^= f(n2+key[1], sbox);
   n2 ^= f(n1+key[2], sbox);
   n1 ^= f(n2+key[3], sbox);
   n2 ^= f(n1+key[4], sbox);
   n1 ^= f(n2+key[5], sbox);
   n2 ^= f(n1+key[6], sbox);
   n1 ^= f(n2+key[7], sbox);

   n2 ^= f(n1+key[7], sbox);
   n1 ^= f(n2+key[6], sbox);
   n2 ^= f(n1+key[5], sbox);
   n1 ^= f(n2+key[4], sbox);
   n2 ^= f(n1+key[3], sbox);
   n1 ^= f(n2+key[2], sbox);
   n2 ^= f(n1+key[1], sbox);
   n1 ^= f(n2+key[0], sbox);

   n2 ^= f(n1+key[7], sbox);
   n1 ^= f(n2+key[6], sbox);
   n2 ^= f(n1+key[5], sbox);
   n1 ^= f(n2+key[4], sbox);
   n2 ^= f(n1+key[3], sbox);
   n1 ^= f(n2+key[2], sbox);
   n2 ^= f(n1+key[1], sbox);
   n1 ^= f(n2+key[0], sbox);

   n2 ^= f(n1+key[7], sbox);
   n1 ^= f(n2+key[6], sbox);
   n2 ^= f(n1+key[5], sbox);
   n1 ^= f(n2+key[4], sbox);
   n2 ^= f(n1+key[3], sbox);
   n1 ^= f(n2+key[2], sbox);
   n2 ^= f(n1+key[1], sbox);
   n1 ^= f(n2+key[0], sbox);

   out[0] = n2;
   out[1] = n1;
}

#if defined(_M_AMD64)
void gost_encrypt_128_CBC_asm(const byte *in, byte *out, gost_kds *ks, uint64 count);
void gost_decrypt_128_CBC_asm(const byte *in, byte *out, gost_kds *ks, uint64 count);
#endif

void gost_encrypt(const byte *in, byte *out, gost_kds *ks, int count) {
#if defined(_M_AMD64)
	gost_encrypt_128_CBC_asm(in, out, ks, (uint64)count);
#else
	while (count > 0) {
		// encrypt two blocks in CBC mode
		gost_encrypt_block(*((uint64*)in), (uint64*)out, ks);
		*((gst_udword*)(out + 8)) = *((gst_udword*)(in + 8)) ^ *((gst_udword*)(out));
		*((gst_udword*)(out + 12)) = *((gst_udword*)(in + 12)) ^ *((gst_udword*)(out + 4));
		gost_encrypt_block(*((uint64*)(out + 8)), (uint64*)(out + 8), ks);
		count--;
		in += 16;
		out += 16;
	}
#endif
}

void gost_decrypt(const byte *in, byte *out, gost_kds *ks, int count) {
#if defined(_M_AMD64)
	gost_decrypt_128_CBC_asm(in, out, ks, (uint64)count);
#else
	while (count > 0) {
		// decrypt two blocks in CBC mode
		gost_decrypt_block(*((uint64*)(in + 8)), (uint64*)(out + 8), ks);
		*((gst_udword*)(out + 8)) ^= *((gst_udword*)(in));;
		*((gst_udword*)(out + 12)) ^= *((gst_udword*)(in + 4));;
		gost_decrypt_block(*((uint64*)(in)), (uint64*)(out), ks);
		count--;
		in += 16;
		out += 16;
	}
#endif
}

#endif
