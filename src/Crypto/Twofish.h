#ifndef TWOFISH_H
#define TWOFISH_H

#include "Common/Tcdefs.h"
#include "config.h"

#if defined(__cplusplus)
extern "C"
{
#endif

#ifndef u4byte
#define u4byte	unsigned __int32
#endif
#ifndef u1byte
#define u1byte	unsigned char
#endif

#ifndef extract_byte
#define extract_byte(x,n)   ((u1byte)((x) >> (8 * n)))
#endif

#ifndef rotl

#ifdef _WIN32
#include <stdlib.h>
#pragma intrinsic(_lrotr,_lrotl)
#define rotr(x,n) _lrotr(x,n)
#define rotl(x,n) _lrotl(x,n)
#else
#define rotr(x,n) (((x)>>(n))|((x)<<(32-(n))))
#define rotl(x,n) (((x)<<(n))|((x)>>(32-(n))))
#endif

#endif
typedef struct
{
#if CRYPTOPP_BOOL_X64
   u4byte mk_tab[4][256], w[8], k[32];
#else
	u4byte l_key[40];
#ifdef TC_MINIMIZE_CODE_SIZE
	u4byte s_key[4];
#ifdef TC_WINDOWS_BOOT_TWOFISH
	u4byte mk_tab[4 * 256];
#endif
#else
   u4byte mk_tab[4][256];
#endif
#endif
} TwofishInstance;

#define TWOFISH_KS		sizeof(TwofishInstance)

/* in_key must be 32-bytes long */
void twofish_set_key(TwofishInstance *instance, const u4byte in_key[]);
#if CRYPTOPP_BOOL_X64
void twofish_encrypt_blocks(TwofishInstance *instance, const byte* in_blk, byte* out_blk, uint32 blockCount);
void twofish_decrypt_blocks(TwofishInstance *instance, const byte* in_blk, byte* out_blk, uint32 blockCount);
#define twofish_encrypt(instance,in_blk,out_blk)   twofish_encrypt_blocks(instance, (const byte*) in_blk, (byte*) out_blk, 1)
#define twofish_decrypt(instance,in_blk,out_blk)   twofish_decrypt_blocks(instance, (const byte*) in_blk, (byte*) out_blk, 1)
#else
void twofish_encrypt(TwofishInstance *instance, const u4byte in_blk[4], u4byte out_blk[4]);
void twofish_decrypt(TwofishInstance *instance, const u4byte in_blk[4], u4byte out_blk[4]);
#endif

#if defined(__cplusplus)
}
#endif

#endif // TWOFISH_H
