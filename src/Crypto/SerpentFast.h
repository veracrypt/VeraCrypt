/*
* Serpent
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "Common/Tcdefs.h"

#pragma once

#ifdef __cplusplus
extern "C"
{
#endif

/* userKey is always 32-bytes long */
void serpent_set_key(const unsigned __int8 userKey[], unsigned __int8 *ks);
void serpent_encrypt_blocks(const unsigned __int8* in, unsigned __int8* out, size_t blocks, unsigned __int8 *ks);
void serpent_decrypt_blocks(const unsigned __int8* in, unsigned __int8* out, size_t blocks, unsigned __int8 *ks);

#define serpent_encrypt(inBlock,outBlock,ks)	serpent_encrypt_blocks(inBlock,outBlock,1,ks)
#define serpent_decrypt(inBlock,outBlock,ks)	serpent_decrypt_blocks(inBlock,outBlock,1,ks)

#ifdef __cplusplus
}
#endif

