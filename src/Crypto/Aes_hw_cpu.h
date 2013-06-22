/*
 Copyright (c) 2010 TrueCrypt Developers Association. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

#ifndef TC_HEADER_Crypto_Aes_Hw_Cpu
#define TC_HEADER_Crypto_Aes_Hw_Cpu

#include "Common/Tcdefs.h"

#if defined(__cplusplus)
extern "C"
{
#endif

byte is_aes_hw_cpu_supported ();
void aes_hw_cpu_enable_sse ();
void aes_hw_cpu_decrypt (const byte *ks, byte *data);
void aes_hw_cpu_decrypt_32_blocks (const byte *ks, byte *data);
void aes_hw_cpu_encrypt (const byte *ks, byte *data);
void aes_hw_cpu_encrypt_32_blocks (const byte *ks, byte *data);

#if defined(__cplusplus)
}
#endif

#endif // TC_HEADER_Crypto_Aes_Hw_Cpu
