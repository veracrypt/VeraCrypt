#ifndef SM4_HEADER_H
#define SM4_HEADER_H

#include "Common/Tcdefs.h"
#include "config.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _sm4_kds
{
	CRYPTOPP_ALIGN_DATA(16) uint32 m_rEnckeys[32];
	CRYPTOPP_ALIGN_DATA(16) uint32 m_rDeckeys[32];
} sm4_kds;

#define SM4_KS	(sizeof(sm4_kds))

void sm4_set_key(const uint8* key, sm4_kds* kds);
void sm4_encrypt_block(uint8* out, const uint8* in, sm4_kds* kds);
void sm4_encrypt_blocks(uint8* out, const uint8* in, size_t blocks, sm4_kds* kds);
void sm4_decrypt_block(uint8* out, const uint8* in, sm4_kds* kds);
void sm4_decrypt_blocks(uint8* out, const uint8* in, size_t blocks, sm4_kds* kds);

#ifdef __cplusplus
}
#endif
#endif
