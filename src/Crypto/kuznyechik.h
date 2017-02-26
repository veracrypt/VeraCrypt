/*
This code is written by kerukuro for cppcrypto library (http://cppcrypto.sourceforge.net/)
and released into public domain.
*/

/* Adapted to VeraCrypt */

#ifndef CPPCRYPTO_KUZNYECHIK_H
#define CPPCRYPTO_KUZNYECHIK_H

#include "Common/Tcdefs.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _kuznyechik_kds
{
	uint64 rke[10][2];
	uint64 rkd[10][2];
} kuznyechik_kds;

#define KUZNYECHIK_KS				(sizeof(kuznyechik_kds))

void kuznyechik_encrypt_block(byte* out, const byte* in, kuznyechik_kds* kds);
void kuznyechik_decrypt_block(byte* out, const byte* in, kuznyechik_kds* kds);
void kuznyechik_set_key(const byte* key, kuznyechik_kds *kds);

#ifdef __cplusplus
}
#endif

#endif
