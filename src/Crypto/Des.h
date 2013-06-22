/* Deprecated/legacy */


#ifndef HEADER_Crypto_DES
#define HEADER_Crypto_DES

#ifdef  __cplusplus
extern "C" {
#endif

typedef struct TRIPLE_DES_KEY_STRUCT
{
	unsigned __int32 k1[32];
	unsigned __int32 k2[32];
	unsigned __int32 k3[32];
	unsigned __int32 k1d[32];
	unsigned __int32 k2d[32];
	unsigned __int32 k3d[32];
} TDES_KEY;

void TripleDesEncrypt (byte *inBlock, byte *outBlock, TDES_KEY *key, int encrypt);
void TripleDesSetKey (const byte *userKey, unsigned int length, TDES_KEY *ks);

#ifdef  __cplusplus
}
#endif

#endif // HEADER_Crypto_DES
