#ifndef HEADER_Crypto_Serpent
#define HEADER_Crypto_Serpent

#include "Common/Tcdefs.h"

#ifdef __cplusplus
extern "C"
{
#endif

void serpent_set_key(const unsigned __int8 userKey[], int keylen, unsigned __int8 *ks);
void serpent_encrypt(const unsigned __int8 *inBlock, unsigned __int8 *outBlock, unsigned __int8 *ks);
void serpent_decrypt(const unsigned __int8 *inBlock,  unsigned __int8 *outBlock, unsigned __int8 *ks);

#ifdef __cplusplus
}
#endif

#endif // HEADER_Crypto_Serpent
