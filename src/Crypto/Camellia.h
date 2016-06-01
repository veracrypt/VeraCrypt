#ifndef HEADER_Crypto_Camellia
#define HEADER_Crypto_Camellia

#include "Common/Tcdefs.h"

#ifdef __cplusplus
extern "C"
{
#endif

#define CAMELLIA_KS		34 * 8

/* userKey is always 32-bytes long */
/* size of ks is 34*8 bytes */
void camellia_set_key(const unsigned __int8 userKey[], unsigned __int8 *ks);
void camellia_encrypt(const unsigned __int8 *inBlock, unsigned __int8 *outBlock, unsigned __int8 *ks);
void camellia_decrypt(const unsigned __int8 *inBlock,  unsigned __int8 *outBlock, unsigned __int8 *ks);

#ifdef __cplusplus
}
#endif

#endif // HEADER_Crypto_Camellia
