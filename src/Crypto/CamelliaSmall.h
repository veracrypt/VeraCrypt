#ifndef SMALL_CAMELLIA_H
#define SMALL_CAMELLIA_H

#include "Common/Tcdefs.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CAMELLIA_KS		34 * 8 * 2

/* userKey is always 32-bytes long */
/* size of ks is 34 */
void camellia_set_key(const unsigned __int8 userKey[], unsigned __int8 *ks);
void camellia_encrypt(const unsigned __int8 *inBlock, unsigned __int8 *outBlock, unsigned __int8 *ks);
void camellia_decrypt(const unsigned __int8 *inBlock,  unsigned __int8 *outBlock, unsigned __int8 *ks);

#ifdef __cplusplus
}
#endif


#endif /* camellia.h */
