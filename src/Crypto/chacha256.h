#ifndef HEADER_Crypto_ChaCha256
#define HEADER_Crypto_ChaCha256

#include "Common/Tcdefs.h"
#include "config.h"

typedef struct
{
    CRYPTOPP_ALIGN_DATA(16) uint32 block_[16];
    CRYPTOPP_ALIGN_DATA(16) uint32 input_[16];
    size_t pos; 
    int internalRounds;
} ChaCha256Ctx;

#ifdef __cplusplus
extern "C" {
#endif

/*
 * key must be 32 bytes long and iv must be 8 bytes long
 */
void ChaCha256Init(ChaCha256Ctx* ctx, const unsigned char* key, const unsigned char* iv, int rounds);
void ChaCha256Encrypt(ChaCha256Ctx* ctx, const unsigned char* in, size_t len, unsigned char* out);
#define ChaCha256Decrypt ChaCha256Encrypt

#ifdef __cplusplus
}
#endif

#endif // HEADER_Crypto_ChaCha

