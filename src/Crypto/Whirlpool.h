#ifndef WHIRLPOOL_H
#define WHIRLPOOL_H 1

#include "Common/Tcdefs.h"
#include "config.h"

typedef struct WHIRLPOOL_CTX {
	uint64 countLo;
	uint64 countHi;
	CRYPTOPP_ALIGN_DATA(16) uint64 data[8];
	CRYPTOPP_ALIGN_DATA(16) uint64 state[8];
} WHIRLPOOL_CTX;

// -------------
#if defined(__cplusplus)
extern "C" {
#endif

void WHIRLPOOL_add(const unsigned char * source, unsigned __int32 sourceBits, WHIRLPOOL_CTX * const ctx);
void WHIRLPOOL_finalize(WHIRLPOOL_CTX* const ctx, unsigned char * result);
void WHIRLPOOL_init(WHIRLPOOL_CTX* const ctx);

#if defined(__cplusplus)
}
#endif

#endif /* WHIRLPOOL_H */
