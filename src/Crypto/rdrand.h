#ifndef HEADER_Crypto_RDRAND
#define HEADER_Crypto_RDRAND

#include "Common/Tcdefs.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * generate bufLen random bytes using CPU RDRAND instruction
 * return 1 in case of success and 0 in case of failure
 */
int RDRAND_getBytes(unsigned char* buf, size_t bufLen);

/*
 * generate bufLen random bytes using CPU RDSEED instruction
 * return 1 in case of success and 0 in case of failure
 */
int RDSEED_getBytes(unsigned char* buf, size_t bufLen);

#ifdef __cplusplus
}
#endif

#endif
