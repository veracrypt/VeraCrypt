/*
   BLAKE2 reference source code package - optimized C implementations

   Copyright 2012, Samuel Neves <sneves@dei.uc.pt>.  You may use this under the
   terms of the CC0, the OpenSSL Licence, or the Apache Public License 2.0, at
   your option.  The terms of these licenses can be found at:

   - CC0 1.0 Universal : http://creativecommons.org/publicdomain/zero/1.0
   - OpenSSL license   : https://www.openssl.org/source/license.html
   - Apache 2.0        : http://www.apache.org/licenses/LICENSE-2.0

   More information about the BLAKE2 hash function can be found at
   https://blake2.net.
*/

/* Adapted for VeraCrypt */

#include "blake2.h"
#include "Common/Endian.h"
#include "Crypto/config.h"
#include "Crypto/cpu.h"
#include "Crypto/misc.h"

#if CRYPTOPP_BOOL_SSE2_INTRINSICS_AVAILABLE
#if CRYPTOPP_BOOL_SSE41_INTRINSICS_AVAILABLE

#define HAVE_SSE41

#if CRYPTOPP_SSSE3_AVAILABLE
#define HAVE_SSSE3
#endif

#include "blake2s-round.h"

int blake2s_has_sse41()
{
    return 1;
}

#else
int blake2s_has_sse41()
{
    return 0;
}

#endif
#else
int blake2s_has_sse41()
{
    return 0;
}
#endif
