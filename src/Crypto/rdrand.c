// rdrand.cpp - written and placed in public domain by Jeffrey Walton and Uri Blumenthal.

/* modified for VeraCrypt */

#include "chacha256.h"
#include "cpu.h"
#include "misc.h"

void CRYPTOPP_FASTCALL MASM_RDRAND_GenerateBlock(uint8*, size_t);
void CRYPTOPP_FASTCALL MASM_RDSEED_GenerateBlock(uint8*, size_t);

int RDRAND_getBytes(unsigned char* buf, size_t bufLen)
{
    if (!buf || !HasRDRAND())
		return 0;

	if (bufLen)
		MASM_RDRAND_GenerateBlock(buf, bufLen);

	return 1;
}

int RDSEED_getBytes(unsigned char* buf, size_t bufLen)
{
    if (!buf || !HasRDSEED())
		return 0;

	if (bufLen)
		MASM_RDSEED_GenerateBlock(buf, bufLen);

	return 1;
}
