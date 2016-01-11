#ifndef CRYPTOPP_MISC_H
#define CRYPTOPP_MISC_H

#include "config.h"
#include <string.h>		// for memcpy and memmove

#ifdef _MSC_VER
	#if _MSC_VER >= 1400
		#ifndef TC_WINDOWS_DRIVER
			// VC2005 workaround: disable declarations that conflict with winnt.h
			#define _interlockedbittestandset CRYPTOPP_DISABLED_INTRINSIC_1
			#define _interlockedbittestandreset CRYPTOPP_DISABLED_INTRINSIC_2
			#define _interlockedbittestandset64 CRYPTOPP_DISABLED_INTRINSIC_3
			#define _interlockedbittestandreset64 CRYPTOPP_DISABLED_INTRINSIC_4
			#include <intrin.h>
			#undef _interlockedbittestandset
			#undef _interlockedbittestandreset
			#undef _interlockedbittestandset64
			#undef _interlockedbittestandreset64
		#endif
		#define CRYPTOPP_FAST_ROTATE(x) 1
	#elif _MSC_VER >= 1300
		#define CRYPTOPP_FAST_ROTATE(x) ((x) == 32 | (x) == 64)
	#else
		#define CRYPTOPP_FAST_ROTATE(x) ((x) == 32)
	#endif
#elif (defined(__MWERKS__) && TARGET_CPU_PPC) || \
	(defined(__GNUC__) && (defined(_ARCH_PWR2) || defined(_ARCH_PWR) || defined(_ARCH_PPC) || defined(_ARCH_PPC64) || defined(_ARCH_COM)))
	#define CRYPTOPP_FAST_ROTATE(x) ((x) == 32)
#elif defined(__GNUC__) && (CRYPTOPP_BOOL_X64 || CRYPTOPP_BOOL_X86)	// depend on GCC's peephole optimization to generate rotate instructions
	#define CRYPTOPP_FAST_ROTATE(x) 1
#else
	#define CRYPTOPP_FAST_ROTATE(x) 0
#endif

#if defined( _MSC_VER ) && ( _MSC_VER > 800 )
#pragma intrinsic(memcpy,memset)
#endif

#if _MSC_VER >= 1300 && !defined(__INTEL_COMPILER)
// Intel C++ Compiler 10.0 calls a function instead of using the rotate instruction when using these instructions
#pragma intrinsic(_rotr,_rotl,_rotr64,_rotl64)

#define rotr32(x,n)	_rotr(x, n)
#define rotl32(x,n)	_rotl(x, n)
#define rotr64(x,n)	_rotr64(x, n)
#define rotl64(x,n)	_rotl64(x, n)

#else

#define rotr32(x,n)	(((x) >> n) | ((x) << (32 - n)))
#define rotl32(x,n)	(((x) << n) | ((x) >> (32 - n)))
#define rotr64(x,n)	(((x) >> n) | ((x) << (64 - n)))
#define rotl64(x,n)	(((x) << n) | ((x) >> (64 - n)))

#endif

#if defined(__GNUC__) && defined(__linux__)
#define CRYPTOPP_BYTESWAP_AVAILABLE
#include <byteswap.h>
#elif defined(_MSC_VER) && _MSC_VER >= 1300
#define CRYPTOPP_BYTESWAP_AVAILABLE
#define bswap_32(x)	_byteswap_ulong(x)
#define bswap_64(x)	_byteswap_uint64(x)
#elif defined(__APPLE__)
#include <libkern/OSByteOrder.h>
#define CRYPTOPP_BYTESWAP_AVAILABLE
#define bswap_16 OSSwapInt16
#define bswap_32 OSSwapInt32
#define bswap_64 OSSwapInt64
#else
#ifdef CRYPTOPP_FAST_ROTATE(32)
#define bswap_32(x)	(rotr32((x), 8U) & 0xff00ff00) | (rotl32((x), 8U) & 0x00ff00ff)
#else
#define bswap_32(x)	(rotl32((((x) & 0xFF00FF00) >> 8) | (((x) & 0x00FF00FF) << 8), 16U))
#endif
#ifndef TC_NO_COMPILER_INT64
#define bswap_64(x)	rotl64(((((((x & LL(0xFF00FF00FF00FF00)) >> 8) | ((x & LL(0x00FF00FF00FF00FF)) << 8)) & LL(0xFFFF0000FFFF0000)) >> 16) | (((((x & LL(0xFF00FF00FF00FF00)) >> 8) | ((x & LL(0x00FF00FF00FF00FF)) << 8)) & LL(0x0000FFFF0000FFFF)) << 16)), 32U)
#endif
#endif

VC_INLINE uint32 ByteReverseWord32 (uint32 value)
{
#if defined(__GNUC__) && defined(CRYPTOPP_X86_ASM_AVAILABLE)
	__asm__ ("bswap %0" : "=r" (value) : "0" (value));
	return value;
#elif defined(CRYPTOPP_BYTESWAP_AVAILABLE)
	return bswap_32(value);
#elif defined(__MWERKS__) && TARGET_CPU_PPC
	return (uint32)__lwbrx(&value,0);
#elif _MSC_VER >= 1400 || (_MSC_VER >= 1300 && !defined(_DLL))
	return _byteswap_ulong(value);
#elif CRYPTOPP_FAST_ROTATE(32)
	// 5 instructions with rotate instruction, 9 without
	return (rotr32(value, 8U) & 0xff00ff00) | (rotl32(value, 8U) & 0x00ff00ff);
#else
	// 6 instructions with rotate instruction, 8 without
	value = ((value & 0xFF00FF00) >> 8) | ((value & 0x00FF00FF) << 8);
	return rotl32(value, 16U);
#endif
}

#ifndef TC_NO_COMPILER_INT64

VC_INLINE uint64 ByteReverseWord64(uint64 value)
{
#if defined(__GNUC__) && defined(CRYPTOPP_X86_ASM_AVAILABLE) && defined(__x86_64__)
	__asm__ ("bswap %0" : "=r" (value) : "0" (value));
	return value;
#elif defined(CRYPTOPP_BYTESWAP_AVAILABLE)
	return bswap_64(value);
#elif defined(_MSC_VER) && _MSC_VER >= 1300
	return _byteswap_uint64(value);
#else
	value = ((value & LL(0xFF00FF00FF00FF00)) >> 8) | ((value & LL(0x00FF00FF00FF00FF)) << 8);
	value = ((value & LL(0xFFFF0000FFFF0000)) >> 16) | ((value & LL(0x0000FFFF0000FFFF)) << 16);
	return rotl64(value, 32U);
#endif
}

VC_INLINE void CorrectEndianess(uint64 *out, const uint64 *in, size_t byteCount)

{
	size_t i, count = byteCount/sizeof(uint64);
	for (i=0; i<count; i++)
		out[i] = ByteReverseWord64(in[i]);
}

#endif

#ifdef CRYPTOPP_ALLOW_UNALIGNED_DATA_ACCESS
	#define GetAlignmentOf(T) 1
#elif (_MSC_VER >= 1300)
	#define GetAlignmentOf(T) __alignof(T)
#elif defined(__GNUC__)
	#define GetAlignmentOf(T) __alignof__(T)
#else
	#define GetAlignmentOf(T) sizeof(T)
#endif

#define IsPowerOf2(n)	(((n) > 0) && (((n) & ((n)-1)) == 0))

#define ModPowerOf2(a,b)	((a) & ((b)-1))

#define IsAlignedOn(p,alignment) ((alignment==1) || (IsPowerOf2(alignment) ? ModPowerOf2((size_t)p, alignment) == 0 : (size_t)p % alignment == 0))

#define IsAligned16(p)	IsAlignedOn(p, GetAlignmentOf(uint64))

#endif
