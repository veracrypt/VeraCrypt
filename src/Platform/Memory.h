/*
 Copyright (c) 2008-2009 TrueCrypt Developers Association. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

#ifndef TC_HEADER_Platform_Memory
#define TC_HEADER_Platform_Memory

#include <new>
#include <memory.h>
#include "PlatformBase.h"

#ifdef TC_WINDOWS

#	ifndef LITTLE_ENDIAN
#		define LITTLE_ENDIAN 1234
#	endif
#	ifndef BYTE_ORDER
#		define BYTE_ORDER LITTLE_ENDIAN
#	endif

#elif !defined(BYTE_ORDER)

#	ifdef TC_MACOSX
#		include <machine/endian.h>
#	elif defined (TC_BSD)
#		include <sys/endian.h>
#	elif defined (TC_SOLARIS)
#		include <sys/types.h>
#		define LITTLE_ENDIAN 1234
#		define BIG_ENDIAN 4321
#		ifdef _BIG_ENDIAN
#			define BYTE_ORDER BIG_ENDIAN
#		else
#			define BYTE_ORDER LITTLE_ENDIAN
#		endif
#	else
#		include <endian.h>
#	endif

#	ifndef BYTE_ORDER
#		ifndef __BYTE_ORDER
#			error Byte ordering cannot be determined (BYTE_ORDER undefined).
#		endif

#		define BYTE_ORDER __BYTE_ORDER
#	endif

#	ifndef LITTLE_ENDIAN
#		define LITTLE_ENDIAN __LITTLE_ENDIAN
#	endif

#	ifndef BIG_ENDIAN
#		define BIG_ENDIAN __BIG_ENDIAN
#	endif

#endif // !BYTE_ORDER

#if BYTE_ORDER != BIG_ENDIAN && BYTE_ORDER != LITTLE_ENDIAN
#	error Unsupported byte ordering detected.
#endif

namespace VeraCrypt
{
	class Memory
	{
	public:
		static void *Allocate (size_t size);
		static int Compare (const void *memory1, size_t size1, const void *memory2, size_t size2);
		static void Copy (void *memoryDestination, const void *memorySource, size_t size);
		static void Erase (void *memory, size_t size);
		static void Free (void *memory);
		static void Zero (void *memory, size_t size);
	};

	class Endian
	{
	public:
		static byte Big (const byte &x)
		{
			return x;
		}

		static uint16 Big (const uint16 &x)
		{
#if BYTE_ORDER == BIG_ENDIAN
			return x;
#else
			return MirrorBytes (x);
#endif
		}

		static uint32 Big (const uint32 &x)
		{
#if BYTE_ORDER == BIG_ENDIAN
			return x;
#else
			return MirrorBytes (x);
#endif
		}

		static uint64 Big (const uint64 &x)
		{
#if BYTE_ORDER == BIG_ENDIAN
			return x;
#else
			return MirrorBytes (x);
#endif
		}

		static byte Little (const byte &x)
		{
			return x;
		}

		static uint16 Little (const uint16 &x)
		{
#if BYTE_ORDER == LITTLE_ENDIAN
			return x;
#else
			return MirrorBytes (x);
#endif
		}

		static uint32 Little (const uint32 &x)
		{
#if BYTE_ORDER == LITTLE_ENDIAN
			return x;
#else
			return MirrorBytes (x);
#endif
		}

		static uint64 Little (const uint64 &x)
		{
#if BYTE_ORDER == LITTLE_ENDIAN
			return x;
#else
			return MirrorBytes (x);
#endif
		}

	protected:
		static uint16 MirrorBytes (const uint16 &x)
		{
			return (x << 8) | (x >> 8);
		}

		static uint32 MirrorBytes (const uint32 &x)
		{
			uint32 n = (byte) x;
			n <<= 8; n |= (byte) (x >> 8);
			n <<= 8; n |= (byte) (x >> 16);
			return (n << 8) | (byte) (x >> 24);
		}

		static uint64 MirrorBytes (const uint64 &x)
		{
			uint64 n = (byte) x;
			n <<= 8; n |= (byte) (x >> 8);
			n <<= 8; n |= (byte) (x >> 16);
			n <<= 8; n |= (byte) (x >> 24);
			n <<= 8; n |= (byte) (x >> 32);
			n <<= 8; n |= (byte) (x >> 40);
			n <<= 8; n |= (byte) (x >> 48);
			return (n << 8) | (byte) (x >> 56);
		}
	};
}

#endif // TC_HEADER_Platform_Memory
