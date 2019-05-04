/*
 Derived from source code of TrueCrypt 7.1a, which is
 Copyright (c) 2008-2012 TrueCrypt Developers Association and which is governed
 by the TrueCrypt License 3.0.

 Modifications and additions to the original source code (contained in this file)
 and all other portions of this file are Copyright (c) 2013-2017 IDRIX
 and are governed by the Apache License 2.0 the full text of which is
 contained in the file License.txt included in VeraCrypt binary and source
 code distribution packages.
*/

#ifndef TC_HEADER_Boot_Platform
#define TC_HEADER_Boot_Platform

#pragma warning (disable: 4018 4102 4704 4769)

#include "TCdefs.h"
#include <memory.h>

typedef char bool;
#define false 0
#define true 1

#define nullptr 0
#define NULL 0

typedef UINT64_STRUCT uint64;

#define array_capacity(arr) (sizeof (arr) / sizeof ((arr)[0]))

#define TC_TO_STRING2(n) #n
#define TC_TO_STRING(n) TC_TO_STRING2(n)


#define TC_X86_CARRY_FLAG 0x1

#define TC_ASM_EMIT(A,B) __asm _emit 0x##A __asm _emit 0x##B
#define TC_ASM_EMIT3(A,B,C) __asm _emit 0x##A __asm _emit 0x##B __asm _emit 0x##C
#define TC_ASM_EMIT4(A,B,C,D) __asm _emit 0x##A __asm _emit 0x##B __asm _emit 0x##C __asm _emit 0x##D

#define TC_ASM_MOV_EAX_DI TC_ASM_EMIT3 (66, 8B, 05)
#define TC_ASM_MOV_EBX_DI TC_ASM_EMIT3 (66, 8B, 1D)
#define TC_ASM_MOV_ECX_DI TC_ASM_EMIT3 (66, 8B, 0D)
#define TC_ASM_MOV_EDX_DI TC_ASM_EMIT3 (66, 8B, 15)

#define TC_ASM_MOV_DI_EAX TC_ASM_EMIT3 (66, 89, 05)
#define TC_ASM_MOV_DI_EBX TC_ASM_EMIT3 (66, 89, 1D)
#define TC_ASM_MOV_DI_ECX TC_ASM_EMIT3 (66, 89, 0D)
#define TC_ASM_MOV_DI_EDX TC_ASM_EMIT3 (66, 89, 15)


#pragma pack(1)

struct Registers
{
	uint16 Flags;

	union
	{
		uint32 EAX;
		struct { uint16 AX; uint16 EAXH; };
	};

	union
	{
		uint32 EBX;
		struct { uint16 BX; uint16 EBXH; };
	};

	union
	{
		uint32 ECX;
		struct { uint16 CX; uint16 ECXH; };
	};

	union
	{
		uint32 EDX;
		struct { uint16 DX; uint16 EDXH; };
	};

	uint16 DI;
	uint16 SI;
	uint16 DS;
	uint16 ES;
	uint16 SS;
};

#pragma pack()


uint64 operator+ (const uint64 &a, const uint64 &b);
uint64 operator+ (const uint64 &a, uint32 b);
uint64 &operator+= (uint64 &a, const uint64 &b);
uint64 operator- (const uint64 &a, const uint64 &b);
uint64 operator- (const uint64 &a, uint32 b);
uint64 &operator-= (uint64 &a, const uint64 &b);
uint64 operator>> (const uint64 &a, int shiftCount);
uint64 operator<< (const uint64 &a, int shiftCount);
uint64 &operator++ (uint64 &a);
bool operator== (const uint64 &a, const uint64 &b);
bool operator> (const uint64 &a, const uint64 &b);
bool operator< (const uint64 &a, const uint64 &b);
bool operator>= (const uint64 &a, const uint64 &b);
bool operator<= (const uint64 &a, const uint64 &b);

void CopyMemory (void *source, uint16 destSegment, uint16 destOffset, uint16 blockSize);
void CopyMemory (uint16 sourceSegment, uint16 sourceOffset, void *destination, uint16 blockSize);
extern "C" void EraseMemory (void *memory, int size);
uint32 GetLinearAddress (uint16 segment, uint16 offset);
bool RegionsIntersect (const uint64 &start1, uint32 length1, const uint64 &start2, const uint64 &end2);
#ifdef TC_BOOT_DEBUG_ENABLED
bool TestInt64 ();
#endif
extern "C" void ThrowFatalException (int line);

#endif // TC_HEADER_Boot_Platform
