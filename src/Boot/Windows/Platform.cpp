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

#include "Platform.h"
#include "BootConsoleIo.h"


uint64 operator+ (const uint64 &a, const uint64 &b)
{
	int carry = 0;
	uint64 r;

	r.LowPart = a.LowPart + b.LowPart;
	__asm
	{
		jnc nocarry
		mov carry, 1
	nocarry:
	}

	r.HighPart = a.HighPart + b.HighPart + carry;

	return r;
}

uint64 operator+ (const uint64 &a, uint32 b)
{
	uint64 b64;
	b64.HighPart = 0;
	b64.LowPart = b;
	return a + b64;
}

uint64 &operator+= (uint64 &a, const uint64 &b)
{
	return a = a + b;
}

uint64 operator- (const uint64 &a, const uint64 &b)
{
	int carry = 0;
	uint64 r;

	r.LowPart = a.LowPart - b.LowPart;
	__asm
	{
		jnc nocarry
		mov carry, 1
	nocarry:
	}

	r.HighPart = a.HighPart - b.HighPart - carry;

	return r;
}

uint64 operator- (const uint64 &a, uint32 b)
{
	uint64 b64;
	b64.HighPart = 0;
	b64.LowPart = b;
	return a - b64;
}

uint64 &operator-= (uint64 &a, const uint64 &b)
{
	return a = a - b;
}

uint64 operator>> (const uint64 &a, int shiftCount)
{
	uint64 r = a;

	while (shiftCount--)
	{
		r.LowPart >>= 1;

		if ((byte) r.HighPart & 1)
			r.LowPart |= 0x80000000UL;

		r.HighPart >>= 1;
	}

	return r;
}

uint64 operator<< (const uint64 &a, int shiftCount)
{
	uint64 r = a;

	while (shiftCount--)
		r += r;

	return r;
}

uint64 &operator++ (uint64 &a)
{
	uint64 b;
	b.HighPart = 0;
	b.LowPart = 1;

	return a += b;
}

bool operator== (const uint64 &a, const uint64 &b)
{
	return a.HighPart == b.HighPart && a.LowPart == b.LowPart;
}

bool operator> (const uint64 &a, const uint64 &b)
{
	return (a.HighPart > b.HighPart) || (a.HighPart == b.HighPart && a.LowPart > b.LowPart);
}

bool operator< (const uint64 &a, const uint64 &b)
{
	return (a.HighPart < b.HighPart) || (a.HighPart == b.HighPart && a.LowPart < b.LowPart);
}

bool operator>= (const uint64 &a, const uint64 &b)
{
	return a > b || a == b;
}

bool operator<= (const uint64 &a, const uint64 &b)
{
	return a < b || a == b;
}

#ifdef TC_BOOT_DEBUG_ENABLED

bool TestInt64 ()
{
	uint64 a, b, c;
	a.HighPart = 0x00112233UL;
	a.LowPart = 0xabcd1234UL;

	b.HighPart = 0x00ffeeddUL;
	b.LowPart = 0xffffFFFFUL;

	a += b;
	a -= b;

	++a;

	b = b + (uint32) 1UL;

	c = (a - ((a + b) >> 32) - (uint32) 1UL);
	if (c.HighPart != 0x112233UL || c.LowPart != 0xAABC0123UL)
		return false;

	c = c << 9;
	return c.HighPart == 0x22446755UL && c.LowPart == 0x78024600UL;
}

#endif

void CopyMemory (void *source, uint16 destSegment, uint16 destOffset, uint16 blockSize)
{
	__asm
	{
		push es
		mov si, ss:source
		mov es, ss:destSegment
		mov di, ss:destOffset
		mov cx, ss:blockSize
		cld
		rep movsb
		pop es
	}
}


void CopyMemory (uint16 sourceSegment, uint16 sourceOffset, void *destination, uint16 blockSize)
{
	__asm
	{
		push ds
		push es
		mov ax, ds
		mov es, ax
		mov di, ss:destination
		mov si, ss:sourceOffset
		mov cx, ss:blockSize
		mov ds, ss:sourceSegment
		cld
		rep movsb
		pop es
		pop ds
	}
}


void EraseMemory (void *memory, int size)
{
	memset (memory, 0, size);
}


uint32 GetLinearAddress (uint16 segment, uint16 offset)
{
	return (uint32 (segment) << 4) + offset;
}


bool RegionsIntersect (const uint64 &start1, uint32 length1, const uint64 &start2, const uint64 &end2)
{
	uint64 end1 = start1 + length1 - 1UL;
	uint64 intersectEnd = (end1 <= end2) ? end1 : end2;

	uint64 intersectStart = (start1 >= start2) ? start1 : start2;
	if (intersectStart > intersectEnd)
		return false;

	return (intersectEnd + 1UL - intersectStart).LowPart != 0;
}


void ThrowFatalException (int line)
{
	PrintChar ('#'); Print (line);
	while (1);
}
