/*
 Copyright (c) 2008 TrueCrypt Developers Association. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

#ifndef TC_HEADER_Boot_BootDebug
#define TC_HEADER_Boot_BootDebug

#include "Platform.h"
#include "BootConsoleIo.h"

#if 0
#	define TC_BOOT_DEBUG_ENABLED
#endif

#if 0 || defined (TC_BOOT_DEBUG_ENABLED)
#	define TC_BOOT_STACK_CHECKING_ENABLED
	extern "C" void CheckStack ();
#else
#	define CheckStack()
#endif

#if 0
#	define TC_BOOT_TRACING_ENABLED
#	if 1
#		define TC_TRACE_INT13
#	endif
#	if 0
#		define TC_TRACE_INT15
#	endif
#endif

#ifdef TC_BOOT_DEBUG_ENABLED
#	define trace_point do { Print(__FILE__); PrintChar (':'); Print (TC_TO_STRING (__LINE__)); PrintEndl(); } while (false)
#	define trace_val(VAL) PrintVal (#VAL, VAL);
#	define trace_hex(VAL) do { Print (#VAL), PrintChar (':'); PrintHex (VAL); PrintEndl(); } while (false)
#	define assert(COND) do { if (!(COND)) { trace_point; __asm jmp $ } } while (false)
#else
#	define trace_point
#	define trace_val(VAL)
#	define trace_hex(VAL)
#	define assert(COND)
#endif

void InitDebugPort ();
void InitStackChecker ();
void WriteDebugPort (byte dataByte);
void PrintHexDump (byte *mem, size_t size, uint16 *memSegment = nullptr);
void PrintHexDump (uint16 memSegment, uint16 memOffset, size_t size);
void PrintVal (const char *message, const uint32 value, bool newLine = true, bool hex = false);
void PrintVal (const char *message, const uint64 &value, bool newLine = true, bool hex = false);

#endif // TC_HEADER_Boot_BootDebug
