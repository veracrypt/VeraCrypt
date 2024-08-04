/*
 Legal Notice: Some portions of the source code contained in this file were
 derived from the source code of TrueCrypt 7.1a, which is
 Copyright (c) 2003-2012 TrueCrypt Developers Association and which is
 governed by the TrueCrypt License 3.0, also from the source code of
 Encryption for the Masses 2.02a, which is Copyright (c) 1998-2000 Paul Le Roux
 and which is governed by the 'License Agreement for Encryption for the Masses'
 Modifications and additions to the original source code (contained in this file)
 and all other portions of this file are Copyright (c) 2013-2017 IDRIX
 and are governed by the Apache License 2.0 the full text of which is
 contained in the file License.txt included in VeraCrypt binary and source
 code distribution packages. */

#ifndef TCDEFS_H
#define TCDEFS_H

#if defined(_UEFI)
#undef  _WIN32
#undef  _WIN64
#undef  _DEBUG

#include <Uefi.h> 
#include <Library/BaseLib.h> 
#include <Library/BaseMemoryLib.h>

void* VeraCryptMemAlloc(IN UINTN size);
void VeraCryptMemFree(IN VOID* ptr);

#define BOOL int
#ifndef FALSE
#define FALSE 0
#define TRUE 1
#endif

#define max(a,b)	((a)>(b))?(a):(b)
#define min(a,b)	((a)<(b))?(a):(b)

#ifdef  __cplusplus
extern "C" {
#endif
extern unsigned __int64 __cdecl _rotl64(unsigned __int64,int);
extern unsigned __int64 __cdecl _rotr64(unsigned __int64,int);
extern unsigned int __cdecl _rotl(unsigned int,int);
extern unsigned int __cdecl _rotr(unsigned int,int);
extern unsigned char _rotr8(unsigned char value, unsigned char shift);
extern unsigned short _rotr16(unsigned short value, unsigned char shift);
extern unsigned char _rotl8(unsigned char value, unsigned char shift);
extern unsigned short _rotl16(unsigned short value, unsigned char shift);
#ifdef  __cplusplus
}
#endif

#endif // defined(_UEFI)

#ifdef TC_WINDOWS_BOOT
#include <stddef.h>
#endif

#define TC_APP_NAME						"VeraCrypt"

// Version displayed to user 
#define VERSION_STRING					"1.26.13"

#ifdef VC_EFI_CUSTOM_MODE
#define VERSION_STRING_SUFFIX			"-CustomEFI"
#elif defined(VC_SKIP_OS_DRIVER_REQ_CHECK)
#define VERSION_STRING_SUFFIX			"-TESTSIGNING"
#else
#define VERSION_STRING_SUFFIX			""
#endif

// Version number to compare against driver
#define VERSION_NUM						0x0126

// Release date
#define TC_STR_RELEASE_DATE			L"August 4, 2024"
#define TC_RELEASE_DATE_YEAR			2024
#define TC_RELEASE_DATE_MONTH			 8

#define BYTES_PER_KB                    1024LL
#define BYTES_PER_MB                    1048576LL
#define BYTES_PER_GB                    1073741824LL
#define BYTES_PER_TB                    1099511627776LL
#define BYTES_PER_PB                    1125899906842624LL

/* GUI/driver errors */

#define WIDE(x) (LPWSTR)L##x

#define VC_MAX(a,b)	((a)>(b))?(a):(b)
#define VC_MIN(a,b)	((a)<(b))?(a):(b)

#ifdef _MSC_VER

typedef __int8 int8;
typedef __int16 int16;
typedef __int32 int32;
typedef unsigned __int8 uint8;
typedef unsigned __int16 uint16;
typedef unsigned __int32 uint32;

#ifdef TC_NO_COMPILER_INT64
typedef unsigned __int32	TC_LARGEST_COMPILER_UINT;
#else
typedef unsigned __int64	TC_LARGEST_COMPILER_UINT;
typedef __int64 int64;
typedef unsigned __int64 uint64;
#define LL(x) x##ui64
#endif

#pragma warning( disable : 4201 )  // disable: 4201 nonstandard extension used : nameless struct/union
#pragma warning( disable : 4324 )  // disable: 4324 structure was padded due to __declspec(align())

#else // !_MSC_VER

#include <inttypes.h>
#include <limits.h>
#include <memory.h>

typedef int8_t int8;
typedef int16_t int16;
typedef int32_t int32;
typedef int64_t int64;
typedef uint8_t uint8;
typedef uint16_t uint16;
typedef uint32_t uint32;
typedef uint64_t uint64;

#define LL(x) x##ULL

#if UCHAR_MAX != 0xffU
#error UCHAR_MAX != 0xff
#endif
#define __int8 char

#if USHRT_MAX != 0xffffU
#error USHRT_MAX != 0xffff
#endif
#define __int16 short

#if UINT_MAX != 0xffffffffU
#error UINT_MAX != 0xffffffff
#endif
#define __int32 int

typedef uint64 TC_LARGEST_COMPILER_UINT;

#define BOOL int
#ifndef FALSE
#define FALSE 0
#define TRUE 1
#endif

#endif // !_MSC_VER

#define TC_INT_TYPES_DEFINED

// Integer types required by Cryptolib
typedef unsigned __int8 uint_8t;
typedef unsigned __int16 uint_16t;
typedef unsigned __int32 uint_32t;
#ifndef TC_NO_COMPILER_INT64
typedef uint64 uint_64t;
#endif

typedef union
{
	struct
	{
		unsigned __int32 LowPart;
		unsigned __int32 HighPart;
	};
#ifndef TC_NO_COMPILER_INT64
	uint64 Value;
#endif

} UINT64_STRUCT;

#ifndef __has_builtin       // Optional of course
#define __has_builtin(x) 0  // Compatibility with non-clang compilers
#endif

#if defined(_UEFI)
typedef UINTN size_t;
typedef uint64 uint_64t;
typedef CHAR16 wchar_t;
typedef int LONG;

#define StringCchCopyW StrCpyS
#define wcslen StrLen
#define wcscmp StrCmp
#define StringCchCatW StrCatS

#define memcpy(dest,source,count)         CopyMem(dest,source,(UINTN)(count))
#define memset(dest,ch,count)             SetMem(dest,(UINTN)(count),(UINT8)(ch))
#define memchr(buf,ch,count)              ScanMem8(buf,(UINTN)(count),(UINT8)ch)
#define memcmp(buf1,buf2,count)           (int)(CompareMem(buf1,buf2,(UINTN)(count)))

#define MAX_STRING_SIZE  0x1000
#define strcat(strDest,strSource)         AsciiStrCatS(strDest,MAX_STRING_SIZE,strSource)
#define strchr(str,ch)                    ScanMem8((VOID *)(str),AsciiStrSize(str),(UINT8)ch)
#define strcmp                            AsciiStrCmp
#define strncmp(string1,string2,count)    (int)(AsciiStrnCmp(string1,string2,(UINTN)(count)))
#define StringCchCopyA(strDest,strMaxSize,strSource)         AsciiStrCpyS(strDest,strMaxSize,strSource)
#define strncpy(strDest,strSource,count)  AsciiStrnCpyS(strDest,MAX_STRING_SIZE,strSource,(UINTN)count)
#define strlen(str)                       (size_t)(AsciiStrnLenS(str,MAX_STRING_SIZE))
#define strstr                            AsciiStrStr

// #define rotr32(x,n)	(((x) >> n) | ((x) << (32 - n)))
// #define rotl32(x,n)	(((x) << n) | ((x) >> (32 - n)))
// #define rotr64(x,n)	(((x) >> n) | ((x) << (64 - n)))
// #define rotl64(x,n)	(((x) << n) | ((x) >> (64 - n)))
// #define bswap_32(x)	(rotl32((((x) & 0xFF00FF00) >> 8) | (((x) & 0x00FF00FF) << 8), 16U))
// #define bswap_64(x)	rotl64(((((((x & LL(0xFF00FF00FF00FF00)) >> 8) | ((x & LL(0x00FF00FF00FF00FF)) << 8)) & LL(0xFFFF0000FFFF0000)) >> 16) | (((((x & LL(0xFF00FF00FF00FF00)) >> 8) | ((x & LL(0x00FF00FF00FF00FF)) << 8)) & LL(0x0000FFFF0000FFFF)) << 16)), 32U)

#endif

#ifdef TC_WINDOWS_BOOT

#	ifdef  __cplusplus
extern "C"
#	endif
void ThrowFatalException (int line);

#	define TC_THROW_FATAL_EXCEPTION	ThrowFatalException (__LINE__)
#elif defined (TC_WINDOWS_DRIVER)
#	define TC_THROW_FATAL_EXCEPTION KeBugCheckEx (SECURITY_SYSTEM, __LINE__, 0, 0, 'VC')
#elif defined(_UEFI)
void ThrowFatalException(int line);
#	define TC_THROW_FATAL_EXCEPTION	ThrowFatalException (__LINE__)
#elif (defined(__clang__) && __has_builtin(__builtin_trap)) \
    || (defined(__GNUC__ ) && (__GNUC__ > 3 || (__GNUC__ == 3 && __GNUC_MINOR__ >= 3))) \
    || (__has_builtin(__builtin_trap))
#   define TC_THROW_FATAL_EXCEPTION __builtin_trap()
#else
#	define TC_THROW_FATAL_EXCEPTION	*(char *) 0 = 0
#endif

#ifdef __COVERITY__
#undef TC_THROW_FATAL_EXCEPTION
#define TC_THROW_FATAL_EXCEPTION __coverity_panic__()
#endif

#ifdef TC_WINDOWS_DRIVER

#include <ntifs.h>
#include <ntddk.h>		/* Standard header file for nt drivers */
#include <ntdddisk.h>		/* Standard I/O control codes  */

/* defines needed for using enhanced protection of NX pool under Windows 8 and later */
#define NonPagedPoolNx  512
#define MdlMappingNoExecute     0x40000000

/* variables used in the implementation of enhanced protection of NX pool under Windows 8 and later */
extern POOL_TYPE ExDefaultNonPagedPoolType;
extern ULONG ExDefaultMdlProtection;
#ifdef _WIN64
extern ULONG AllocTag;
#else
#define AllocTag 'MMCV'
#endif

#define TCalloc(size) ((void *) ExAllocatePoolWithTag( ExDefaultNonPagedPoolType, size, AllocTag ))
#define TCfree(memblock) ExFreePoolWithTag( memblock, AllocTag )

#define DEVICE_DRIVER

#ifndef BOOL
typedef int BOOL;
#endif

#ifndef WORD
typedef USHORT WORD;
#endif

#ifndef BOOLEAN
typedef unsigned char  BOOLEAN;
#endif

#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE !TRUE
#endif

typedef NTSTATUS (NTAPI *KeSaveExtendedProcessorStateFn) (
    __in ULONG64 Mask,
    PXSTATE_SAVE XStateSave
    );


typedef VOID (NTAPI *KeRestoreExtendedProcessorStateFn) (
	PXSTATE_SAVE XStateSave
	);

typedef NTSTATUS (NTAPI *ExGetFirmwareEnvironmentVariableFn) (
  PUNICODE_STRING VariableName,
  LPGUID          VendorGuid,
  PVOID           Value,
  PULONG          ValueLength,
  PULONG          Attributes
);

typedef ULONG64 (NTAPI *KeQueryInterruptTimePreciseFn)(
  PULONG64 QpcTimeStamp
);

typedef BOOLEAN (NTAPI *KeAreAllApcsDisabledFn) ();

typedef void (NTAPI *KeSetSystemGroupAffinityThreadFn)(
  PGROUP_AFFINITY Affinity,
  PGROUP_AFFINITY PreviousAffinity
);

typedef USHORT (NTAPI *KeQueryActiveGroupCountFn)();

typedef ULONG (NTAPI *KeQueryActiveProcessorCountExFn)(
  USHORT GroupNumber
);

extern NTSTATUS NTAPI KeSaveExtendedProcessorStateVC (
    __in ULONG64 Mask,
    PXSTATE_SAVE XStateSave
    );


extern VOID NTAPI KeRestoreExtendedProcessorStateVC (
	PXSTATE_SAVE XStateSave
	);

extern BOOLEAN VC_KeAreAllApcsDisabled (VOID);


#else				/* !TC_WINDOWS_DRIVER */
#if !defined(_UEFI)
#define TCalloc malloc
#define TCfree free
#else
#define TCalloc VeraCryptMemAlloc
#define TCfree VeraCryptMemFree
#endif //!defined(_UEFI)

#ifdef _WIN32

#ifndef TC_LOCAL_WIN32_WINNT_OVERRIDE
#	undef _WIN32_WINNT
#ifdef _M_ARM64
#	define  _WIN32_WINNT 0x0A00
#else
#	define	_WIN32_WINNT 0x0601	/* Does not apply to the driver */
#endif
#endif

#include <windows.h>		/* Windows header */
#include <commctrl.h>		/* The common controls */
#include <process.h>		/* Process control */
#include <winioctl.h>
#include <stdio.h>		/* For sprintf */
#include <tchar.h>

#endif				/* _WIN32 */

#endif				/* !TC_WINDOWS_DRIVER */

#ifndef TC_TO_STRING
#	define TC_TO_STRING2(n) #n
#	define TC_TO_STRING(n) TC_TO_STRING2(n)
#endif

#ifdef DEVICE_DRIVER
#	if defined (DEBUG) || defined (DEBUG_TRACE)
#		if 0 // DbgPrintEx is not available on Windows 2000
#			define Dump DbgPrint
#		else
#			define Dump(...) DbgPrintEx (DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, __VA_ARGS__)
#		endif
#		define DumpMem(...) DumpMemory (__VA_ARGS__)
#	else
#		define Dump(...)
#		define DumpMem(...)
#	endif
#elif !defined (TC_WINDOWS_BOOT)
#	define Dump(...)
#	define DumpMem(...)
#endif

#if !defined (trace_msg) && !defined (TC_WINDOWS_BOOT)
#	if defined(DEBUG) || defined (DEBUG_TRACE)
#		ifdef DEVICE_DRIVER
#			define trace_msg Dump
#		elif defined (_WIN32)
#			define trace_msg(...) do { char msg[2048]; StringCbPrintfA (msg, sizeof (msg), __VA_ARGS__); OutputDebugString (msg); } while (0)
#		else
#			define trace_msg(...)
#		endif
#		define trace_point trace_msg (__FUNCTION__ ":" TC_TO_STRING(__LINE__) "\n")
#	else
#		define trace_msg(...)
#		define trace_point
#	endif
#endif

#ifdef DEVICE_DRIVER
#	define TC_EVENT KEVENT
#	define TC_WAIT_EVENT(EVENT) KeWaitForSingleObject (&EVENT, Executive, KernelMode, FALSE, NULL)
#elif defined (_WIN32)
#	define TC_EVENT HANDLE
#	define TC_WAIT_EVENT(EVENT) WaitForSingleObject (EVENT, INFINITE)
#endif

#if defined(_WIN32) && !defined(_UEFI)
#define burn(mem,size) do { volatile char *burnm = (volatile char *)(mem); size_t burnc = size; RtlSecureZeroMemory (mem, size); while (burnc--) *burnm++ = 0; } while (0)
#else
#define burn(mem,size) do { volatile char *burnm = (volatile char *)(mem); int burnc = size; while (burnc--) *burnm++ = 0; } while (0)
#endif

#define volatile_memcpy(d,s,size) do { volatile char *destm = (volatile char *)(d); volatile char *srcm = (volatile char *)(s); size_t memc = size; while (memc--) *destm++ = *srcm++; } while (0)

// The size of the memory area to wipe is in bytes amd it must be a multiple of 8.
#ifndef TC_NO_COMPILER_INT64
#	define FAST_ERASE64(mem,size) do { volatile uint64 *burnm = (volatile uint64 *)(mem); int burnc = size >> 3; while (burnc--) *burnm++ = 0; } while (0)
#else
#	define FAST_ERASE64(mem,size) do { volatile unsigned __int32 *burnm = (volatile unsigned __int32 *)(mem); int burnc = size >> 2; while (burnc--) *burnm++ = 0; } while (0)
#endif

#ifdef TC_WINDOWS_BOOT
#	ifndef max
#		define max(a,b) (((a) > (b)) ? (a) : (b))
#	endif

#	if defined(__cplusplus) && !defined(_UEFI)
extern "C"
#	endif
void EraseMemory (void *memory, int size);

#	undef burn
#	define burn EraseMemory
#endif

#ifdef MAX_PATH
#define TC_MAX_PATH		MAX_PATH
#else
#define TC_MAX_PATH		260	/* Includes the null terminator */
#endif

#define TC_STR_RELEASED_BY L"Released by IDRIX on " TC_STR_RELEASE_DATE

#define MAX_URL_LENGTH	2084 /* Internet Explorer limit. Includes the terminating null character. */

#define TC_HOMEPAGE L"https://www.idrix.fr/"
#define TC_APPLINK L"https://www.veracrypt.fr"

enum
{
	/* WARNING: ADD ANY NEW CODES AT THE END (DO NOT INSERT THEM BETWEEN EXISTING). DO *NOT* DELETE ANY
	EXISTING CODES! Changing these values or their meanings may cause incompatibility with other versions
	(for example, if a new version of the TrueCrypt installer receives an error code from an installed
	driver whose version is lower, it will report and interpret the error incorrectly). */

	ERR_SUCCESS								= 0,
	ERR_OS_ERROR							= 1,
	ERR_OUTOFMEMORY							= 2,
	ERR_PASSWORD_WRONG						= 3,
	ERR_VOL_FORMAT_BAD						= 4,
	ERR_DRIVE_NOT_FOUND						= 5,
	ERR_FILES_OPEN							= 6,
	ERR_VOL_SIZE_WRONG						= 7,
	ERR_COMPRESSION_NOT_SUPPORTED			= 8,
	ERR_PASSWORD_CHANGE_VOL_TYPE			= 9,
	ERR_PASSWORD_CHANGE_VOL_VERSION			= 10,
	ERR_VOL_SEEKING							= 11,
	ERR_VOL_WRITING							= 12,
	ERR_FILES_OPEN_LOCK						= 13,
	ERR_VOL_READING							= 14,
	ERR_DRIVER_VERSION						= 15,
	ERR_NEW_VERSION_REQUIRED				= 16,
	ERR_CIPHER_INIT_FAILURE					= 17,
	ERR_CIPHER_INIT_WEAK_KEY				= 18,
	ERR_SELF_TESTS_FAILED					= 19,
	ERR_SECTOR_SIZE_INCOMPATIBLE			= 20,
	ERR_VOL_ALREADY_MOUNTED					= 21,
	ERR_NO_FREE_DRIVES						= 22,
	ERR_FILE_OPEN_FAILED					= 23,
	ERR_VOL_MOUNT_FAILED					= 24,
	DEPRECATED_ERR_INVALID_DEVICE			= 25,
	ERR_ACCESS_DENIED						= 26,
	ERR_MODE_INIT_FAILED					= 27,
	ERR_DONT_REPORT							= 28,
	ERR_ENCRYPTION_NOT_COMPLETED			= 29,
	ERR_PARAMETER_INCORRECT					= 30,
	ERR_SYS_HIDVOL_HEAD_REENC_MODE_WRONG	= 31,
	ERR_NONSYS_INPLACE_ENC_INCOMPLETE		= 32,
	ERR_USER_ABORT							= 33,
	ERR_RAND_INIT_FAILED					= 34,
	ERR_CAPI_INIT_FAILED					= 35,
	ERR_XTS_MASTERKEY_VULNERABLE			= 36,
	ERR_SYSENC_XTS_MASTERKEY_VULNERABLE			= 37
};

#endif 	// #ifndef TCDEFS_H
