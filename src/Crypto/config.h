#ifndef CRYPTOPP_CONFIG_H
#define CRYPTOPP_CONFIG_H

#ifdef __GNUC__
	#define VC_INLINE	static inline __attribute__((always_inline))
#elif defined (_MSC_VER)
	#define VC_INLINE	__forceinline
#else
	#define VC_INLINE	static inline
#endif

#ifdef __GNUC__
	#define CRYPTOPP_GCC_VERSION (__GNUC__ * 10000 + __GNUC_MINOR__ * 100 + __GNUC_PATCHLEVEL__)
#endif

#ifndef CRYPTOPP_L1_CACHE_LINE_SIZE
	// This should be a lower bound on the L1 cache line size. It's used for defense against timing attacks.
	#if defined(_M_X64) || defined(__x86_64__)
		#define CRYPTOPP_L1_CACHE_LINE_SIZE 64
	#else
		// L1 cache line size is 32 on Pentium III and earlier
		#define CRYPTOPP_L1_CACHE_LINE_SIZE 32
	#endif
#endif

#ifndef CRYPTOPP_ALIGN_DATA
	#if defined(_MSC_VER)
		#define CRYPTOPP_ALIGN_DATA(x) __declspec(align(x))
	#elif defined(__GNUC__)
		#define CRYPTOPP_ALIGN_DATA(x) __attribute__((aligned(x)))
	#else
		#define CRYPTOPP_ALIGN_DATA(x)
	#endif
#endif

#ifndef CRYPTOPP_SECTION_ALIGN16
	#if defined(__GNUC__) && !defined(__APPLE__)
		// the alignment attribute doesn't seem to work without this section attribute when -fdata-sections is turned on
		#define CRYPTOPP_SECTION_ALIGN16 __attribute__((section ("CryptoPP_Align16")))
	#else
		#define CRYPTOPP_SECTION_ALIGN16
	#endif
#endif

#if defined(_MSC_VER) || defined(__fastcall)
	#define CRYPTOPP_FASTCALL __fastcall
#else
	#define CRYPTOPP_FASTCALL
#endif

#ifdef CRYPTOPP_DISABLE_X86ASM		// for backwards compatibility: this macro had both meanings
#define CRYPTOPP_DISABLE_ASM
#define CRYPTOPP_DISABLE_SSE2
#endif

#if !defined(CRYPTOPP_DISABLE_ASM) && ((defined(_MSC_VER) && defined(_M_IX86)) || (defined(__GNUC__) && (defined(__i386__) || defined(__x86_64__))))
	// C++Builder 2010 does not allow "call label" where label is defined within inline assembly
	#define CRYPTOPP_X86_ASM_AVAILABLE

	#if !defined(CRYPTOPP_DISABLE_SSE2) && (defined(_MSC_VER) || CRYPTOPP_GCC_VERSION >= 30300)
		#define CRYPTOPP_BOOL_SSE2_ASM_AVAILABLE 1
	#else
		#define CRYPTOPP_BOOL_SSE2_ASM_AVAILABLE 0
	#endif

	// SSSE3 was actually introduced in GNU as 2.17, which was released 6/23/2006, but we can't tell what version of binutils is installed.
	// GCC 4.1.2 was released on 2/13/2007, so we'll use that as a proxy for the binutils version.
	#if !defined(CRYPTOPP_DISABLE_SSSE3) && (_MSC_VER >= 1400 || CRYPTOPP_GCC_VERSION >= 40102)
		#define CRYPTOPP_BOOL_SSSE3_ASM_AVAILABLE 1
	#else
		#define CRYPTOPP_BOOL_SSSE3_ASM_AVAILABLE 0
	#endif
#endif

#if !defined(CRYPTOPP_DISABLE_ASM) && defined(_MSC_VER) && defined(_M_X64)
	#define CRYPTOPP_X64_MASM_AVAILABLE
#endif

#if !defined(CRYPTOPP_DISABLE_ASM) && defined(__GNUC__) && defined(__x86_64__)
	#define CRYPTOPP_X64_ASM_AVAILABLE
#endif

#if !defined(CRYPTOPP_DISABLE_SSE2) && (defined(_MSC_VER) || defined(__SSE2__))
	#define CRYPTOPP_BOOL_SSE2_INTRINSICS_AVAILABLE 1
#else
	#define CRYPTOPP_BOOL_SSE2_INTRINSICS_AVAILABLE 0
#endif

#if !defined(CRYPTOPP_DISABLE_SSSE3) && !defined(CRYPTOPP_DISABLE_AESNI) && CRYPTOPP_BOOL_SSE2_INTRINSICS_AVAILABLE && (CRYPTOPP_GCC_VERSION >= 40400 || _MSC_FULL_VER >= 150030729 || __INTEL_COMPILER >= 1110)
	#define CRYPTOPP_BOOL_AESNI_INTRINSICS_AVAILABLE 1
#else
	#define CRYPTOPP_BOOL_AESNI_INTRINSICS_AVAILABLE 0
#endif

#if CRYPTOPP_BOOL_SSE2_INTRINSICS_AVAILABLE || CRYPTOPP_BOOL_SSE2_ASM_AVAILABLE || defined(CRYPTOPP_X64_MASM_AVAILABLE)
	#define CRYPTOPP_BOOL_ALIGN16_ENABLED 1
#else
	#define CRYPTOPP_BOOL_ALIGN16_ENABLED 0
#endif

// how to allocate 16-byte aligned memory (for SSE2)
#if defined(_MSC_VER)
	#define CRYPTOPP_MM_MALLOC_AVAILABLE
#elif defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
	#define CRYPTOPP_MALLOC_ALIGNMENT_IS_16
#elif defined(__linux__) || defined(__sun__) || defined(__CYGWIN__)
	#define CRYPTOPP_MEMALIGN_AVAILABLE
#else
	#define CRYPTOPP_NO_ALIGNED_ALLOC
#endif

// how to declare class constants
#if (defined(_MSC_VER) && _MSC_VER <= 1300) || defined(__INTEL_COMPILER)
#	define CRYPTOPP_CONSTANT(x) enum {x};
#else
#	define CRYPTOPP_CONSTANT(x) static const int x;
#endif

#if defined(_M_X64) || defined(__x86_64__)
	#define CRYPTOPP_BOOL_X64 1
#else
	#define CRYPTOPP_BOOL_X64 0
#endif

// see http://predef.sourceforge.net/prearch.html
#if defined(_M_IX86) || defined(__i386__) || defined(__i386) || defined(_X86_) || defined(__I86__) || defined(__INTEL__)
	#define CRYPTOPP_BOOL_X86 1
#else
	#define CRYPTOPP_BOOL_X86 0
#endif

#if CRYPTOPP_BOOL_X64 || CRYPTOPP_BOOL_X86 || defined(__powerpc__)
	#define CRYPTOPP_ALLOW_UNALIGNED_DATA_ACCESS
#endif

#define GETBYTE(x, y) (unsigned int)((unsigned char)((x)>>(8*(y))))

#endif
