#ifndef CRYPTOPP_CONFIG_H
#define CRYPTOPP_CONFIG_H

#ifdef __GNUC__
	#define VC_INLINE	static inline __attribute__((always_inline))
#elif defined (_MSC_VER)
	#define VC_INLINE	__forceinline
#else
	#define VC_INLINE	static inline
#endif

// Clang pretends to be VC++, too.
//   See http://github.com/weidai11/cryptopp/issues/147
#if defined(_MSC_VER) && defined(__clang__) && !defined(_DCSPKG_ANALYZE)
# error: "Unsupported configuration"
#endif

#ifdef __GNUC__
	#define CRYPTOPP_GCC_VERSION (__GNUC__ * 10000 + __GNUC_MINOR__ * 100 + __GNUC_PATCHLEVEL__)
#endif


// Apple and LLVM's Clang. Apple Clang version 7.0 roughly equals LLVM Clang version 3.7
#if defined(__clang__ ) && !defined(__apple_build_version__) && !defined(_DCSPKG_ANALYZE) 
	#define CRYPTOPP_LLVM_CLANG_VERSION (__clang_major__ * 10000 + __clang_minor__ * 100 + __clang_patchlevel__)
	#define CRYPTOPP_CLANG_INTEGRATED_ASSEMBLER 1
#elif defined(__clang__ ) && defined(__apple_build_version__) && !defined(_DCSPKG_ANALYZE)
	#define CRYPTOPP_APPLE_CLANG_VERSION (__clang_major__ * 10000 + __clang_minor__ * 100 + __clang_patchlevel__)
	#define CRYPTOPP_CLANG_INTEGRATED_ASSEMBLER 1
#endif

#if defined(_MSC_VER) && !defined(__clang__)
# undef CRYPTOPP_LLVM_CLANG_VERSION
# define CRYPTOPP_MSC_VERSION (_MSC_VER)
#endif

// Clang due to "Inline assembly operands don't work with .intel_syntax", http://llvm.org/bugs/show_bug.cgi?id=24232
//   TODO: supply the upper version when LLVM fixes it. We set it to 20.0 for compilation purposes.
#if (defined(CRYPTOPP_LLVM_CLANG_VERSION) && CRYPTOPP_LLVM_CLANG_VERSION <= 200000) || (defined(CRYPTOPP_APPLE_CLANG_VERSION) && CRYPTOPP_APPLE_CLANG_VERSION <= 200000) || defined(CRYPTOPP_CLANG_INTEGRATED_ASSEMBLER)
	#define CRYPTOPP_DISABLE_INTEL_ASM 1
#endif

#ifndef CRYPTOPP_L1_CACHE_LINE_SIZE
	// This should be a lower bound on the L1 cache line size. It's used for defense against timing attacks.
    // Also see http://stackoverflow.com/questions/794632/programmatically-get-the-cache-line-size.
    #if defined(_M_X64) || defined(__x86_64__) || (__ILP32__ >= 1)
		#define CRYPTOPP_L1_CACHE_LINE_SIZE 64
	#else
		// L1 cache line size is 32 on Pentium III and earlier
		#define CRYPTOPP_L1_CACHE_LINE_SIZE 32
	#endif
#endif

#if defined(_MSC_VER) && (_MSC_VER > 1200)
	#define CRYPTOPP_MSVC6PP_OR_LATER
#endif

#ifndef CRYPTOPP_ALIGN_DATA
	#if defined(_MSC_VER) && !defined(TC_WINDOWS_BOOT)
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

// Apple's Clang prior to 5.0 cannot handle SSE2 (and Apple does not use LLVM Clang numbering...)
#if defined(CRYPTOPP_APPLE_CLANG_VERSION) && (CRYPTOPP_APPLE_CLANG_VERSION < 50000)
# define CRYPTOPP_DISABLE_ASM
#endif

#if !defined(CRYPTOPP_DISABLE_ASM) && ((defined(_MSC_VER) && defined(_M_IX86)) || (defined(__GNUC__) && (defined(__i386__) || defined(__x86_64__))))
    // C++Builder 2010 does not allow "call label" where label is defined within inline assembly
    #define CRYPTOPP_X86_ASM_AVAILABLE

    #if !defined(CRYPTOPP_DISABLE_SSE2) && (defined(CRYPTOPP_MSVC6PP_OR_LATER) || CRYPTOPP_GCC_VERSION >= 30300 || defined(__SSE2__))
        #define CRYPTOPP_BOOL_SSE2_ASM_AVAILABLE 1
    #else
        #define CRYPTOPP_BOOL_SSE2_ASM_AVAILABLE 0
    #endif

    // SSE3 was actually introduced in GNU as 2.17, which was released 6/23/2006, but we can't tell what version of binutils is installed.
    // GCC 4.1.2 was released on 2/13/2007, so we'll use that as a proxy for the binutils version. Also see the output of
    // `gcc -dM -E -march=native - < /dev/null | grep -i SSE` for preprocessor defines available.
    #if !defined(CRYPTOPP_DISABLE_SSSE3) && (_MSC_VER >= 1400 || CRYPTOPP_GCC_VERSION >= 40102 || defined(__SSSE3__) || defined(__SSE3__))
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

#if !defined(CRYPTOPP_DISABLE_SSE2) && (defined(CRYPTOPP_MSVC6PP_OR_LATER) || defined(__SSE2__)) && !defined(_M_ARM) && !defined(_M_ARM64) && !defined(__arm__) && !defined(__aarch64__) && !defined(__arm64__)
    #define CRYPTOPP_BOOL_SSE2_INTRINSICS_AVAILABLE 1
#else
    #define CRYPTOPP_BOOL_SSE2_INTRINSICS_AVAILABLE 0
#endif

#if !defined(CRYPTOPP_DISABLE_ASM) && !defined(CRYPTOPP_DISABLE_SSSE3) && !defined(_M_ARM) && !defined(_M_ARM64) && !defined(__arm__) && !defined(__aarch64__) && !defined(__arm64__) && ( \
	defined(__SSSE3__) || (_MSC_VER >= 1500) || \
	(CRYPTOPP_GCC_VERSION >= 40300) || (__INTEL_COMPILER >= 1000) || (__SUNPRO_CC >= 0x5110) || \
	(CRYPTOPP_LLVM_CLANG_VERSION >= 20300) || (CRYPTOPP_APPLE_CLANG_VERSION >= 40000))
	#define CRYPTOPP_SSSE3_AVAILABLE 1
#else
	#define CRYPTOPP_SSSE3_AVAILABLE 0
# endif

#if !defined(CRYPTOPP_DISABLE_SSSE3) && (defined(__SSSE3__) || (_MSC_VER >= 1500)) && !defined(_M_ARM) && !defined(_M_ARM64) && !defined(__arm__) && !defined(__aarch64__) && !defined(__arm64__)
    #define CRYPTOPP_BOOL_SSSE3_INTRINSICS_AVAILABLE 1
#else
    #define CRYPTOPP_BOOL_SSSE3_INTRINSICS_AVAILABLE 0
#endif

#if !defined(CRYPTOPP_DISABLE_SSSE3) && !defined(CRYPTOPP_DISABLE_AESNI) && CRYPTOPP_BOOL_SSE2_INTRINSICS_AVAILABLE && (CRYPTOPP_GCC_VERSION >= 40400 || _MSC_FULL_VER >= 150030729 || __INTEL_COMPILER >= 1110 || defined(__AES__))
    #define CRYPTOPP_BOOL_AESNI_INTRINSICS_AVAILABLE 1
#else
    #define CRYPTOPP_BOOL_AESNI_INTRINSICS_AVAILABLE 0
#endif

#if CRYPTOPP_BOOL_SSE2_INTRINSICS_AVAILABLE || CRYPTOPP_BOOL_SSE2_ASM_AVAILABLE || defined(CRYPTOPP_X64_MASM_AVAILABLE)
    #define CRYPTOPP_BOOL_ALIGN16 1
#else
    #define CRYPTOPP_BOOL_ALIGN16 0
#endif

#if CRYPTOPP_BOOL_SSSE3_INTRINSICS_AVAILABLE && (defined(__SSE4_1__) || defined(__INTEL_COMPILER) || defined(_MSC_VER))
    #define CRYPTOPP_BOOL_SSE41_INTRINSICS_AVAILABLE 1
#else
    #define CRYPTOPP_BOOL_SSE41_INTRINSICS_AVAILABLE 0
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

// Linux provides X32, which is 32-bit integers, longs and pointers on x86_64 using the full x86_64 register set.
// Detect via __ILP32__ (http://wiki.debian.org/X32Port). However, __ILP32__ shows up in more places than
// the System V ABI specs calls out, like on just about any 32-bit system with Clang.
#if ((__ILP32__ >= 1) || (_ILP32 >= 1)) && defined(__x86_64__)
    #define CRYPTOPP_BOOL_X32 1
#else
    #define CRYPTOPP_BOOL_X32 0
#endif

// see http://predef.sourceforge.net/prearch.html
#if (defined(_M_IX86) || defined(__i386__) || defined(__i386) || defined(_X86_) || defined(__I86__) || defined(__INTEL__)) && !CRYPTOPP_BOOL_X32
    #define CRYPTOPP_BOOL_X86 1
#else
    #define CRYPTOPP_BOOL_X86 0
#endif

#if (defined(_M_X64) || defined(__x86_64__)) && !CRYPTOPP_BOOL_X32
    #define CRYPTOPP_BOOL_X64 1
#else
    #define CRYPTOPP_BOOL_X64 0
#endif

#if !defined(CRYPTOPP_DISABLE_SHANI) && \
	(CRYPTOPP_BOOL_X32 || CRYPTOPP_BOOL_X86 || CRYPTOPP_BOOL_X64) && \
	defined(CRYPTOPP_BOOL_SSE41_INTRINSICS_AVAILABLE) && \
	(defined(__SHA__) || (_MSC_VER >= 1900) || (__SUNPRO_CC >= 0x5160) || \
	(CRYPTOPP_GCC_VERSION >= 40900) || (__INTEL_COMPILER >= 1600) || \
	(CRYPTOPP_LLVM_CLANG_VERSION >= 30400) || (CRYPTOPP_APPLE_CLANG_VERSION >= 50100))
	#define CRYPTOPP_SHANI_AVAILABLE 1
#else
	#define CRYPTOPP_SHANI_AVAILABLE 0
#endif

#if defined(__arm64__) || defined(__aarch64__) || defined(_M_ARM64)
	#define CRYPTOPP_BOOL_ARMV8 1
	#define CRYPTOPP_BOOL_ARM64 1
#else
	#define CRYPTOPP_BOOL_ARMV8 0
	#define CRYPTOPP_BOOL_ARM64 0
#endif

// ARMv8 and ASIMD. -march=armv8-a or above must be present
// Requires GCC 4.8, Clang 3.3 or Visual Studio 2017
// Do not use APPLE_CLANG_VERSION; use __ARM_FEATURE_XXX instead.
#if !defined(CRYPTOPP_ARM_ASIMD_AVAILABLE) && !defined(CRYPTOPP_DISABLE_ARM_ASIMD)
# if defined(__aarch32__) || defined(__aarch64__) || defined(__arm64__) || defined(_M_ARM64)
#  if defined(__ARM_NEON) || defined(__ARM_ASIMD) || defined(__ARM_FEATURE_NEON) || defined(__ARM_FEATURE_ASIMD) || \
      (CRYPTOPP_GCC_VERSION >= 40800) || (CRYPTOPP_LLVM_CLANG_VERSION >= 30300) || \
      (CRYPTOPP_APPLE_CLANG_VERSION >= 40000) || (CRYPTOPP_MSC_VERSION >= 1916)
#   define CRYPTOPP_ARM_NEON_AVAILABLE 1
#   define CRYPTOPP_ARM_ASIMD_AVAILABLE 1
#  endif  // Compilers
# endif  // Platforms
#endif

// ARMv8 and AES. -march=armv8-a+crypto or above must be present
// Requires GCC 4.8, Clang 3.3 or Visual Studio 2017
#if !defined(CRYPTOPP_ARM_AES_AVAILABLE) && !defined(CRYPTOPP_DISABLE_ARM_AES)
# if defined(__aarch32__) || defined(__aarch64__) || defined(_M_ARM64)
#  if defined(__ARM_FEATURE_CRYPTO) || (CRYPTOPP_GCC_VERSION >= 40800) || \
      (CRYPTOPP_LLVM_CLANG_VERSION >= 30300) || (CRYPTOPP_APPLE_CLANG_VERSION >= 40300) || \
      (CRYPTOPP_MSC_VERSION >= 1916)
#   define CRYPTOPP_ARM_AES_AVAILABLE 1
#  endif  // Compilers
# endif  // Platforms
#endif

// ARMv8 and SHA-1, SHA-256. -march=armv8-a+crypto or above must be present
// Requires GCC 4.8, Clang 3.3 or Visual Studio 2017
#if !defined(CRYPTOPP_ARM_SHA_AVAILABLE) && !defined(CRYPTOPP_DISABLE_ARM_SHA)
# if defined(__aarch32__) || defined(__aarch64__) || defined(_M_ARM64)
#  if defined(__ARM_FEATURE_CRYPTO) || (CRYPTOPP_GCC_VERSION >= 40800) || \
      (CRYPTOPP_LLVM_CLANG_VERSION >= 30300) || (CRYPTOPP_APPLE_CLANG_VERSION >= 40300) || \
      (CRYPTOPP_MSC_VERSION >= 1916)
#   define CRYPTOPP_ARM_SHA1_AVAILABLE 1
#   define CRYPTOPP_ARM_SHA2_AVAILABLE 1
#  endif  // Compilers
# endif  // Platforms
#endif

// Undo the ASM and Intrinsic related defines due to X32.
#if CRYPTOPP_BOOL_X32
# undef CRYPTOPP_BOOL_X64
# undef CRYPTOPP_X64_ASM_AVAILABLE
# undef CRYPTOPP_X64_MASM_AVAILABLE
#endif

#if !defined(CRYPTOPP_NO_UNALIGNED_DATA_ACCESS) && !defined(CRYPTOPP_ALLOW_UNALIGNED_DATA_ACCESS)
#if (CRYPTOPP_BOOL_X64 || CRYPTOPP_BOOL_X86 || CRYPTOPP_BOOL_X32 || defined(__powerpc__) || (__ARM_FEATURE_UNALIGNED >= 1))
    #define CRYPTOPP_ALLOW_UNALIGNED_DATA_ACCESS
#endif
#endif

// this version of the macro is fastest on Pentium 3 and Pentium 4 with MSVC 6 SP5 w/ Processor Pack
#define GETBYTE(x, y) (unsigned int)((unsigned char)((x)>>(8*(y))))
// these may be faster on other CPUs/compilers
// #define GETBYTE(x, y) (unsigned int)(((x)>>(8*(y)))&255)
// #define GETBYTE(x, y) (((uint8 *)&(x))[y])

#define CRYPTOPP_GET_BYTE_AS_BYTE(x, y) ((uint8)((x)>>(8*(y))))

#endif
