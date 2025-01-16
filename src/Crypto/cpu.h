#ifndef CRYPTOPP_CPU_H
#define CRYPTOPP_CPU_H

#include "Common/Tcdefs.h"
#include "config.h"

// Applies to both X86/X32/X64 and ARM32/ARM64
#if defined(CRYPTOPP_LLVM_CLANG_VERSION) || defined(CRYPTOPP_APPLE_CLANG_VERSION) || defined(CRYPTOPP_CLANG_INTEGRATED_ASSEMBLER)
	#define NEW_LINE "\n"
	#define INTEL_PREFIX ".intel_syntax;"
	#define INTEL_NOPREFIX ".intel_syntax;"
	#define ATT_PREFIX ".att_syntax;"
	#define ATT_NOPREFIX ".att_syntax;"
#elif defined(__GNUC__)
	#define NEW_LINE
	#define INTEL_PREFIX ".intel_syntax prefix;"
	#define INTEL_NOPREFIX ".intel_syntax noprefix;"
	#define ATT_PREFIX ".att_syntax prefix;"
	#define ATT_NOPREFIX ".att_syntax noprefix;"
#else
	#define NEW_LINE
	#define INTEL_PREFIX
	#define INTEL_NOPREFIX
	#define ATT_PREFIX
	#define ATT_NOPREFIX
#endif

#if defined (_MSC_VER) && !defined (TC_WINDOWS_BOOT) 
#if defined(TC_WINDOWS_DRIVER) || defined (_UEFI)
#if defined(__cplusplus)
extern "C" {
#endif
#if defined(_M_X64) || defined (_M_IX86) || defined (_M_IX86_FP)
extern unsigned __int64 __rdtsc();
#endif
#if defined(__cplusplus)
}
#endif
#else
#include <intrin.h>
#if defined(_M_X64) || defined (_M_IX86) || defined (_M_IX86_FP)
#pragma intrinsic(__rdtsc)
#endif
#endif
#endif

#ifdef CRYPTOPP_GENERATE_X64_MASM

#define CRYPTOPP_X86_ASM_AVAILABLE
#define CRYPTOPP_BOOL_X64 1
#define CRYPTOPP_BOOL_SSE2_ASM_AVAILABLE 1

#else

#if CRYPTOPP_BOOL_SSE2_INTRINSICS_AVAILABLE
#if defined(TC_WINDOWS_DRIVER) || defined (_UEFI)
#if defined(__cplusplus)
extern "C" {
#endif
typedef union __declspec(intrin_type) CRYPTOPP_ALIGN_DATA(8) __m64
{
    unsigned __int64    m64_u64;
    float               m64_f32[2];
    __int8              m64_i8[8];
    __int16             m64_i16[4];
    __int32             m64_i32[2];    
    __int64             m64_i64;
    unsigned __int8     m64_u8[8];
    unsigned __int16    m64_u16[4];
    unsigned __int32    m64_u32[2];
} __m64;

typedef union __declspec(intrin_type) CRYPTOPP_ALIGN_DATA(16) __m128 {
     float               m128_f32[4];
     unsigned __int64    m128_u64[2];
     __int8              m128_i8[16];
     __int16             m128_i16[8];
     __int32             m128_i32[4];
     __int64             m128_i64[2];
     unsigned __int8     m128_u8[16];
     unsigned __int16    m128_u16[8];
     unsigned __int32    m128_u32[4];
 } __m128;
 
typedef union __declspec(intrin_type) CRYPTOPP_ALIGN_DATA(16) __m128i {
    __int8              m128i_i8[16];
    __int16             m128i_i16[8];
    __int32             m128i_i32[4];    
    __int64             m128i_i64[2];
    unsigned __int8     m128i_u8[16];
    unsigned __int16    m128i_u16[8];
    unsigned __int32    m128i_u32[4];
    unsigned __int64    m128i_u64[2];
} __m128i;

typedef struct __declspec(intrin_type) CRYPTOPP_ALIGN_DATA(16) __m128d {
    double              m128d_f64[2];
} __m128d;

#define _MM_SHUFFLE2(x,y) (((x)<<1) | (y))

extern void  _m_empty(void);
extern int _mm_extract_epi16(__m128i _A, int _Imm);
extern __m128i _mm_load_si128(__m128i const*_P);
extern __m128i _mm_xor_si128(__m128i _A, __m128i _B);
extern __m128i _mm_cvtsi64_si128(__int64);
extern __m128i _mm_unpacklo_epi64(__m128i _A, __m128i _B);
extern void _mm_store_si128(__m128i *_P, __m128i _B);
extern __m64 _m_pxor(__m64 _MM1, __m64 _MM2);
extern __m128i _mm_set_epi64(__m64 _Q1, __m64 _Q0);
extern __m128i _mm_set1_epi64(__m64 q);
extern __m128i _mm_setr_epi32(int _I0, int _I1, int _I2, int _I3);
extern __m128i _mm_loadu_si128(__m128i const*_P);
extern __m128i _mm_set_epi8(char b15, char b14, char b13, char b12, char b11, char b10, char b9, char b8, char b7, char b6, char b5, char b4, char b3, char b2, char b1, char b0);
extern __m128i _mm_set_epi32(int _I3, int _I2, int _I1, int _I0);
extern __m128i _mm_set1_epi32(int _I);
extern void _mm_storeu_si128(__m128i *_P, __m128i _B);
extern __m128i _mm_or_si128(__m128i _A, __m128i _B);
extern __m128i _mm_slli_epi32(__m128i _A, int _Count);
extern __m128i _mm_srli_epi32(__m128i _A, int _Count);
extern __m128i _mm_add_epi32(__m128i _A, __m128i _B);
extern __m128i _mm_sub_epi32(__m128i _A, __m128i _B);
extern __m128i _mm_add_epi64 (__m128i a, __m128i b);
extern __m128i _mm_or_si128(__m128i _A, __m128i _B);
extern __m128i _mm_and_si128(__m128i _A, __m128i _B);
extern __m128i _mm_andnot_si128(__m128i _A, __m128i _B);
extern __m128i _mm_shufflehi_epi16(__m128i _A, int _Imm);
extern __m128i _mm_shufflelo_epi16(__m128i _A, int _Imm);
extern __m128i _mm_unpacklo_epi32(__m128i _A, __m128i _B);
extern __m128i _mm_unpackhi_epi32(__m128i _A, __m128i _B);
extern __m128i _mm_unpackhi_epi64(__m128i _A, __m128i _B);
extern __m128i _mm_srli_epi16(__m128i _A, int _Count);
extern __m128i _mm_slli_epi16(__m128i _A, int _Count);
extern __m128i _mm_shuffle_epi32 (__m128i a, int imm8);
extern __m128i _mm_set_epi64x (__int64 e1, __int64 e0);
extern __m128i _mm_set1_epi64x (__int64 a);
extern __m128i _mm_castps_si128(__m128);
extern __m128  _mm_castsi128_ps(__m128i);
extern __m128 _mm_shuffle_ps(__m128 _A, __m128 _B, unsigned int _Imm8);
extern __m128i _mm_srli_si128(__m128i _A, int _Imm);
extern __m128i _mm_slli_si128(__m128i _A, int _Imm);
#define _mm_xor_si64      _m_pxor
#define _mm_empty         _m_empty
#define _MM_SHUFFLE(fp3,fp2,fp1,fp0) (((fp3) << 6) | ((fp2) << 4) | \
                                     ((fp1) << 2) | ((fp0)))
#if defined(__cplusplus)
}
#endif
#else
#include <mmintrin.h>
#include <emmintrin.h>
#endif
#endif

#if CRYPTOPP_BOOL_SSSE3_INTRINSICS_AVAILABLE || defined(__INTEL_COMPILER)
#if defined(TC_WINDOWS_DRIVER) || defined (_UEFI)
#if defined(__cplusplus)
extern "C" {
#endif
extern __m128i _mm_shuffle_epi8 (__m128i a, __m128i b);
extern __m128i _mm_alignr_epi8 (__m128i a, __m128i b, int n);
#if defined(__cplusplus)
}
#endif
#else
#include <tmmintrin.h>
#endif
#endif

#if CRYPTOPP_BOOL_SSE41_INTRINSICS_AVAILABLE || defined(__INTEL_COMPILER)
#if defined(TC_WINDOWS_DRIVER) || defined (_UEFI)
#if defined(__cplusplus)
extern "C" {
#endif
extern int   _mm_extract_epi32(__m128i src, const int ndx);
extern __m128i _mm_insert_epi32(__m128i dst, int s, const int ndx);
extern __m128i _mm_blend_epi16 (__m128i v1, __m128i v2, const int mask);
#if defined(_M_X64)
extern __m128i _mm_insert_epi64(__m128i dst, __int64 s, const int ndx);
#endif
#if defined(__cplusplus)
}
#endif
#else
#include <smmintrin.h>
#endif
#endif

#if (defined(__AES__) && defined(__PCLMUL__)) || defined(__INTEL_COMPILER) || CRYPTOPP_BOOL_AESNI_INTRINSICS_AVAILABLE
#if defined(TC_WINDOWS_DRIVER) || defined (_UEFI)
#if defined(__cplusplus)
extern "C" {
#endif
extern __m128i _mm_clmulepi64_si128(__m128i v1, __m128i v2, 
					    const int imm8);
extern __m128i _mm_aeskeygenassist_si128(__m128i ckey, const int rcon);
extern __m128i _mm_aesimc_si128(__m128i v);
extern __m128i _mm_aesenc_si128(__m128i v, __m128i rkey);
extern __m128i _mm_aesenclast_si128(__m128i v, __m128i rkey);
extern __m128i _mm_aesdec_si128(__m128i v, __m128i rkey);
extern __m128i _mm_aesdeclast_si128(__m128i v, __m128i rkey);
#if defined(__cplusplus)
}
#endif
#else
#include <wmmintrin.h>
#endif
#endif

#if CRYPTOPP_SHANI_AVAILABLE
#if defined(TC_WINDOWS_DRIVER) || defined (_UEFI)
#if defined(__cplusplus)
extern "C" {
#endif
extern __m128i __cdecl _mm_sha256msg1_epu32(__m128i, __m128i);
extern __m128i __cdecl _mm_sha256msg2_epu32(__m128i, __m128i);
extern __m128i __cdecl _mm_sha256rnds2_epu32(__m128i, __m128i, __m128i);
#if defined(__cplusplus)
}
#endif
#else
#include <immintrin.h>
#endif
#endif

#if CRYPTOPP_BOOL_X86 || CRYPTOPP_BOOL_X32 || CRYPTOPP_BOOL_X64

#if defined(__cplusplus)
extern "C" {
#endif

#define CRYPTOPP_CPUID_AVAILABLE
#if !defined(CRYPTOPP_DISABLE_AESNI) && !defined(WOLFCRYPT_BACKEND)
#define TC_AES_HW_CPU
#endif

// these should not be used directly
extern volatile int g_x86DetectionDone;
extern volatile int g_hasSSE2;
extern volatile int g_hasISSE;
extern volatile int g_hasMMX;
extern volatile int g_hasAVX;
extern volatile int g_hasAVX2;
extern volatile int g_hasBMI2;
extern volatile int g_hasSSE42;
extern volatile int g_hasSSE41;
extern volatile int g_hasSSSE3;
extern volatile int g_hasAESNI;
extern volatile int g_hasCLMUL;
extern volatile int g_isP4;
extern volatile int g_hasRDRAND;
extern volatile int g_hasRDSEED;
extern volatile int g_hasSHA256;
extern volatile int g_isIntel;
extern volatile int g_isAMD;
extern volatile uint32 g_cacheLineSize;
void DetectX86Features(); // must be called at the start of the program/driver
int CpuId(uint32 input, uint32 output[4]);
// disable all CPU extended features (e.g. SSE, AVX, AES) that may have
// been enabled by DetectX86Features.
void DisableCPUExtendedFeatures (); 

#ifdef CRYPTOPP_BOOL_X64
#define HasSSE2()	1
#define HasISSE()	1
#else
#define HasSSE2()	g_hasSSE2
#define HasISSE()	g_hasISSE
#endif
#define HasMMX()	g_hasMMX
#define HasSSE42() g_hasSSE42
#define HasSSE41() g_hasSSE41
#define HasSAVX() g_hasAVX
#define HasSAVX2() g_hasAVX2
#define HasSBMI2() g_hasBMI2
#define HasSSSE3() g_hasSSSE3
#define HasAESNI() g_hasAESNI
#define HasCLMUL() g_hasCLMUL
#define IsP4() g_isP4
#define HasRDRAND() g_hasRDRAND
#define HasRDSEED() g_hasRDSEED
#define HasSHA256() g_hasSHA256
#define IsCpuIntel() g_isIntel
#define IsCpuAMD() g_isAMD
#define GetCacheLineSize() g_cacheLineSize

#if defined(__cplusplus)
}
#endif

#elif CRYPTOPP_BOOL_ARMV8
#if defined(__cplusplus)
extern "C" {
#endif

#if !defined(CRYPTOPP_DISABLE_AESNI) && !defined(WOLFCRYPT_BACKEND)
#define TC_AES_HW_CPU
#endif

extern volatile int g_hasAESARM;
void DetectArmFeatures();

#define HasAESNI() g_hasAESARM

#if defined(__cplusplus)
}
#endif

#else

#define HasSSE2()	0
#define HasISSE()	0

#define HasMMX()	0
#define HasSSE42() 0
#define HasSSE41() 0
#define HasSAVX() 0
#define HasSAVX2() 0
#define HasSBMI2() 0
#define HasSSSE3() 0
#define HasAESNI() 0
#define HasCLMUL() 0
#define IsP4() 0
#define HasRDRAND() 0
#define HasRDSEED() 0
#define IsCpuIntel() 0
#define IsCpuAMD() 0
#define GetCacheLineSize()	CRYPTOPP_L1_CACHE_LINE_SIZE

#define DetectX86Features()
#define DisableCPUExtendedFeatures()

#endif

#endif

#if CRYPTOPP_BOOL_X86 || CRYPTOPP_BOOL_X32 || CRYPTOPP_BOOL_X64

#ifdef CRYPTOPP_GENERATE_X64_MASM
	#define AS1(x) x*newline*
	#define AS2(x, y) x, y*newline*
	#define AS3(x, y, z) x, y, z*newline*
	#define ASS(x, y, a, b, c, d) x, y, a*64+b*16+c*4+d*newline*
	#define ASL(x) label##x:*newline*
	#define ASJ(x, y, z) x label##y*newline*
	#define ASC(x, y) x label##y*newline*
	#define AS_HEX(y) 0##y##h
#elif defined(_MSC_VER) || defined(__BORLANDC__)
	#define CRYPTOPP_MS_STYLE_INLINE_ASSEMBLY
	#define AS1(x) __asm {x}
	#define AS2(x, y) __asm {x, y}
	#define AS3(x, y, z) __asm {x, y, z}
	#define ASS(x, y, a, b, c, d) __asm {x, y, (a)*64+(b)*16+(c)*4+(d)}
	#define ASL(x) __asm {label##x:}
	#define ASJ(x, y, z) __asm {x label##y}
	#define ASC(x, y) __asm {x label##y}
	#define CRYPTOPP_NAKED __declspec(naked)
	#define AS_HEX(y) 0x##y
#else
	#define CRYPTOPP_GNU_STYLE_INLINE_ASSEMBLY

    // define these in two steps to allow arguments to be expanded
    #define GNU_AS1(x) #x ";" NEW_LINE
    #define GNU_AS2(x, y) #x ", " #y ";" NEW_LINE
    #define GNU_AS3(x, y, z) #x ", " #y ", " #z ";" NEW_LINE
    #define GNU_ASL(x) "\n" #x ":" NEW_LINE
    #define GNU_ASJ(x, y, z) #x " " #y #z ";" NEW_LINE
    #define AS1(x) GNU_AS1(x)
    #define AS2(x, y) GNU_AS2(x, y)
    #define AS3(x, y, z) GNU_AS3(x, y, z)
    #define ASS(x, y, a, b, c, d) #x ", " #y ", " #a "*64+" #b "*16+" #c "*4+" #d ";"
    #define ASL(x) GNU_ASL(x)
    #define ASJ(x, y, z) GNU_ASJ(x, y, z)
    #define ASC(x, y) #x " " #y ";"
    #define CRYPTOPP_NAKED
    #define AS_HEX(y) 0x##y
#endif

#define IF0(y)
#define IF1(y) y

#ifdef CRYPTOPP_GENERATE_X64_MASM
#define ASM_MOD(x, y) ((x) MOD (y))
#define XMMWORD_PTR XMMWORD PTR
#else
// GNU assembler doesn't seem to have mod operator
#define ASM_MOD(x, y) ((x)-((x)/(y))*(y))
// GAS 2.15 doesn't support XMMWORD PTR. it seems necessary only for MASM
#define XMMWORD_PTR
#endif

#if CRYPTOPP_BOOL_X86
	#define AS_REG_1 ecx
	#define AS_REG_2 edx
	#define AS_REG_3 esi
	#define AS_REG_4 edi
	#define AS_REG_5 eax
	#define AS_REG_6 ebx
	#define AS_REG_7 ebp
	#define AS_REG_1d ecx
	#define AS_REG_2d edx
	#define AS_REG_3d esi
	#define AS_REG_4d edi
	#define AS_REG_5d eax
	#define AS_REG_6d ebx
	#define AS_REG_7d ebp
	#define WORD_SZ 4
	#define WORD_REG(x)	e##x
	#define WORD_PTR DWORD PTR
	#define AS_PUSH_IF86(x) AS1(push e##x)
	#define AS_POP_IF86(x) AS1(pop e##x)
	#define AS_JCXZ jecxz
#elif CRYPTOPP_BOOL_X32
    #define AS_REG_1 ecx
    #define AS_REG_2 edx
    #define AS_REG_3 r8d
    #define AS_REG_4 r9d
    #define AS_REG_5 eax
    #define AS_REG_6 r10d
    #define AS_REG_7 r11d
    #define AS_REG_1d ecx
    #define AS_REG_2d edx
    #define AS_REG_3d r8d
    #define AS_REG_4d r9d
    #define AS_REG_5d eax
    #define AS_REG_6d r10d
    #define AS_REG_7d r11d
    #define WORD_SZ 4
    #define WORD_REG(x)	e##x
    #define WORD_PTR DWORD PTR
    #define AS_PUSH_IF86(x) AS1(push r##x)
    #define AS_POP_IF86(x) AS1(pop r##x)
    #define AS_JCXZ jecxz
#elif CRYPTOPP_BOOL_X64
	#ifdef CRYPTOPP_GENERATE_X64_MASM
		#define AS_REG_1 rcx
		#define AS_REG_2 rdx
		#define AS_REG_3 r8
		#define AS_REG_4 r9
		#define AS_REG_5 rax
		#define AS_REG_6 r10
		#define AS_REG_7 r11
		#define AS_REG_1d ecx
		#define AS_REG_2d edx
		#define AS_REG_3d r8d
		#define AS_REG_4d r9d
		#define AS_REG_5d eax
		#define AS_REG_6d r10d
		#define AS_REG_7d r11d
	#else
		#define AS_REG_1 rdi
		#define AS_REG_2 rsi
		#define AS_REG_3 rdx
		#define AS_REG_4 rcx
		#define AS_REG_5 r8
		#define AS_REG_6 r9
		#define AS_REG_7 r10
		#define AS_REG_1d edi
		#define AS_REG_2d esi
		#define AS_REG_3d edx
		#define AS_REG_4d ecx
		#define AS_REG_5d r8d
		#define AS_REG_6d r9d
		#define AS_REG_7d r10d
	#endif
	#define WORD_SZ 8
	#define WORD_REG(x)	r##x
	#define WORD_PTR QWORD PTR
	#define AS_PUSH_IF86(x)
	#define AS_POP_IF86(x)
	#define AS_JCXZ jrcxz
#endif

// helper macro for stream cipher output
#define AS_XMM_OUTPUT4(labelPrefix, inputPtr, outputPtr, x0, x1, x2, x3, t, p0, p1, p2, p3, increment)\
	AS2(	test	inputPtr, inputPtr)\
	ASC(	jz,		labelPrefix##3)\
	AS2(	test	inputPtr, 15)\
	ASC(	jnz,	labelPrefix##7)\
	AS2(	pxor	xmm##x0, [inputPtr+p0*16])\
	AS2(	pxor	xmm##x1, [inputPtr+p1*16])\
	AS2(	pxor	xmm##x2, [inputPtr+p2*16])\
	AS2(	pxor	xmm##x3, [inputPtr+p3*16])\
	AS2(	add		inputPtr, increment*16)\
	ASC(	jmp,	labelPrefix##3)\
	ASL(labelPrefix##7)\
	AS2(	movdqu	xmm##t, [inputPtr+p0*16])\
	AS2(	pxor	xmm##x0, xmm##t)\
	AS2(	movdqu	xmm##t, [inputPtr+p1*16])\
	AS2(	pxor	xmm##x1, xmm##t)\
	AS2(	movdqu	xmm##t, [inputPtr+p2*16])\
	AS2(	pxor	xmm##x2, xmm##t)\
	AS2(	movdqu	xmm##t, [inputPtr+p3*16])\
	AS2(	pxor	xmm##x3, xmm##t)\
	AS2(	add		inputPtr, increment*16)\
	ASL(labelPrefix##3)\
	AS2(	test	outputPtr, 15)\
	ASC(	jnz,	labelPrefix##8)\
	AS2(	movdqa	[outputPtr+p0*16], xmm##x0)\
	AS2(	movdqa	[outputPtr+p1*16], xmm##x1)\
	AS2(	movdqa	[outputPtr+p2*16], xmm##x2)\
	AS2(	movdqa	[outputPtr+p3*16], xmm##x3)\
	ASC(	jmp,	labelPrefix##9)\
	ASL(labelPrefix##8)\
	AS2(	movdqu	[outputPtr+p0*16], xmm##x0)\
	AS2(	movdqu	[outputPtr+p1*16], xmm##x1)\
	AS2(	movdqu	[outputPtr+p2*16], xmm##x2)\
	AS2(	movdqu	[outputPtr+p3*16], xmm##x3)\
	ASL(labelPrefix##9)\
	AS2(	add		outputPtr, increment*16)

#endif  //  X86/X32/X64

#if defined(TC_WINDOWS_DRIVER) || defined (_UEFI)
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
#endif

#endif
