/* cpu.c - written and placed in the public domain by Wei Dai */

#include "cpu.h"
#include "misc.h"

#ifndef EXCEPTION_EXECUTE_HANDLER
#define EXCEPTION_EXECUTE_HANDLER 1
#endif

#ifndef CRYPTOPP_MS_STYLE_INLINE_ASSEMBLY
#include <signal.h>
#include <setjmp.h>
#endif

#ifdef CRYPTOPP_CPUID_AVAILABLE

#if _MSC_VER >= 1400 && CRYPTOPP_BOOL_X64

int CpuId(uint32 input, uint32 output[4])
{
	__cpuid((int *)output, input);
	return 1;
}

#else

#ifndef CRYPTOPP_MS_STYLE_INLINE_ASSEMBLY

#if defined(__cplusplus)
extern "C" {
#endif

typedef void (*SigHandler)(int);

static jmp_buf s_jmpNoCPUID;
static void SigIllHandlerCPUID(int p)
{
	longjmp(s_jmpNoCPUID, 1);
}

#if CRYPTOPP_BOOL_X64 == 0
static jmp_buf s_jmpNoSSE2;
static void SigIllHandlerSSE2(int p)
{
	longjmp(s_jmpNoSSE2, 1);
}
#endif

#if defined(__cplusplus)
}
#endif
#endif

int CpuId(uint32 input, uint32 output[4])
{
#ifdef CRYPTOPP_MS_STYLE_INLINE_ASSEMBLY
    __try
	{
		__asm
		{
			mov eax, input
            mov ecx, 0
			cpuid
			mov edi, output
			mov [edi], eax
			mov [edi+4], ebx
			mov [edi+8], ecx
			mov [edi+12], edx
		}
	}
    __except (EXCEPTION_EXECUTE_HANDLER)
	{
		return 0;
    }

	// function 0 returns the highest basic function understood in EAX
	if(input == 0)
        return !!output[0]? 1 : 0;

	return 1;
#else
	// longjmp and clobber warnings. Volatile is required.
	// http://github.com/weidai11/cryptopp/issues/24
	// http://stackoverflow.com/q/7721854
	volatile int result = 1;

	SigHandler oldHandler = signal(SIGILL, SigIllHandlerCPUID);
	if (oldHandler == SIG_ERR)
		result = 0;

	if (setjmp(s_jmpNoCPUID))
		result = 0;
	else
	{
		asm volatile
		(
            // save ebx in case -fPIC is being used
            // TODO: this might need an early clobber on EDI.
#if CRYPTOPP_BOOL_X32 || CRYPTOPP_BOOL_X64
            "pushq %%rbx; cpuid; mov %%ebx, %%edi; popq %%rbx"
#else
            "push %%ebx; cpuid; mov %%ebx, %%edi; pop %%ebx"
#endif
            : "=a" (output[0]), "=D" (output[1]), "=c" (output[2]), "=d" (output[3])
            : "a" (input), "c" (0)
         );
	}

	signal(SIGILL, oldHandler);
	return result;
#endif
}

#endif

static int TrySSE2()
{
#if CRYPTOPP_BOOL_X64
	return 1;
#elif defined(CRYPTOPP_MS_STYLE_INLINE_ASSEMBLY)
    __try
	{
#if CRYPTOPP_BOOL_SSE2_ASM_AVAILABLE
        AS2(por xmm0, xmm0)        // executing SSE2 instruction
#elif CRYPTOPP_BOOL_SSE2_INTRINSICS_AVAILABLE
		__m128i x = _mm_setzero_si128();
		return _mm_cvtsi128_si32(x) == 0 ? 1 : 0;
#endif
	}
    __except (EXCEPTION_EXECUTE_HANDLER)
	{
		return 0;
    }
	return 1;
#else
	// longjmp and clobber warnings. Volatile is required.
	// http://github.com/weidai11/cryptopp/issues/24
	// http://stackoverflow.com/q/7721854
	volatile int result = 1;

	SigHandler oldHandler = signal(SIGILL, SigIllHandlerSSE2);
	if (oldHandler == SIG_ERR)
		return 0;

	if (setjmp(s_jmpNoSSE2))
		result = 1;
	else
	{
#if CRYPTOPP_BOOL_SSE2_ASM_AVAILABLE
		__asm __volatile ("por %xmm0, %xmm0");
#elif CRYPTOPP_BOOL_SSE2_INTRINSICS_AVAILABLE
		__m128i x = _mm_setzero_si128();
		result = _mm_cvtsi128_si32(x) == 0? 1 : 0;
#endif
	}

	signal(SIGILL, oldHandler);
	return result;
#endif
}

int g_x86DetectionDone = 0;
int g_hasISSE = 0, g_hasSSE2 = 0, g_hasSSSE3 = 0, g_hasMMX = 0, g_hasAESNI = 0, g_hasCLMUL = 0, g_isP4 = 0;
int g_hasAVX = 0, g_hasSSE42 = 0, g_hasSSE41 = 0;
uint32 g_cacheLineSize = CRYPTOPP_L1_CACHE_LINE_SIZE;

VC_INLINE int IsIntel(const uint32 output[4])
{
	// This is the "GenuineIntel" string
	return (output[1] /*EBX*/ == 0x756e6547) &&
    (output[2] /*ECX*/ == 0x6c65746e) &&
    (output[3] /*EDX*/ == 0x49656e69);
}

VC_INLINE int IsAMD(const uint32 output[4])
{
	// This is the "AuthenticAMD" string
	return (output[1] /*EBX*/ == 0x68747541) &&
    (output[2] /*ECX*/ == 0x69746E65) &&
    (output[3] /*EDX*/ == 0x444D4163);
}

void DetectX86Features()
{
	uint32 cpuid[4], cpuid1[4];
	if (!CpuId(0, cpuid))
		return;
	if (!CpuId(1, cpuid1))
		return;

	g_hasMMX = (cpuid1[3] & (1 << 23)) != 0;
	if ((cpuid1[3] & (1 << 26)) != 0)
		g_hasSSE2 = TrySSE2();
	g_hasAVX = g_hasSSE2 && (cpuid1[2] & (1 << 28));
	g_hasSSE42 = g_hasSSE2 && (cpuid1[2] & (1 << 20));
	g_hasSSE41 = g_hasSSE2 && (cpuid1[2] & (1 << 19));
	g_hasSSSE3 = g_hasSSE2 && (cpuid1[2] & (1<<9));
	g_hasAESNI = g_hasSSE2 && (cpuid1[2] & (1<<25));
	g_hasCLMUL = g_hasSSE2 && (cpuid1[2] & (1<<1));

	if ((cpuid1[3] & (1 << 25)) != 0)
		g_hasISSE = 1;
	else
	{
		uint32 cpuid2[4];
		CpuId(0x080000000, cpuid2);
		if (cpuid2[0] >= 0x080000001)
		{
			CpuId(0x080000001, cpuid2);
			g_hasISSE = (cpuid2[3] & (1 << 22)) != 0;
		}
	}

	if (IsIntel(cpuid))
	{
		g_isP4 = ((cpuid1[0] >> 8) & 0xf) == 0xf;
		g_cacheLineSize = 8 * GETBYTE(cpuid1[1], 1);
	}
	else if (IsAMD(cpuid))
	{
		CpuId(0x80000005, cpuid);
		g_cacheLineSize = GETBYTE(cpuid[2], 0);
	}

	if (!g_cacheLineSize)
		g_cacheLineSize = CRYPTOPP_L1_CACHE_LINE_SIZE;

	*((volatile int*)&g_x86DetectionDone) = 1;
}

#endif
