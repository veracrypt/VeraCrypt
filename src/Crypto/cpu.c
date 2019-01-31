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

#if !defined (_UEFI) && ((defined(__AES__) && defined(__PCLMUL__)) || defined(__INTEL_COMPILER) || CRYPTOPP_BOOL_AESNI_INTRINSICS_AVAILABLE)

static jmp_buf s_jmpNoAESNI;
static void SigIllHandlerAESNI(int p)
{
	longjmp(s_jmpNoAESNI, 1);
}

#endif

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
#ifndef _UEFI
    __try
	{
#endif
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
#ifndef _UEFI
	 }
	 __except (EXCEPTION_EXECUTE_HANDLER)
	{
		return 0;
    }
#endif

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
#elif defined(CRYPTOPP_MS_STYLE_INLINE_ASSEMBLY) && !defined(_UEFI)
	volatile int result = 1;
#if defined (TC_WINDOWS_DRIVER) && !defined (_WIN64)
	KFLOATING_SAVE floatingPointState;
	if (NT_SUCCESS (KeSaveFloatingPointState (&floatingPointState)))
	{
#endif
    __try
	{
#if CRYPTOPP_BOOL_SSE2_ASM_AVAILABLE
        AS2(por xmm0, xmm0)        // executing SSE2 instruction
#elif CRYPTOPP_BOOL_SSE2_INTRINSICS_AVAILABLE
		__m128i x = _mm_setzero_si128();
		result = _mm_cvtsi128_si32(x) == 0 ? 1 : 0;
#endif
	}
    __except (EXCEPTION_EXECUTE_HANDLER)
	{
		result = 0;
	}
#if defined (TC_WINDOWS_DRIVER) && !defined (_WIN64)
	KeRestoreFloatingPointState (&floatingPointState);
	}
	else
		return 0;
#endif
	return result;
#elif !defined(_UEFI)
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
#else
	return 1;
#endif
}

static uint64 xgetbv()
{
#if defined(_MSC_VER) && defined(_XCR_XFEATURE_ENABLED_MASK) && !defined(_UEFI)
	 return _xgetbv(_XCR_XFEATURE_ENABLED_MASK);
#elif defined(__GNUC__) || defined(__clang__)
    uint32 eax, edx;
    __asm__ __volatile__(".byte 0x0F, 0x01, 0xd0" : "=a"(eax), "=d"(edx) : "c"(0));
    return ((uint64_t)edx << 32) | eax;
#else
	return 0;
#endif
}

volatile int g_x86DetectionDone = 0;
volatile int g_hasISSE = 0, g_hasSSE2 = 0, g_hasSSSE3 = 0, g_hasMMX = 0, g_hasAESNI = 0, g_hasCLMUL = 0, g_isP4 = 0;
volatile int g_hasAVX = 0, g_hasAVX2 = 0, g_hasBMI2 = 0, g_hasSSE42 = 0, g_hasSSE41 = 0, g_isIntel = 0, g_isAMD = 0;
volatile int g_hasRDRAND = 0, g_hasRDSEED = 0;
volatile uint32 g_cacheLineSize = CRYPTOPP_L1_CACHE_LINE_SIZE;

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

VC_INLINE int IsHygon(const uint32 output[4])
{
	// This is the "HygonGenuine" string.
	return (output[1] /*EBX*/ == 0x6f677948) &&
		(output[2] /*ECX*/ == 0x656e6975) &&
		(output[3] /*EDX*/ == 0x6e65476e);
}

#if !defined (_UEFI) && ((defined(__AES__) && defined(__PCLMUL__)) || defined(__INTEL_COMPILER) || CRYPTOPP_BOOL_AESNI_INTRINSICS_AVAILABLE)

static int TryAESNI ()
{
	volatile int result = 0;
#ifdef _MSC_VER
	__try
#else
	SigHandler oldHandler = signal(SIGILL, SigIllHandlerAESNI);
	if (oldHandler == SIG_ERR)
		return 0;

	if (setjmp(s_jmpNoAESNI))
		result = 0;
	else
#endif
	{
		__m128i block, subkey, ciphered;
		// perform AES round.
		block = _mm_setr_epi32(0x11223344,0x55667788,0x99AABBCC,0xDDEEFF00);
		subkey = _mm_setr_epi32(0xA5A5A5A5,0xA5A5A5A5,0x5A5A5A5A,0x5A5A5A5A);
		ciphered = _mm_aesenc_si128(block, subkey);
#ifdef _MSC_VER
		if (ciphered.m128i_u64[0] == LL(0x2f4654b9485061fa) && ciphered.m128i_u64[1] == LL(0xc8b51f1fe1256f99))
#else
		if (((uint64_t*)(&ciphered))[0] == LL(0x2f4654b9485061fa) && ((uint64_t*)(&ciphered))[1] == LL(0xc8b51f1fe1256f99))
#endif
			result = 1;
	}
#ifdef _MSC_VER
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		// ignore error if AES-NI not supported
	}
#else
	signal(SIGILL, oldHandler);
#endif
	
	return result;
}

static int Detect_MS_HyperV_AES ()
{
	int hasAesNI = 0;
	// when Hyper-V is enabled on older versions of Windows Server (i.e. 2008 R2), the AES-NI capability 
	// gets masked out for all applications, even running on the host.
	// We try to detect Hyper-V virtual CPU and perform a dummy AES-NI operation to check its real presence
	uint32 cpuid[4];
	char HvProductName[13];

	CpuId(0x40000000, cpuid);
	memcpy (HvProductName, &cpuid[1], 12);
	HvProductName[12] = 0;
	if (_stricmp(HvProductName, "Microsoft Hv") == 0)
	{
#if defined (TC_WINDOWS_DRIVER) && !defined (_WIN64)
		KFLOATING_SAVE floatingPointState;
		if (NT_SUCCESS (KeSaveFloatingPointState (&floatingPointState)))
		{
#endif
		hasAesNI = TryAESNI ();

#if defined (TC_WINDOWS_DRIVER) && !defined (_WIN64)
		KeRestoreFloatingPointState (&floatingPointState);
		}
#endif
	}

	return hasAesNI;
}

#endif

void DetectX86Features()
{
	uint32 cpuid[4] = {0}, cpuid1[4] = {0}, cpuid2[4] = {0};
	if (!CpuId(0, cpuid))
		return;
	if (!CpuId(1, cpuid1))
		return;

	g_hasMMX = (cpuid1[3] & (1 << 23)) != 0;

	// cpuid1[2] & (1 << 27) is XSAVE/XRESTORE and signals OS support for SSE; use it to avoid probes.
	// See http://github.com/weidai11/cryptopp/issues/511 and http://stackoverflow.com/a/22521619/608639
	if ((cpuid1[3] & (1 << 26)) != 0)
		g_hasSSE2 = (cpuid1[2] & (1 << 27)) || TrySSE2();
	if (g_hasSSE2 && (cpuid1[2] & (1 << 28)) && (cpuid1[2] & (1 << 27)) && (cpuid1[2] & (1 << 26))) /* CPU has AVX and OS supports XSAVE/XRSTORE */
	{
      uint64 xcrFeatureMask = xgetbv();
      g_hasAVX = (xcrFeatureMask & 0x6) == 0x6;
	}
	g_hasAVX2 = g_hasAVX && (cpuid1[1] & (1 << 5));
	g_hasBMI2 = g_hasSSE2 && (cpuid1[1] & (1 << 8));
	g_hasSSE42 = g_hasSSE2 && (cpuid1[2] & (1 << 20));
	g_hasSSE41 = g_hasSSE2 && (cpuid1[2] & (1 << 19));
	g_hasSSSE3 = g_hasSSE2 && (cpuid1[2] & (1<<9));
	g_hasAESNI = g_hasSSE2 && (cpuid1[2] & (1<<25));
	g_hasCLMUL = g_hasSSE2 && (cpuid1[2] & (1<<1));

#if !defined (_UEFI) && ((defined(__AES__) && defined(__PCLMUL__)) || defined(__INTEL_COMPILER) || CRYPTOPP_BOOL_AESNI_INTRINSICS_AVAILABLE)
	// Hypervisor = bit 31 of ECX of CPUID leaf 0x1
	// reference: http://artemonsecurity.com/vmde.pdf
	if (!g_hasAESNI && (cpuid1[2] & (1<<31)))
	{
		g_hasAESNI = Detect_MS_HyperV_AES ();
	}
#endif

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
		g_isIntel = 1;
		g_isP4 = ((cpuid1[0] >> 8) & 0xf) == 0xf;
		g_cacheLineSize = 8 * GETBYTE(cpuid1[1], 1);
		g_hasRDRAND = (cpuid1[2] & (1 << 30)) != 0;

		if (cpuid[0] >= 7)
		{
			if (CpuId(7, cpuid2))
			{
				g_hasRDSEED = (cpuid2[1] & (1 << 18)) != 0;
				g_hasAVX2 = (cpuid2[1] & (1 <<  5)) != 0;
				g_hasBMI2 = (cpuid2[1] & (1 <<  8)) != 0;
			}
		}
	}
	else if (IsAMD(cpuid) || IsHygon(cpuid))
	{
		g_isAMD = 1;
		CpuId(0x80000005, cpuid);
		g_cacheLineSize = GETBYTE(cpuid[2], 0);
		g_hasRDRAND = (cpuid1[2] & (1 << 30)) != 0;

		if (cpuid[0]  >= 7)
		{
			if (CpuId(7, cpuid2))
			{
				g_hasRDSEED = (cpuid2[1] & (1 << 18)) != 0;
				g_hasAVX2 = (cpuid2[1] & (1 <<  5)) != 0;
				g_hasBMI2 = (cpuid2[1] & (1 <<  8)) != 0;
			}
		}
	}

	if (!g_cacheLineSize)
		g_cacheLineSize = CRYPTOPP_L1_CACHE_LINE_SIZE;

	*((volatile int*)&g_x86DetectionDone) = 1;
}

int is_aes_hw_cpu_supported ()
{
	int bHasAESNI = 0;
	uint32 cpuid[4];

	if (CpuId(1, cpuid))
	{
		if (cpuid[2] & (1<<25))
			bHasAESNI = 1;
#if !defined (_UEFI) && ((defined(__AES__) && defined(__PCLMUL__)) || defined(__INTEL_COMPILER) || CRYPTOPP_BOOL_AESNI_INTRINSICS_AVAILABLE)
		// Hypervisor = bit 31 of ECX of CPUID leaf 0x1
		// reference: http://artemonsecurity.com/vmde.pdf
		if (!bHasAESNI && (cpuid[2] & (1<<31)))
		{
			bHasAESNI = Detect_MS_HyperV_AES ();
		}
#endif
	}

	return bHasAESNI;
}

void DisableCPUExtendedFeatures ()
{
	g_hasSSE2 = 0;
	g_hasISSE = 0;
	g_hasMMX = 0;
	g_hasSSE2 = 0;
	g_hasISSE = 0;
	g_hasMMX = 0;
	g_hasAVX = 0;
	g_hasAVX2 = 0;
	g_hasBMI2 = 0;
	g_hasSSE42 = 0;
	g_hasSSE41 = 0;
	g_hasSSSE3 = 0;
	g_hasAESNI = 0;
	g_hasCLMUL = 0;
}

#endif

