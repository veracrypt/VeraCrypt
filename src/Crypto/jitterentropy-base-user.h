/*
 * Non-physical true random number generator based on timing jitter.
 *
 * Copyright Stephan Mueller <smueller@chronox.de>, 2013 - 2019
 *
 * License
 * =======
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, and the entire permission notice in its entirety,
 *    including the disclaimer of warranties.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote
 *    products derived from this software without specific prior
 *    written permission.
 *
 * ALTERNATIVELY, this product may be distributed under the terms of
 * the GNU General Public License, in which case the provisions of the GPL are
 * required INSTEAD OF the above restrictions.  (This clause is
 * necessary due to a potential bad interaction between the GPL and
 * the restrictions contained in a BSD-style copyright.)
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, ALL OF
 * WHICH ARE HEREBY DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
 * USE OF THIS SOFTWARE, EVEN IF NOT ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 */

/* Adapted for VeraCrypt */

#pragma once

#include "Common/Tcdefs.h"
#include "misc.h"
#include "cpu.h"
#include <stdlib.h>
#include <string.h>

#ifdef _MSC_VER

typedef uint64 uint64_t;
typedef int64 int64_t;

#ifndef _UEFI
#define CONFIG_CRYPTO_CPU_JITTERENTROPY_SECURE_MEMORY
#endif

#ifndef _UEFI
typedef SSIZE_T ssize_t;
#else
#if CRYPTOPP_BOOL_X64
typedef int64 ssize_t;
#else
typedef int32 ssize_t;
#endif
#endif

static VC_INLINE void jent_get_nstime(uint64 *out)
{
#ifdef _M_ARM64
	LARGE_INTEGER v = { 0 };
#ifdef TC_WINDOWS_DRIVER
		v = KeQueryPerformanceCounter(NULL);
#else
		QueryPerformanceCounter(&v);
#endif
		* out = v.QuadPart;
#else
	*out = __rdtsc();;
#endif
}

#else

#if CRYPTOPP_BOOL_X86 || CRYPTOPP_BOOL_X32 || CRYPTOPP_BOOL_X64

/* taken from Linux kernel */
#if CRYPTOPP_BOOL_X64
#define DECLARE_ARGS(val, low, high)    unsigned low, high
#define EAX_EDX_VAL(val, low, high)     ((low) | ((uint64)(high) << 32))
#define EAX_EDX_RET(val, low, high)     "=a" (low), "=d" (high)
#else   
#define DECLARE_ARGS(val, low, high)    unsigned long long val
#define EAX_EDX_VAL(val, low, high)     (val)
#define EAX_EDX_RET(val, low, high)     "=A" (val)
#endif

VC_INLINE void jent_get_nstime(uint64 *out)
{
	DECLARE_ARGS(val, low, high);
	asm volatile("rdtsc" : EAX_EDX_RET(val, low, high));
	*out = EAX_EDX_VAL(val, low, high);
}

#else

#include <time.h>

VC_INLINE void jent_get_nstime(uint64 *out)
{
	/* we could use CLOCK_MONOTONIC(_RAW), but with CLOCK_REALTIME
	 * we get some nice extra entropy once in a while from the NTP actions
	 * that we want to use as well... though, we do not rely on that
	 * extra little entropy */
	uint64_t tmp = 0;
	struct timespec time;
	if (clock_gettime(CLOCK_REALTIME, &time) == 0)
	{
		tmp = time.tv_sec;
		tmp = tmp << 32;
		tmp = tmp | time.tv_nsec;
	}
	*out = tmp;
}

#endif

#endif

#ifdef _MSC_VER
static
#endif
VC_INLINE void *jent_zalloc(size_t len)
{
	void *tmp = NULL;
	tmp = TCalloc(len);
	if(NULL != tmp)
	{
		memset(tmp, 0, len);
#if defined(_WIN32) && !defined(TC_WINDOWS_DRIVER) && !defined(_UEFI)
		VirtualLock (tmp, len);
#endif
	}
	return tmp;
}

#ifdef _MSC_VER
static
#endif
VC_INLINE void jent_zfree(void *ptr, unsigned int len)
{
	if (len % 8)
		burn(ptr, len);
	else
		FAST_ERASE64(ptr, len);
#if defined(_WIN32) && !defined(TC_WINDOWS_DRIVER) && !defined(_UEFI)
	VirtualUnlock (ptr, len);
#endif
	TCfree(ptr);
}

#ifdef _MSC_VER
static
#endif
VC_INLINE int jent_fips_enabled(void)
{
        return 1;
}

/* --- helpers needed in user space -- */

#define rol64(x,n)	rotl64(x,n)



