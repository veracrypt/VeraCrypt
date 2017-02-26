/*
 Derived from source code of TrueCrypt 7.1a, which is
 Copyright (c) 2008-2012 TrueCrypt Developers Association and which is governed
 by the TrueCrypt License 3.0.

 Modifications and additions to the original source code (contained in this file)
 and all other portions of this file are Copyright (c) 2013-2016 IDRIX
 and are governed by the Apache License 2.0 the full text of which is
 contained in the file License.txt included in VeraCrypt binary and source
 code distribution packages.
*/

#ifndef TC_HEADER_Platform_Mutex
#define TC_HEADER_Platform_Mutex

#ifdef TC_WINDOWS
#	include "System.h"
#else
#	include <pthread.h>
#endif
#include "PlatformBase.h"

namespace VeraCrypt
{
	class Mutex
	{
#ifdef TC_WINDOWS
		typedef CRITICAL_SECTION SystemMutex_t;
#else
		typedef pthread_mutex_t SystemMutex_t;
#endif

	public:
		Mutex ();
		~Mutex ();

		SystemMutex_t *GetSystemHandle () { return &SystemMutex; }
		void Lock ();
		void Unlock ();

	protected:
		bool Initialized;
		SystemMutex_t SystemMutex;

	private:
		Mutex (const Mutex &);
		Mutex &operator= (const Mutex &);
	};

	class ScopeLock
	{
	public:
		ScopeLock (Mutex &mutex) : ScopeMutex (mutex) { mutex.Lock(); }
		~ScopeLock () { ScopeMutex.Unlock(); }

	protected:
		Mutex &ScopeMutex;

	private:
		ScopeLock (const ScopeLock &);
		ScopeLock &operator= (const ScopeLock &);
	};
}

#endif // TC_HEADER_Platform_Mutex
