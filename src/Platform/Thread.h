/*
 Derived from source code of TrueCrypt 7.1a, which is
 Copyright (c) 2008-2012 TrueCrypt Developers Association and which is governed
 by the TrueCrypt License 3.0.

 Modifications and additions to the original source code (contained in this file)
 and all other portions of this file are Copyright (c) 2013-2025 AM Crypto
 and are governed by the Apache License 2.0 the full text of which is
 contained in the file License.txt included in VeraCrypt binary and source
 code distribution packages.
*/

#ifndef TC_HEADER_Platform_Thread
#define TC_HEADER_Platform_Thread

#ifdef TC_WINDOWS
#	include "System.h"
#	define TC_THREAD_PROC DWORD WINAPI
#else
#	include <pthread.h>
#	define TC_THREAD_PROC void*
#endif
#include "PlatformBase.h"
#include "Functor.h"
#include "SharedPtr.h"
#include "SyncEvent.h"

namespace VeraCrypt
{
	class Thread
	{
	public:
#ifdef TC_WINDOWS
		typedef HANDLE ThreadSystemHandle;
		typedef LPTHREAD_START_ROUTINE ThreadProcPtr;
#else
		typedef pthread_t ThreadSystemHandle;
		typedef void* (*ThreadProcPtr) (void *);
#endif
		Thread () { };
		virtual ~Thread () { };

		void Join () const;
		void Start (ThreadProcPtr threadProc, void *parameter = nullptr);

		void Start (Functor *functor)
		{
			Start (Thread::FunctorEntry, (void *)functor);
		}

		static void Sleep (uint32 milliSeconds);

	protected:
		static TC_THREAD_PROC FunctorEntry (void *functorArg)
		{
			Functor *functor = (Functor *) functorArg;
			try
			{
				(*functor) ();
			}
			catch (...) { }

			delete functor;
			return 0;
		}

		static const size_t MinThreadStackSize = 1024 * 1024;

		ThreadSystemHandle SystemHandle;

	private:
		Thread (const Thread &);
		Thread &operator= (const Thread &);
	};

}

#endif // TC_HEADER_Platform_Thread
