/*
 Copyright (c) 2008 TrueCrypt Developers Association. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
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
