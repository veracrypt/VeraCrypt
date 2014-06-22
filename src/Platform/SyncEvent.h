/*
 Copyright (c) 2008 TrueCrypt Developers Association. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

#ifndef TC_HEADER_Platform_SyncEvent
#define TC_HEADER_Platform_SyncEvent

#ifdef TC_WINDOWS
#	include "System.h"
#else
#	include <pthread.h>
#endif
#include "PlatformBase.h"
#include "Mutex.h"

namespace VeraCrypt
{
	class SyncEvent
	{
	public:
		SyncEvent ();
		~SyncEvent ();

		void Signal ();
		void Wait ();

	protected:
		bool Initialized;
#ifdef TC_WINDOWS
		HANDLE SystemSyncEvent;
#else
		volatile bool Signaled;
		pthread_cond_t SystemSyncEvent;
		Mutex EventMutex;
#endif

	private:
		SyncEvent (const SyncEvent &);
		SyncEvent &operator= (const SyncEvent &);
	};
}

#endif // TC_HEADER_Platform_SyncEvent
