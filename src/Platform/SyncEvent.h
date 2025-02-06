/*
 Derived from source code of TrueCrypt 7.1a, which is
 Copyright (c) 2008-2012 TrueCrypt Developers Association and which is governed
 by the TrueCrypt License 3.0.

 Modifications and additions to the original source code (contained in this file)
 and all other portions of this file are Copyright (c) 2013-2025 IDRIX
 and are governed by the Apache License 2.0 the full text of which is
 contained in the file License.txt included in VeraCrypt binary and source
 code distribution packages.
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
