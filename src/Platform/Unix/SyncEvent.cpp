/*
 Derived from source code of TrueCrypt 7.1a, which is
 Copyright (c) 2008-2012 TrueCrypt Developers Association and which is governed
 by the TrueCrypt License 3.0.

 Modifications and additions to the original source code (contained in this file) 
 and all other portions of this file are Copyright (c) 2013-2015 IDRIX
 and are governed by the Apache License 2.0 the full text of which is
 contained in the file License.txt included in VeraCrypt binary and source
 code distribution packages.
*/

#include "Platform/Exception.h"
#include "Platform/SyncEvent.h"
#include "Platform/SystemException.h"

namespace VeraCrypt
{
	SyncEvent::SyncEvent ()
	{
		int status = pthread_cond_init (&SystemSyncEvent, nullptr);
		if (status != 0)
			throw SystemException (SRC_POS, status);

		Signaled = false;
		Initialized = true;
	}

	SyncEvent::~SyncEvent ()
	{
#ifdef DEBUG
		int status =
#endif
		pthread_cond_destroy (&SystemSyncEvent);

#ifdef DEBUG
		if (status != 0)
			SystemLog::WriteException (SystemException (SRC_POS, status));
#endif

		Initialized = false;
	}

	void SyncEvent::Signal ()
	{
		assert (Initialized);

		ScopeLock lock (EventMutex);

		Signaled = true;

		int status = pthread_cond_signal (&SystemSyncEvent);
		if (status != 0)
			throw SystemException (SRC_POS, status);
	}

	void SyncEvent::Wait ()
	{
		assert (Initialized);

		ScopeLock lock (EventMutex);

		while (!Signaled)
		{
			int status = pthread_cond_wait (&SystemSyncEvent, EventMutex.GetSystemHandle());
			if (status != 0)
				throw SystemException (SRC_POS, status);
		}
		
		Signaled = false;
	}
}
