/*
 Derived from source code of TrueCrypt 7.1a, which is
 Copyright (c) 2008-2012 TrueCrypt Developers Association and which is governed
 by the TrueCrypt License 3.0.

 Modifications and additions to the original source code (contained in this file)
 and all other portions of this file are Copyright (c) 2013-2026 AM Crypto
 and are governed by the Apache License 2.0 the full text of which is
 contained in the file License.txt included in VeraCrypt binary and source
 code distribution packages.
*/

#include <pthread.h>
#include <unistd.h>
#include "Platform/SystemException.h"
#include "Platform/Thread.h"
#include "Platform/SystemLog.h"

namespace VeraCrypt
{
	namespace
	{
		struct PthreadAttr
		{
			PthreadAttr ()
			{
				int status = pthread_attr_init (&Attr);
				if (status != 0)
					throw SystemException (SRC_POS, status);
			}

			~PthreadAttr ()
			{
				pthread_attr_destroy (&Attr);
			}

			pthread_attr_t Attr;
		};
	}

	void Thread::Join () const
	{
		int status = pthread_join (SystemHandle, nullptr);
		if (status != 0)
			throw SystemException (SRC_POS, status);
	}

	void Thread::Detach () const
	{
		int status = pthread_detach (SystemHandle);
		if (status != 0)
			throw SystemException (SRC_POS, status);
	}

	void Thread::Start (ThreadProcPtr threadProc, void *parameter)
	{
		PthreadAttr attr;
		size_t stackSize = 0;
		int status;

		status = pthread_attr_getstacksize (&attr.Attr, &stackSize);
		if (status != 0)
			throw SystemException (SRC_POS, status);

		if (stackSize < MinThreadStackSize)
		{
			status = pthread_attr_setstacksize (&attr.Attr, MinThreadStackSize);
			if (status != 0)
				throw SystemException (SRC_POS, status);
		}

		status = pthread_create (&SystemHandle, &attr.Attr, threadProc, parameter);
		if (status != 0)
			throw SystemException (SRC_POS, status);
	}

	void Thread::Sleep (uint32 milliSeconds)
	{
		::usleep (milliSeconds * 1000);
	}
}
