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

#include <pthread.h>
#include "Platform/Mutex.h"
#include "Platform/SystemException.h"

namespace VeraCrypt
{
	Mutex::Mutex ()
	{
		pthread_mutexattr_t attributes;

		int status = pthread_mutexattr_init (&attributes);
		if (status != 0)
			throw SystemException (SRC_POS, status);

		status = pthread_mutexattr_settype (&attributes, PTHREAD_MUTEX_RECURSIVE);
		if (status != 0)
			throw SystemException (SRC_POS, status);

		status = pthread_mutex_init (&SystemMutex, &attributes);
		if (status != 0)
			throw SystemException (SRC_POS, status);

		Initialized = true;
	}

	Mutex::~Mutex ()
	{
		Initialized = false;
#ifdef DEBUG
		int status =
#endif
		pthread_mutex_destroy (&SystemMutex);

#ifdef DEBUG
		if (status != 0)
			SystemLog::WriteException (SystemException (SRC_POS, status));
#endif
	}

	void Mutex::Lock ()
	{
		assert (Initialized);
		int status = pthread_mutex_lock (&SystemMutex);
		if (status != 0)
			throw SystemException (SRC_POS, status);
	}

	void Mutex::Unlock ()
	{
		int status = pthread_mutex_unlock (&SystemMutex);
		if (status != 0)
			throw SystemException (SRC_POS, status);
	}
}
