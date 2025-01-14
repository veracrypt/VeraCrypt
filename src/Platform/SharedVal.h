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

#ifndef TC_HEADER_Platform_SharedVal
#define TC_HEADER_Platform_SharedVal

#include "PlatformBase.h"
#include "Mutex.h"

namespace VeraCrypt
{
	template <class T>
	class SharedVal
	{
	public:
		SharedVal () { }
		explicit SharedVal (T value) : Value (value) { }
		virtual ~SharedVal () { }

		operator T ()
		{
			return Get ();
		}

		T Decrement ()
		{
			ValMutex.Lock();
			T r = --Value;
			ValMutex.Unlock();
			return r;
		}

		T Get ()
		{
			ValMutex.Lock();
			T r = Value;
			ValMutex.Unlock();
			return r;
		}

		T Increment ()
		{
			ValMutex.Lock();
			T r = ++Value;
			ValMutex.Unlock();
			return r;
		}

		void Set (T value)
		{
			ValMutex.Lock();
			Value = value;
			ValMutex.Unlock();
		}

	protected:
		volatile T Value;
		Mutex ValMutex;

	private:
		SharedVal (const SharedVal &);
		SharedVal &operator= (const SharedVal &);
	};
}

#endif // TC_HEADER_Platform_SharedVal
