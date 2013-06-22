/*
 Copyright (c) 2008 TrueCrypt Developers Association. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

#ifndef TC_HEADER_Platform_SharedVal
#define TC_HEADER_Platform_SharedVal

#include "PlatformBase.h"
#include "Mutex.h"

namespace TrueCrypt
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
