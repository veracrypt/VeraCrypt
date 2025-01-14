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

#ifndef TC_HEADER_Platform_Time
#define TC_HEADER_Platform_Time

#include "PlatformBase.h"

namespace VeraCrypt
{
	class Time
	{
	public:
		Time () { }
		virtual ~Time () { }

		static uint64 GetCurrent (); // Returns time in hundreds of nanoseconds since 1601/01/01

	private:
		Time (const Time &);
		Time &operator= (const Time &);
	};
}

#endif // TC_HEADER_Platform_Time
