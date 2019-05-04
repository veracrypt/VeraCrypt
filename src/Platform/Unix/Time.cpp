/*
 Derived from source code of TrueCrypt 7.1a, which is
 Copyright (c) 2008-2012 TrueCrypt Developers Association and which is governed
 by the TrueCrypt License 3.0.

 Modifications and additions to the original source code (contained in this file)
 and all other portions of this file are Copyright (c) 2013-2017 IDRIX
 and are governed by the Apache License 2.0 the full text of which is
 contained in the file License.txt included in VeraCrypt binary and source
 code distribution packages.
*/

#include "Platform/Time.h"
#include <sys/time.h>
#include <time.h>

namespace VeraCrypt
{
	uint64 Time::GetCurrent ()
	{
		struct timeval tv;
		gettimeofday (&tv, NULL);

		// Unix time => Windows file time
		return  ((uint64) tv.tv_sec + 134774LL * 24 * 3600) * 1000LL * 1000 * 10;
	}
}
