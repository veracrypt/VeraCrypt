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

#ifndef TC_HEADER_Volume_Version
#define TC_HEADER_Volume_Version

#include "Platform/PlatformBase.h"
#include "Common/Tcdefs.h"

namespace VeraCrypt
{
	class Version
	{
	public:
		static const string String ()					{ return VERSION_STRING; }
		static const uint16 Number ()					{ return VERSION_NUM; }
	};
}

#endif // TC_HEADER_Volume_Version
