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

#ifndef TC_HEADER_Volume_VolumePasswordCache
#define TC_HEADER_Volume_VolumePasswordCache

#include "Platform/Platform.h"
#include "VolumePassword.h"

namespace VeraCrypt
{
	typedef list < shared_ptr < VolumePassword > > CachedPasswordList;

	class VolumePasswordCache
	{
	public:
		static CachedPasswordList GetPasswords ();
		static bool IsEmpty () { return CachedPasswords.empty(); }
		static void Store (const VolumePassword &newPassword);
		static void Clear () { CachedPasswords.clear(); }
		static const size_t Capacity = 4;

	protected:
		static CachedPasswordList CachedPasswords;

	private:
		VolumePasswordCache ();
	};
}

#endif // TC_HEADER_Volume_VolumePasswordCache
