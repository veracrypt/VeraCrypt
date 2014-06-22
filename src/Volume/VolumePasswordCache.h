/*
 Copyright (c) 2008 TrueCrypt Developers Association. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
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
