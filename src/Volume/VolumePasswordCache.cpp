/*
 Copyright (c) 2008 TrueCrypt Developers Association. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

#include "VolumePasswordCache.h"

namespace TrueCrypt
{
	CachedPasswordList VolumePasswordCache::GetPasswords ()
	{
		CachedPasswordList passwords;

		foreach_ref (const VolumePassword &password, CachedPasswords)
			passwords.push_back (make_shared <VolumePassword> (VolumePassword (password)));

		return passwords;
	}

	void VolumePasswordCache::Store (const VolumePassword &newPassword)
	{
		CachedPasswordList::iterator iter = CachedPasswords.begin();
		foreach_ref (const VolumePassword &password, CachedPasswords)
		{
			if (newPassword == password)
			{
				CachedPasswords.erase (iter);
				break;
			}
			iter++;
		}

		CachedPasswords.push_front (make_shared <VolumePassword> (VolumePassword (newPassword)));

		if (CachedPasswords.size() > Capacity)
			CachedPasswords.pop_back();
	}

	CachedPasswordList VolumePasswordCache::CachedPasswords;
}
