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

#include "VolumePasswordCache.h"

namespace VeraCrypt
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
