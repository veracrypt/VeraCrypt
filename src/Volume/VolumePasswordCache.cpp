/*
 Derived from source code of TrueCrypt 7.1a, which is
 Copyright (c) 2008-2012 TrueCrypt Developers Association and which is governed
 by the TrueCrypt License 3.0.

 Modifications and additions to the original source code (contained in this file)
 and all other portions of this file are Copyright (c) 2013-2026 AM Crypto
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

		foreach (const CachedPassword &cached, CachedPasswords)
		{
			CachedPassword copy;
			copy.Password = make_shared <VolumePassword> (VolumePassword (*cached.Password));
			copy.Kdf = cached.Kdf;
			passwords.push_back (copy);
		}

		return passwords;
	}

	void VolumePasswordCache::Store (const VolumePassword &newPassword, shared_ptr <Pkcs5Kdf> kdf)
	{
		// A password used with several KDFs gets an entry for each of them
		for (CachedPasswordList::iterator iter = CachedPasswords.begin(); iter != CachedPasswords.end(); ++iter)
		{
			if (*iter->Password == newPassword
				&& (iter->Kdf ? iter->Kdf->GetName() : wstring()) == (kdf ? kdf->GetName() : wstring()))
			{
				CachedPasswords.erase (iter);
				break;
			}
		}

		CachedPassword cached;
		cached.Password = make_shared <VolumePassword> (VolumePassword (newPassword));
		cached.Kdf = kdf;
		CachedPasswords.push_front (cached);

		if (CachedPasswords.size() > Capacity)
			CachedPasswords.pop_back();
	}

	CachedPasswordList VolumePasswordCache::CachedPasswords;
}
