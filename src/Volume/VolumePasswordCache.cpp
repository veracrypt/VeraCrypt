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
	void VolumePasswordCache::AddKdf (const VolumePassword &password, shared_ptr <Pkcs5Kdf> kdf)
	{
		for (CachedPasswordList::iterator iter = CachedPasswords.begin(); iter != CachedPasswords.end(); ++iter)
		{
			if (*iter->Password == password)
			{
				AddKdf (*iter, kdf);
				break;
			}
		}
	}

	void VolumePasswordCache::AddKdf (CachedPassword &cached, shared_ptr <Pkcs5Kdf> kdf)
	{
		const wstring name = kdf ? kdf->GetName() : wstring();

		for (Pkcs5KdfList::iterator iter = cached.Kdfs.begin(); iter != cached.Kdfs.end(); ++iter)
		{
			if ((*iter ? (*iter)->GetName() : wstring()) == name)
			{
				cached.Kdfs.erase (iter);
				break;
			}
		}

		cached.Kdfs.push_front (kdf);
	}

	CachedPasswordList VolumePasswordCache::GetPasswords ()
	{
		CachedPasswordList passwords;

		foreach (const CachedPassword &cached, CachedPasswords)
		{
			CachedPassword copy;
			copy.Password = make_shared <VolumePassword> (VolumePassword (*cached.Password));
			copy.Kdfs = cached.Kdfs;
			passwords.push_back (copy);
		}

		return passwords;
	}

	void VolumePasswordCache::Store (const VolumePassword &newPassword, shared_ptr <Pkcs5Kdf> kdf)
	{
		CachedPassword cached;
		cached.Password = make_shared <VolumePassword> (VolumePassword (newPassword));

		for (CachedPasswordList::iterator iter = CachedPasswords.begin(); iter != CachedPasswords.end(); ++iter)
		{
			if (*iter->Password == newPassword)
			{
				cached.Kdfs = iter->Kdfs;
				CachedPasswords.erase (iter);
				break;
			}
		}

		AddKdf (cached, kdf);
		CachedPasswords.push_front (cached);

		if (CachedPasswords.size() > Capacity)
			CachedPasswords.pop_back();
	}

	CachedPasswordList VolumePasswordCache::CachedPasswords;
}
