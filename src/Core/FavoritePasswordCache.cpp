/*
 Copyright (c) 2026 AM Crypto. All rights reserved.
 Governed by the Apache License 2.0, included in License.txt.
*/

#include "FavoritePasswordCache.h"
#include "Volume/VolumePasswordCache.h"

namespace VeraCrypt
{
	void FavoritePasswordCache::Clear ()
	{
		ScopeLock lock (CredentialsMutex);
		Credentials.clear();
	}

	FavoriteCredentialList FavoritePasswordCache::GetCredentials ()
	{
		ScopeLock lock (CredentialsMutex);
		return Credentials;
	}

	bool FavoritePasswordCache::IsEmpty ()
	{
		ScopeLock lock (CredentialsMutex);
		return Credentials.empty();
	}

	void FavoritePasswordCache::Store (const VolumePassword &password, int pim, shared_ptr <Pkcs5Kdf> kdf, bool systemEncryption)
	{
		if (pim < 0)
			pim = 0;

		ScopeLock lock (CredentialsMutex);
		for (FavoriteCredentialList::iterator i = Credentials.begin(); i != Credentials.end(); ++i)
		{
			if (i->Password == password && i->Pim == pim && i->Kdf->GetName() == kdf->GetName()
				&& i->SystemEncryption == systemEncryption)
			{
				Credentials.erase (i);
				break;
			}
		}

		Credentials.push_front (FavoriteCredential (password, pim, kdf, systemEncryption));

		if (Credentials.size() > VolumePasswordCache::Capacity)
			Credentials.pop_back();
	}

	FavoriteCredentialList FavoritePasswordCache::Credentials;
	Mutex FavoritePasswordCache::CredentialsMutex;
}
