/*
 Copyright (c) 2026 AM Crypto. All rights reserved.
 Governed by the Apache License 2.0, included in License.txt.
*/

#include "FavoritePasswordCache.h"
#include "Volume/VolumePasswordCache.h"

namespace VeraCrypt
{
	Mutex FavoritePasswordCache::InstancesMutex;
	list <std::weak_ptr <FavoritePasswordCache> > FavoritePasswordCache::Instances;

	shared_ptr <FavoritePasswordCache> FavoritePasswordCache::Create ()
	{
		shared_ptr <FavoritePasswordCache> cache (new FavoritePasswordCache ());
		ScopeLock lock (InstancesMutex);
		for (list <std::weak_ptr <FavoritePasswordCache> >::iterator i = Instances.begin(); i != Instances.end(); )
		{
			if (i->expired())
				i = Instances.erase (i);
			else
				++i;
		}
		Instances.push_back (cache);
		return cache;
	}

	bool FavoritePasswordCache::Entry::Matches (const Entry &other) const
	{
		return Password == other.Password && (Pim < 0 ? 0 : Pim) == (other.Pim < 0 ? 0 : other.Pim)
			&& SystemEncryption == other.SystemEncryption
			&& ((!Kdf && !other.Kdf) || (Kdf && other.Kdf && Kdf->GetName() == other.Kdf->GetName()));
	}

	FavoritePasswordCache::FavoritePasswordCache ()
		: Generation (0), Active (true)
	{
	}

	FavoritePasswordCache::~FavoritePasswordCache ()
	{
		Close();
	}

	FavoritePasswordCache::Snapshot FavoritePasswordCache::GetSnapshot () const
	{
		ScopeLock lock (AccessMutex);
		Snapshot snapshot;
		if (Active)
			snapshot.Entries = Entries;
		snapshot.Generation = Generation;
		return snapshot;
	}

	bool FavoritePasswordCache::IsEmpty () const
	{
		ScopeLock lock (AccessMutex);
		return !Active || Entries.empty();
	}

	bool FavoritePasswordCache::IsCurrent (uint64 generation) const
	{
		ScopeLock lock (AccessMutex);
		return Active && generation == Generation;
	}

	void FavoritePasswordCache::Store (const VolumePassword &password, int pim, shared_ptr <Pkcs5Kdf> kdf,
		bool systemEncryption, uint64 generation)
	{
		if (password.IsEmpty() || !kdf)
			return;
		ScopeLock lock (AccessMutex);
		// Wiping the cache while a request is in flight must also prevent that
		// request from repopulating the temporary cache when it completes.
		if (!Active || generation != Generation)
			return;

		shared_ptr <Entry> entry = make_shared <Entry> (password, pim < 0 ? 0 : pim, kdf, systemEncryption);
		for (EntryList::iterator i = Entries.begin(); i != Entries.end(); ++i)
		{
			if ((*i)->Matches (*entry))
			{
				Entries.splice (Entries.begin(), Entries, i);
				return;
			}
		}

		Entries.push_front (entry);

		if (Entries.size() > VolumePasswordCache::Capacity)
			Entries.pop_back();
	}

	void FavoritePasswordCache::Clear ()
	{
		ScopeLock lock (AccessMutex);
		Entries.clear();
		++Generation;
	}

	void FavoritePasswordCache::Close ()
	{
		ScopeLock lock (AccessMutex);
		Entries.clear();
		++Generation;
		Active = false;
	}

	void FavoritePasswordCache::ClearAll ()
	{
		ScopeLock lock (InstancesMutex);
		foreach (const std::weak_ptr <FavoritePasswordCache> &instance, Instances)
		{
			shared_ptr <FavoritePasswordCache> cache = instance.lock();
			if (cache)
				cache->Clear();
		}
	}
}
