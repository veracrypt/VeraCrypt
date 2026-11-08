/*
 Copyright (c) 2026 AM Crypto. All rights reserved.
 Governed by the Apache License 2.0, included in License.txt.
*/

#ifndef TC_HEADER_Core_FavoritePasswordCache
#define TC_HEADER_Core_FavoritePasswordCache

#include "Volume/Pkcs5Kdf.h"
#include "Volume/VolumePassword.h"

namespace VeraCrypt
{
	// Application-local credentials for one favorites operation. MountOptions
	// shares this object between favorites, but never serializes it to a service.
	class FavoritePasswordCache
	{
	public:
		struct Entry
		{
			Entry (const VolumePassword &password, int pim, shared_ptr <Pkcs5Kdf> kdf, bool systemEncryption)
				: Password (password), Pim (pim), Kdf (kdf), SystemEncryption (systemEncryption) { }
			~Entry () { burn (&Pim, sizeof (Pim)); }

			bool Matches (const Entry &other) const;

			VolumePassword Password;
			int Pim;
			shared_ptr <Pkcs5Kdf> Kdf;
			bool SystemEncryption;
		};

		typedef list <shared_ptr <Entry> > EntryList;
		struct Snapshot
		{
			Snapshot () : Generation (0) { }
			EntryList Entries;
			uint64 Generation;
		};

		static shared_ptr <FavoritePasswordCache> Create ();
		~FavoritePasswordCache ();
		Snapshot GetSnapshot () const;
		bool IsEmpty () const;
		bool IsCurrent (uint64 generation) const;
		void Store (const VolumePassword &password, int pim, shared_ptr <Pkcs5Kdf> kdf,
			bool systemEncryption, uint64 generation);
		void Clear ();
		void Close ();
		static void ClearAll ();

	private:
		FavoritePasswordCache ();
		FavoritePasswordCache (const FavoritePasswordCache &);
		FavoritePasswordCache &operator= (const FavoritePasswordCache &);

		mutable Mutex AccessMutex;
		EntryList Entries;
		uint64 Generation;
		bool Active;
		static Mutex InstancesMutex;
		static list <std::weak_ptr <FavoritePasswordCache> > Instances;
	};
}

#endif
