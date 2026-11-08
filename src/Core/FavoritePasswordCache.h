/*
 Copyright (c) 2026 AM Crypto. All rights reserved.
 Governed by the Apache License 2.0, included in License.txt.
*/

#ifndef TC_HEADER_Core_FavoritePasswordCache
#define TC_HEADER_Core_FavoritePasswordCache

#include "Platform/Platform.h"
#include "Volume/Pkcs5Kdf.h"
#include "Volume/VolumePassword.h"

namespace VeraCrypt
{
	struct FavoriteCredential
	{
		FavoriteCredential (const VolumePassword &password, int pim, shared_ptr <Pkcs5Kdf> kdf, bool systemEncryption)
			: Password (password), Pim (pim), Kdf (kdf), SystemEncryption (systemEncryption) { }
		~FavoriteCredential () { burn (&Pim, sizeof (Pim)); }

		VolumePassword Password;
		int Pim;
		shared_ptr <Pkcs5Kdf> Kdf;
		bool SystemEncryption;
	};

	typedef list <FavoriteCredential> FavoriteCredentialList;

	// Credentials supplied during a Mount Favorite Volumes operation. They are
	// kept in the application process only, until the operation ends or the
	// password cache is wiped.
	class FavoritePasswordCache
	{
	public:
		static void Clear ();
		static FavoriteCredentialList GetCredentials ();
		static bool IsEmpty ();
		static void Store (const VolumePassword &password, int pim, shared_ptr <Pkcs5Kdf> kdf, bool systemEncryption);

	protected:
		static FavoriteCredentialList Credentials;
		static Mutex CredentialsMutex;

	private:
		FavoritePasswordCache ();
	};
}

#endif // TC_HEADER_Core_FavoritePasswordCache
