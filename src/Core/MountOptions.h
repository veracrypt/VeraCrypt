/*
 Derived from source code of TrueCrypt 7.1a, which is
 Copyright (c) 2008-2012 TrueCrypt Developers Association and which is governed
 by the TrueCrypt License 3.0.

 Modifications and additions to the original source code (contained in this file)
 and all other portions of this file are Copyright (c) 2013-2025 AM Crypto
 and are governed by the Apache License 2.0 the full text of which is
 contained in the file License.txt included in VeraCrypt binary and source
 code distribution packages.
*/

#ifndef TC_HEADER_Core_MountOptions
#define TC_HEADER_Core_MountOptions

#include "Platform/Serializable.h"
#include "Volume/Keyfile.h"
#include "Volume/Volume.h"
#include "Volume/VolumeSlot.h"
#include "Volume/VolumePassword.h"

namespace VeraCrypt
{
	struct MountOptions : public Serializable
	{
		MountOptions ()
			:
			CachePassword (false),
			NoFilesystem (false),
			NoHardwareCrypto (false),
			NoKernelCrypto (false),
			Pim (-1),
			PartitionInSystemEncryptionScope (false),
			PreserveTimestamps (true),
			Protection (VolumeProtection::None),
			ProtectionPim (-1),
			Removable (false),
			SharedAccessAllowed (false),
			SlotNumber (0),
			UseBackupHeaders (false)
		{
		}

		MountOptions (const MountOptions &other) { CopyFrom (other); }
		virtual ~MountOptions () { }

		MountOptions &operator= (const MountOptions &other) { CopyFrom (other); return *this; }

		TC_SERIALIZABLE (MountOptions);

		bool CachePassword;
		wstring FilesystemOptions;
		wstring FilesystemType;
		shared_ptr <KeyfileList> Keyfiles;
		shared_ptr <DirectoryPath> MountPoint;
		bool NoFilesystem;
		bool NoHardwareCrypto;
		bool NoKernelCrypto;
		shared_ptr <VolumePassword> Password;
		int Pim;
		shared_ptr <Pkcs5Kdf> Kdf;
		bool PartitionInSystemEncryptionScope;
		shared_ptr <VolumePath> Path;
		bool PreserveTimestamps;
		VolumeProtection::Enum Protection;
		shared_ptr <VolumePassword> ProtectionPassword;
		int ProtectionPim;
		shared_ptr <Pkcs5Kdf> ProtectionKdf;
		shared_ptr <KeyfileList> ProtectionKeyfiles;
		bool Removable;
		bool SharedAccessAllowed;
		VolumeSlotNumber SlotNumber;
		bool UseBackupHeaders;
		bool EMVSupportEnabled;

	protected:
		void CopyFrom (const MountOptions &other);
	};
}

#endif // TC_HEADER_Core_MountOptions
