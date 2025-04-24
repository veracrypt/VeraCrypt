/*
 Derived from source code of TrueCrypt 7.1a, which is
 Copyright (c) 2008-2012 TrueCrypt Developers Association and which is governed
 by the TrueCrypt License 3.0.

 Modifications and additions to the original source code (contained in this file)
 and all other portions of this file are Copyright (c) 2013-2025 IDRIX
 and are governed by the Apache License 2.0 the full text of which is
 contained in the file License.txt included in VeraCrypt binary and source
 code distribution packages.
*/

#include "MountOptions.h"
#include "Platform/MemoryStream.h"
#include "Platform/SerializerFactory.h"

namespace VeraCrypt
{
	void MountOptions::CopyFrom (const MountOptions &other)
	{
#define TC_CLONE(NAME) NAME = other.NAME
#define TC_CLONE_SHARED(TYPE,NAME) NAME = other.NAME ? make_shared <TYPE> (*other.NAME) : shared_ptr <TYPE> ()

		TC_CLONE (CachePassword);
		TC_CLONE (FilesystemOptions);
		TC_CLONE (FilesystemType);
		TC_CLONE_SHARED (KeyfileList, Keyfiles);
		TC_CLONE_SHARED (DirectoryPath, MountPoint);
		TC_CLONE (NoFilesystem);
		TC_CLONE (NoHardwareCrypto);
		TC_CLONE (NoKernelCrypto);
		TC_CLONE_SHARED (VolumePassword, Password);
		TC_CLONE (Pim);
		if (other.Kdf)
		{
			Kdf.reset(other.Kdf->Clone());
		}
		else
			Kdf.reset();
		TC_CLONE_SHARED (VolumePath, Path);
		TC_CLONE (PartitionInSystemEncryptionScope);
		TC_CLONE (PreserveTimestamps);
		TC_CLONE (Protection);
		TC_CLONE_SHARED (VolumePassword, ProtectionPassword);
		TC_CLONE (ProtectionPim);
		if (other.ProtectionKdf)
			ProtectionKdf.reset(other.ProtectionKdf->Clone());
		else
			ProtectionKdf.reset();
		TC_CLONE_SHARED (KeyfileList, ProtectionKeyfiles);
		TC_CLONE (ProtectionSecurityTokenSchemeSpec);
		TC_CLONE (Removable);
		TC_CLONE (SharedAccessAllowed);
		TC_CLONE (SlotNumber);
		TC_CLONE (UseBackupHeaders);
		TC_CLONE (SecurityTokenSchemeSpec);
	}

	void MountOptions::Deserialize (shared_ptr <Stream> stream)
	{
		Serializer sr (stream);
		wstring nameValue;

		sr.Deserialize ("CachePassword", CachePassword);
		sr.Deserialize ("FilesystemOptions", FilesystemOptions);
		sr.Deserialize ("FilesystemType", FilesystemType);

		Keyfiles = Keyfile::DeserializeList (stream, "Keyfiles");

		if (!sr.DeserializeBool ("MountPointNull"))
			MountPoint.reset (new DirectoryPath (sr.DeserializeWString ("MountPoint")));
		else
			MountPoint.reset();

		sr.Deserialize ("NoFilesystem", NoFilesystem);
		sr.Deserialize ("NoHardwareCrypto", NoHardwareCrypto);
		sr.Deserialize ("NoKernelCrypto", NoKernelCrypto);

		if (!sr.DeserializeBool ("PasswordNull"))
			Password = Serializable::DeserializeNew <VolumePassword> (stream);
		else
			Password.reset();

		if (!sr.DeserializeBool ("PathNull"))
			Path.reset (new VolumePath (sr.DeserializeWString ("Path")));
		else
			Path.reset();

		sr.Deserialize ("PartitionInSystemEncryptionScope", PartitionInSystemEncryptionScope);
		sr.Deserialize ("PreserveTimestamps", PreserveTimestamps);

		Protection = static_cast <VolumeProtection::Enum> (sr.DeserializeInt32 ("Protection"));

		if (!sr.DeserializeBool ("ProtectionPasswordNull"))
			ProtectionPassword = Serializable::DeserializeNew <VolumePassword> (stream);
		else
			ProtectionPassword.reset();

		ProtectionKeyfiles = Keyfile::DeserializeList (stream, "ProtectionKeyfiles");
		sr.Deserialize ("ProtectionSecurityTokenSchemeSpec", ProtectionSecurityTokenSchemeSpec);
		sr.Deserialize ("Removable", Removable);
		sr.Deserialize ("SharedAccessAllowed", SharedAccessAllowed);
		sr.Deserialize ("SlotNumber", SlotNumber);
		sr.Deserialize ("UseBackupHeaders", UseBackupHeaders);

		sr.Deserialize("SecurityTokenSchemeSpec", SecurityTokenSchemeSpec);

		try
		{
			if (!sr.DeserializeBool ("KdfNull"))
			{
				sr.Deserialize ("Kdf", nameValue);
				Kdf = Pkcs5Kdf::GetAlgorithm (nameValue);
			}
		}
		catch(...) {}

		try
		{
			if (!sr.DeserializeBool ("ProtectionKdfNull"))
			{
				sr.Deserialize ("ProtectionKdf", nameValue);
				ProtectionKdf = Pkcs5Kdf::GetAlgorithm (nameValue);
			}
		}
		catch(...) {}

		sr.Deserialize ("Pim", Pim);
		sr.Deserialize ("ProtectionPim", ProtectionPim);
	}

	void MountOptions::Serialize (shared_ptr <Stream> stream) const
	{
		Serializable::Serialize (stream);
		Serializer sr (stream);

		sr.Serialize ("CachePassword", CachePassword);
		sr.Serialize ("FilesystemOptions", FilesystemOptions);
		sr.Serialize ("FilesystemType", FilesystemType);
		Keyfile::SerializeList (stream, "Keyfiles", Keyfiles);

		sr.Serialize ("MountPointNull", MountPoint == nullptr);
		if (MountPoint)
			sr.Serialize ("MountPoint", wstring (*MountPoint));

		sr.Serialize ("NoFilesystem", NoFilesystem);
		sr.Serialize ("NoHardwareCrypto", NoHardwareCrypto);
		sr.Serialize ("NoKernelCrypto", NoKernelCrypto);

		sr.Serialize ("PasswordNull", Password == nullptr);
		if (Password)
			Password->Serialize (stream);

		sr.Serialize ("PathNull", Path == nullptr);
		if (Path)
			sr.Serialize ("Path", wstring (*Path));

		sr.Serialize ("PartitionInSystemEncryptionScope", PartitionInSystemEncryptionScope);
		sr.Serialize ("PreserveTimestamps", PreserveTimestamps);
		sr.Serialize ("Protection", static_cast <uint32> (Protection));

		sr.Serialize ("ProtectionPasswordNull", ProtectionPassword == nullptr);
		if (ProtectionPassword)
			ProtectionPassword->Serialize (stream);

		Keyfile::SerializeList (stream, "ProtectionKeyfiles", ProtectionKeyfiles);
		sr.Serialize ("ProtectionSecurityTokenSchemeSpec", ProtectionSecurityTokenSchemeSpec);
		sr.Serialize ("Removable", Removable);
		sr.Serialize ("SharedAccessAllowed", SharedAccessAllowed);
		sr.Serialize ("SlotNumber", SlotNumber);
		sr.Serialize ("UseBackupHeaders", UseBackupHeaders);

		sr.Serialize("SecurityTokenSchemeSpec", SecurityTokenSchemeSpec);
		sr.Serialize ("KdfNull", Kdf == nullptr);
		if (Kdf)
			sr.Serialize ("Kdf", Kdf->GetName());

		sr.Serialize ("ProtectionKdfNull", ProtectionKdf == nullptr);
		if (ProtectionKdf)
			sr.Serialize ("ProtectionKdf", ProtectionKdf->GetName());

		sr.Serialize ("Pim", Pim);
		sr.Serialize ("ProtectionPim", ProtectionPim);
	}

	TC_SERIALIZER_FACTORY_ADD_CLASS (MountOptions);
}
