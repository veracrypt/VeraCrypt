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

#include "Common/Tcdefs.h"
#include "VolumeInfo.h"
#include "Platform/SerializerFactory.h"

namespace VeraCrypt
{
	void VolumeInfo::Deserialize (shared_ptr <Stream> stream)
	{
		Serializer sr (stream);

		sr.Deserialize ("ProgramVersion", ProgramVersion);
		AuxMountPoint = sr.DeserializeWString ("AuxMountPoint");
		sr.Deserialize ("EncryptionAlgorithmBlockSize", EncryptionAlgorithmBlockSize);
		sr.Deserialize ("EncryptionAlgorithmKeySize", EncryptionAlgorithmKeySize);
		sr.Deserialize ("EncryptionAlgorithmMinBlockSize", EncryptionAlgorithmMinBlockSize);
		EncryptionAlgorithmName = sr.DeserializeWString ("EncryptionAlgorithmName");
		EncryptionModeName = sr.DeserializeWString ("EncryptionModeName");
		sr.Deserialize ("HeaderCreationTime", HeaderCreationTime);
		sr.Deserialize ("HiddenVolumeProtectionTriggered", HiddenVolumeProtectionTriggered);
		LoopDevice = sr.DeserializeWString ("LoopDevice");

		if (ProgramVersion >= 0x10b)
			sr.Deserialize ("MinRequiredProgramVersion", MinRequiredProgramVersion);

		MountPoint = sr.DeserializeWString ("MountPoint");
		Path = sr.DeserializeWString ("Path");
		sr.Deserialize ("Pkcs5IterationCount", Pkcs5IterationCount);
		Pkcs5PrfName = sr.DeserializeWString ("Pkcs5PrfName");
		Protection = static_cast <VolumeProtection::Enum> (sr.DeserializeInt32 ("Protection"));
		sr.Deserialize ("SerialInstanceNumber", SerialInstanceNumber);
		sr.Deserialize ("Size", Size);
		sr.Deserialize ("SlotNumber", SlotNumber);

		if (ProgramVersion >= 0x10b)
			sr.Deserialize ("SystemEncryption", SystemEncryption);

		if (ProgramVersion >= 0x10b)
			sr.Deserialize ("TopWriteOffset", TopWriteOffset);

		sr.Deserialize ("TotalDataRead", TotalDataRead);
		sr.Deserialize ("TotalDataWritten", TotalDataWritten);
		Type = static_cast <VolumeType::Enum> (sr.DeserializeInt32 ("Type"));
		VirtualDevice = sr.DeserializeWString ("VirtualDevice");
		sr.Deserialize ("VolumeCreationTime", VolumeCreationTime);
		sr.Deserialize ("Pim", Pim);
		sr.Deserialize ("MasterKeyVulnerable", MasterKeyVulnerable);
	}

	bool VolumeInfo::FirstVolumeMountedAfterSecond (shared_ptr <VolumeInfo> first, shared_ptr <VolumeInfo> second)
	{
		return first->SerialInstanceNumber > second->SerialInstanceNumber;
	}

	void VolumeInfo::Serialize (shared_ptr <Stream> stream) const
	{
		Serializable::Serialize (stream);
		Serializer sr (stream);

		const uint32 version = VERSION_NUM;
		sr.Serialize ("ProgramVersion", version);
		sr.Serialize ("AuxMountPoint", wstring (AuxMountPoint));
		sr.Serialize ("EncryptionAlgorithmBlockSize", EncryptionAlgorithmBlockSize);
		sr.Serialize ("EncryptionAlgorithmKeySize", EncryptionAlgorithmKeySize);
		sr.Serialize ("EncryptionAlgorithmMinBlockSize", EncryptionAlgorithmMinBlockSize);
		sr.Serialize ("EncryptionAlgorithmName", EncryptionAlgorithmName);
		sr.Serialize ("EncryptionModeName", EncryptionModeName);
		sr.Serialize ("HeaderCreationTime", HeaderCreationTime);
		sr.Serialize ("HiddenVolumeProtectionTriggered", HiddenVolumeProtectionTriggered);
		sr.Serialize ("LoopDevice", wstring (LoopDevice));
		sr.Serialize ("MinRequiredProgramVersion", MinRequiredProgramVersion);
		sr.Serialize ("MountPoint", wstring (MountPoint));
		sr.Serialize ("Path", wstring (Path));
		sr.Serialize ("Pkcs5IterationCount", Pkcs5IterationCount);
		sr.Serialize ("Pkcs5PrfName", Pkcs5PrfName);
		sr.Serialize ("Protection", static_cast <uint32> (Protection));
		sr.Serialize ("SerialInstanceNumber", SerialInstanceNumber);
		sr.Serialize ("Size", Size);
		sr.Serialize ("SlotNumber", SlotNumber);
		sr.Serialize ("SystemEncryption", SystemEncryption);
		sr.Serialize ("TopWriteOffset", TopWriteOffset);
		sr.Serialize ("TotalDataRead", TotalDataRead);
		sr.Serialize ("TotalDataWritten", TotalDataWritten);
		sr.Serialize ("Type", static_cast <uint32> (Type));
		sr.Serialize ("VirtualDevice", wstring (VirtualDevice));
		sr.Serialize ("VolumeCreationTime", VolumeCreationTime);
		sr.Serialize ("Pim", Pim);
		sr.Serialize ("MasterKeyVulnerable", MasterKeyVulnerable);
	}

	void VolumeInfo::Set (const Volume &volume)
	{
		EncryptionAlgorithmBlockSize = static_cast <uint32> (volume.GetEncryptionAlgorithm()->GetMaxBlockSize());
		EncryptionAlgorithmKeySize = static_cast <uint32> (volume.GetEncryptionAlgorithm()->GetKeySize());
		EncryptionAlgorithmMinBlockSize = static_cast <uint32> (volume.GetEncryptionAlgorithm()->GetMinBlockSize());
		EncryptionAlgorithmName = volume.GetEncryptionAlgorithm()->GetName();
		EncryptionModeName = volume.GetEncryptionMode()->GetName();
		HeaderCreationTime = volume.GetHeaderCreationTime();
		VolumeCreationTime = volume.GetVolumeCreationTime();
		HiddenVolumeProtectionTriggered = volume.IsHiddenVolumeProtectionTriggered();
		MinRequiredProgramVersion = volume.GetHeader()->GetRequiredMinProgramVersion();
		Path = volume.GetPath();
		Pkcs5IterationCount = volume.GetPkcs5Kdf()->GetIterationCount(volume.GetPim ());
		Pkcs5PrfName = volume.GetPkcs5Kdf()->GetName();
		Protection = volume.GetProtectionType();
		Size = volume.GetSize();
		SystemEncryption = volume.IsInSystemEncryptionScope();
		Type = volume.GetType();
		TopWriteOffset = volume.GetTopWriteOffset();
		TotalDataRead = volume.GetTotalDataRead();
		TotalDataWritten = volume.GetTotalDataWritten();
		Pim = volume.GetPim ();
		MasterKeyVulnerable = volume.IsMasterKeyVulnerable();
	}

	TC_SERIALIZER_FACTORY_ADD_CLASS (VolumeInfo);
}
