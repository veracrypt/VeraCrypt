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

#include <set>

#include "CoreBase.h"
#include "RandomNumberGenerator.h"
#include "Volume/Volume.h"

namespace VeraCrypt
{
	CoreBase::CoreBase ()
		: DeviceChangeInProgress (false)
#if defined(TC_LINUX ) || defined (TC_FREEBSD)
		, UseDummySudoPassword (false)
#endif
	{
	}

	CoreBase::~CoreBase ()
	{
	}

	void CoreBase::ChangePassword (shared_ptr <Volume> openVolume, shared_ptr <VolumePassword> newPassword, int newPim, shared_ptr <KeyfileList> newKeyfiles, bool emvSupportEnabled, shared_ptr <Pkcs5Kdf> newPkcs5Kdf, int wipeCount) const
	{
		if ((!newPassword || newPassword->Size() < 1) && (!newKeyfiles || newKeyfiles->empty()))
			throw PasswordEmpty (SRC_POS);

		if (!newPkcs5Kdf)
		{
			newPkcs5Kdf = openVolume->GetPkcs5Kdf();
		}

		if ((openVolume->GetHeader()->GetFlags() & TC_HEADER_FLAG_ENCRYPTED_SYSTEM) != 0
			&& openVolume->GetType() == VolumeType::Hidden
			&& openVolume->GetPath().IsDevice())
		{
			throw EncryptedSystemRequired (SRC_POS);
		}

		RandomNumberGenerator::SetHash (newPkcs5Kdf->GetHash());

		SecureBuffer newSalt (openVolume->GetSaltSize());
		SecureBuffer newHeaderKey (VolumeHeader::GetLargestSerializedKeySize());

		shared_ptr <VolumePassword> password (Keyfile::ApplyListToPassword (newKeyfiles, newPassword, emvSupportEnabled));

		bool backupHeader = false;
		while (true)
		{
			for (int i = 1; i <= wipeCount; i++)
			{
				if (i == wipeCount)
					RandomNumberGenerator::GetData (newSalt);
				else
					RandomNumberGenerator::GetDataFast (newSalt);

				newPkcs5Kdf->DeriveKey (newHeaderKey, *password, newPim, newSalt);

				openVolume->ReEncryptHeader (backupHeader, newSalt, newHeaderKey, newPkcs5Kdf);
				openVolume->GetFile()->Flush();
			}

			if (!openVolume->GetLayout()->HasBackupHeader() || backupHeader)
				break;

			backupHeader = true;
		}
	}

	shared_ptr <Volume> CoreBase::ChangePassword (shared_ptr <VolumePath> volumePath, bool preserveTimestamps, shared_ptr <VolumePassword> password, int pim, shared_ptr <Pkcs5Kdf> kdf, shared_ptr <KeyfileList> keyfiles, shared_ptr <VolumePassword> newPassword, int newPim, shared_ptr <KeyfileList> newKeyfiles, bool emvSupportEnabled, shared_ptr <Pkcs5Kdf> newPkcs5Kdf, int wipeCount) const
	{
		shared_ptr <Volume> volume = OpenVolume (volumePath, preserveTimestamps, password, pim, kdf, keyfiles, emvSupportEnabled);
		ChangePassword (volume, newPassword, newPim, newKeyfiles, emvSupportEnabled, newPkcs5Kdf, wipeCount);
		return volume;
	}

	void CoreBase::CoalesceSlotNumberAndMountPoint (MountOptions &options) const
	{
		if (options.SlotNumber < GetFirstSlotNumber())
		{
			if (options.MountPoint && !options.MountPoint->IsEmpty())
				options.SlotNumber = MountPointToSlotNumber (*options.MountPoint);
			else
				options.SlotNumber = GetFirstFreeSlotNumber();
		}

		if (!IsSlotNumberAvailable (options.SlotNumber))
#ifdef TC_WINDOWS
			throw DriveLetterUnavailable (SRC_POS);
#else
			throw VolumeSlotUnavailable (SRC_POS);
#endif
		if (!options.NoFilesystem && (!options.MountPoint || options.MountPoint->IsEmpty()))
			options.MountPoint.reset (new DirectoryPath (SlotNumberToMountPoint (options.SlotNumber)));
	}

	void CoreBase::CreateKeyfile (const FilePath &keyfilePath) const
	{
		SecureBuffer keyfileBuffer (VolumePassword::MaxSize);
		RandomNumberGenerator::GetData (keyfileBuffer);

		File keyfile;
		keyfile.Open (keyfilePath, File::CreateWrite);
		keyfile.Write (keyfileBuffer);
	}

	VolumeSlotNumber CoreBase::GetFirstFreeSlotNumber (VolumeSlotNumber startFrom) const
	{
		if (startFrom < GetFirstSlotNumber())
			startFrom = GetFirstSlotNumber();

		set <VolumeSlotNumber> usedSlotNumbers;

		foreach_ref (const VolumeInfo &volume, GetMountedVolumes())
			usedSlotNumbers.insert (volume.SlotNumber);

		for (VolumeSlotNumber slotNumber = startFrom; slotNumber <= GetLastSlotNumber(); ++slotNumber)
		{
			if (usedSlotNumbers.find (slotNumber) == usedSlotNumbers.end()
				&& IsMountPointAvailable (SlotNumberToMountPoint (slotNumber)))
				return slotNumber;
		}
#ifdef TC_WINDOWS
		throw DriveLetterUnavailable (SRC_POS);
#else
		throw VolumeSlotUnavailable (SRC_POS);
#endif
	}

	uint64 CoreBase::GetMaxHiddenVolumeSize (shared_ptr <Volume> outerVolume) const
	{
		uint32 sectorSize = outerVolume->GetSectorSize();

		SecureBuffer bootSectorBuffer (sectorSize);
		outerVolume->ReadSectors (bootSectorBuffer, 0);

		int fatType;
		uint8 *bootSector = bootSectorBuffer.Ptr();

		if (memcmp (bootSector + 54, "FAT12", 5) == 0)
			fatType = 12;
		else if (memcmp (bootSector + 54, "FAT16", 5) == 0)
			fatType = 16;
		else if (memcmp (bootSector + 82, "FAT32", 5) == 0)
			fatType = 32;
		else
			throw ParameterIncorrect (SRC_POS);

		uint32 clusterSize = bootSector[13] * sectorSize;
		uint32 reservedSectorCount = Endian::Little (*(uint16 *) (bootSector + 14));
		uint32 fatCount = bootSector[16];

		uint64 fatSectorCount;
		if (fatType == 32)
			fatSectorCount = Endian::Little (*(uint32 *) (bootSector + 36));
		else
			fatSectorCount = Endian::Little (*(uint16 *) (bootSector + 22));
		uint64 fatSize = fatSectorCount * sectorSize;

		uint64 fatStartOffset = reservedSectorCount * sectorSize;
		uint64 dataAreaOffset = reservedSectorCount * sectorSize + fatSize * fatCount;

		if (fatType < 32)
			dataAreaOffset += Endian::Little (*(uint16 *) (bootSector + 17)) * 32;

		SecureBuffer sector (sectorSize);

		// Find last used cluster
		for (uint64 readOffset = fatStartOffset + fatSize - sectorSize;
			readOffset >= fatStartOffset;
			readOffset -= sectorSize)
		{
			outerVolume->ReadSectors (sector, readOffset);

			for (int offset = sectorSize - 4; offset >= 0; offset -= 4)
			{
				if (*(uint32 *) (sector.Ptr() + offset))
				{
					uint64 clusterNumber = readOffset - fatStartOffset + offset;

					if (fatType == 12)
						clusterNumber = (clusterNumber * 8) / 12;
					else if (fatType == 16)
						clusterNumber /= 2;
					else if (fatType == 32)
						clusterNumber /= 4;

					uint64 maxSize = outerVolume->GetSize() - dataAreaOffset;

					// Some FAT entries may span over sector boundaries
					if (maxSize >= clusterSize)
						maxSize -= clusterSize;

					uint64 clusterOffset = clusterNumber * clusterSize;
					if (maxSize < clusterOffset)
						return 0;

					return maxSize - clusterOffset;
				}
			}
		}

		return 0;
	}

	shared_ptr <VolumeInfo> CoreBase::GetMountedVolume (const VolumePath &volumePath) const
	{
		VolumeInfoList volumes = GetMountedVolumes (volumePath);
		if (volumes.empty())
			return shared_ptr <VolumeInfo> ();
		else
			return volumes.front();
	}

	shared_ptr <VolumeInfo> CoreBase::GetMountedVolume (VolumeSlotNumber slot) const
	{
		foreach (shared_ptr <VolumeInfo> volume, GetMountedVolumes())
		{
			if (volume->SlotNumber == slot)
				return volume;
		}

		return shared_ptr <VolumeInfo> ();
	}

	bool CoreBase::IsSlotNumberAvailable (VolumeSlotNumber slotNumber) const
	{
		if (!IsMountPointAvailable (SlotNumberToMountPoint (slotNumber)))
			return false;

		foreach_ref (const VolumeInfo &volume, GetMountedVolumes())
		{
			if (volume.SlotNumber == slotNumber)
				return false;
		}

		return true;
	}

	bool CoreBase::IsVolumeMounted (const VolumePath &volumePath) const
	{
		shared_ptr<VolumeInfo> mountedVolume = GetMountedVolume (volumePath);
		if (mountedVolume)
			return true;
		else
			return false;
	}

	shared_ptr <Volume> CoreBase::OpenVolume (shared_ptr <VolumePath> volumePath, bool preserveTimestamps, shared_ptr <VolumePassword> password, int pim, shared_ptr<Pkcs5Kdf> kdf, shared_ptr <KeyfileList> keyfiles, bool emvSupportEnabled, VolumeProtection::Enum protection, shared_ptr <VolumePassword> protectionPassword, int protectionPim, shared_ptr<Pkcs5Kdf> protectionKdf, shared_ptr <KeyfileList> protectionKeyfiles, bool sharedAccessAllowed, VolumeType::Enum volumeType, bool useBackupHeaders, bool partitionInSystemEncryptionScope) const
	{
		make_shared_auto (Volume, volume);
		volume->Open (*volumePath, preserveTimestamps, password, pim, kdf, keyfiles, emvSupportEnabled, protection, protectionPassword, protectionPim, protectionKdf, protectionKeyfiles, sharedAccessAllowed, volumeType, useBackupHeaders, partitionInSystemEncryptionScope);
		return volume;
	}

	void CoreBase::RandomizeEncryptionAlgorithmKey (shared_ptr <EncryptionAlgorithm> encryptionAlgorithm) const
	{
		SecureBuffer eaKey (encryptionAlgorithm->GetKeySize());
		RandomNumberGenerator::GetData (eaKey);
		encryptionAlgorithm->SetKey (eaKey);

		SecureBuffer modeKey (encryptionAlgorithm->GetMode()->GetKeySize());
		RandomNumberGenerator::GetData (modeKey);
		encryptionAlgorithm->GetMode()->SetKey (modeKey);
	}

	void CoreBase::ReEncryptVolumeHeaderWithNewSalt (const BufferPtr &newHeaderBuffer, shared_ptr <VolumeHeader> header, shared_ptr <VolumePassword> password, int pim, shared_ptr <KeyfileList> keyfiles, bool emvSupportEnabled) const
	{
		shared_ptr <Pkcs5Kdf> pkcs5Kdf = header->GetPkcs5Kdf();

		RandomNumberGenerator::SetHash (pkcs5Kdf->GetHash());

		SecureBuffer newSalt (header->GetSaltSize());
		SecureBuffer newHeaderKey (VolumeHeader::GetLargestSerializedKeySize());

		shared_ptr <VolumePassword> passwordKey (Keyfile::ApplyListToPassword (keyfiles, password, emvSupportEnabled));

		RandomNumberGenerator::GetData (newSalt);
		pkcs5Kdf->DeriveKey (newHeaderKey, *passwordKey, pim, newSalt);

		header->EncryptNew (newHeaderBuffer, newSalt, newHeaderKey, pkcs5Kdf);
	}
}
